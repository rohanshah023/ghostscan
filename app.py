import logging, os, threading, time
from collections import deque
from functools import wraps
from flask import Flask, jsonify, render_template, request
from werkzeug.exceptions import HTTPException
from config import (MAX_FILE_BYTES, ALLOW_URL_DOWNLOAD, RATE_LIMIT, RATE_WINDOW_S, TRUST_PROXY,
                    MAX_CONCURRENT_IMAGE_JOBS, QUEUE_WAIT_S)
from scanner.pipeline import scan_file, scan_url, Busy
from scanner import stego

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_FILE_BYTES + 1024 * 64   # reject oversize bodies early
app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 86400                 # static files are cached for a day (URLs carry ?v=<mtime>)
app.config["JSON_SORT_KEYS"] = False
if TRUST_PROXY:       # only honour X-Forwarded-* when a trusted reverse proxy is in front, otherwise clients could spoof their IP
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=TRUST_PROXY, x_proto=TRUST_PROXY, x_host=TRUST_PROXY)
if __name__ != "__main__":        # under gunicorn: send app logs to its error log
    _g = logging.getLogger("gunicorn.error")
    app.logger.handlers, app.logger.level = _g.handlers, _g.level

_STATIC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")


@app.context_processor
def _assets():
    def v(name):      # cache-busting version = file modification time
        try:
            return int(os.path.getmtime(os.path.join(_STATIC, name)))
        except OSError:
            return 0
    return {"v": v}


# ----------------------------------------------------------------- abuse protection
class RateLimiter:
    """Sliding window per client IP, in memory (per server process). Put nginx limit_req in front for a global limit."""

    def __init__(self, limit, window):
        self.limit, self.window, self.hits, self.lock = limit, window, {}, threading.Lock()

    def check(self, key):
        now = time.monotonic()
        with self.lock:
            q = self.hits.setdefault(key, deque())
            while q and q[0] <= now - self.window:
                q.popleft()
            if len(q) >= self.limit:
                return int(q[0] + self.window - now) + 1
            q.append(now)
            if len(self.hits) > 20000:                         # keep memory bounded
                for k in [k for k, d in self.hits.items() if not d or d[-1] <= now - self.window]:
                    del self.hits[k]
            return 0


limiter = RateLimiter(RATE_LIMIT, RATE_WINDOW_S)
_image_jobs = threading.BoundedSemaphore(MAX_CONCURRENT_IMAGE_JOBS)


def image_job(fn):
    """Image tools run inside the web process and use a lot of memory: allow only a few at once."""
    @wraps(fn)
    def inner(*a, **k):
        if not _image_jobs.acquire(timeout=QUEUE_WAIT_S):
            raise Busy()
        try:
            return fn(*a, **k)
        finally:
            _image_jobs.release()
    return inner


@app.before_request
def throttle():
    if request.method == "POST" and request.path.startswith("/api/") and RATE_LIMIT > 0:
        wait = limiter.check(request.remote_addr or "?")
        if wait:
            r = jsonify(error=f"Too many requests. Please wait {wait} seconds and try again.")
            r.status_code = 429
            r.headers["Retry-After"] = str(wait)
            return r


@app.after_request
def headers(r):
    r.headers["X-Content-Type-Options"] = "nosniff"
    r.headers["X-Frame-Options"] = "DENY"
    r.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    r.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    r.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    r.headers["Content-Security-Policy"] = ("default-src 'self'; script-src 'self'; style-src 'self' https://fonts.googleapis.com; "
                                            "font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; "
                                            "object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'")
    if request.is_secure:
        r.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    if request.path.startswith("/api/") or request.path == "/healthz":
        r.headers["Cache-Control"] = "no-store"        # results describe one person's file: never cache them
    return r


@app.get("/healthz")
def healthz():
    return jsonify(ok=True)


@app.get("/")
def index():
    return render_template("index.html", allow_download=ALLOW_URL_DOWNLOAD,
                           max_mb=MAX_FILE_BYTES // 1024 // 1024)


@app.post("/api/scan/file")
def api_file():
    f = request.files.get("file")
    if not f:
        return jsonify(error="Choose a file to scan."), 400
    return jsonify(scan_file(f.filename, f.read(MAX_FILE_BYTES + 1)))


@app.post("/api/scan/url")
def api_url():
    url = (request.get_json(silent=True) or {}).get("url", "").strip()
    if not url:
        return jsonify(error="Paste a link to scan."), 400
    return jsonify(scan_url(url[:2048], download=ALLOW_URL_DOWNLOAD))


def _upload(exts):
    f = request.files.get("file")
    if not f or not f.filename:
        raise stego.StegoError("Choose a file first.")
    data = f.read(MAX_FILE_BYTES + 1)
    if len(data) > MAX_FILE_BYTES:
        raise stego.StegoError(f"The file is larger than the {MAX_FILE_BYTES // 1024 // 1024} MB limit.")
    ext = f.filename.lower().rsplit(".", 1)[-1] if "." in f.filename else ""
    if ext not in exts:
        raise stego.StegoError("Supported types here: " + ", ".join("." + e for e in sorted(exts)) + ".")
    return f.filename, ext, data


def _img_out(png: bytes, name: str, suffix: str, **extra):
    base = name.rsplit(".", 1)[0][:60]
    return jsonify(filename=f"{base}_{suffix}.png", mime="image/png", data=stego.b64(png), **extra)


@app.errorhandler(stego.StegoError)
def stego_err(e):
    return jsonify(error=str(e)), 400


@app.post("/api/stego/hide")
@image_job
def api_hide():
    name, ext, data = _upload({"png", "jpg", "jpeg", "txt"})
    msg, pw = request.form.get("message", ""), request.form.get("passphrase", "")
    if not msg.strip():
        raise stego.StegoError("Type the message you want to hide.")
    if ext == "txt":
        out = stego.text_hide(data.decode("utf-8", "ignore"), msg, pw).encode("utf-8")
        return jsonify(filename=name.rsplit(".", 1)[0][:60] + "_hidden.txt", mime="text/plain", data=stego.b64(out),
                       note="The message is stored in invisible characters. Copying the text keeps it; retyping or most editors' clean-up tools remove it.")
    r = stego.lsb_hide(data, msg, pw)
    return _img_out(r["png"], name, "hidden", note=f"Hidden in the pixels ({r['used_bytes']} of about {r['capacity_bytes']} bytes used). "
                    "Save and share it as PNG. Re-saving as JPG or resizing destroys the message.")


@app.post("/api/stego/reveal")
@image_job
def api_reveal():
    name, ext, data = _upload({"png", "jpg", "jpeg", "txt"})
    pw = request.form.get("passphrase", "")
    if ext == "txt":
        text = data.decode("utf-8", "ignore")
        msg = stego.text_reveal(text, pw)
        findings = stego.unicode_findings(text)
        stats = {}
    else:
        msg = stego.lsb_reveal(data, pw)
        findings, stats = stego.analyze_image(data)
    return jsonify(found=msg is not None, message=msg,
                   indicators=[{"evidence": e, "confidence": stego.confidence_label(w), "rule": r} for r, w, e in findings if w],
                   statistics=stats,
                   note=None if msg is not None else "No GhostScan message was found. It may be protected by a different passphrase, "
                        "or hidden with another tool. Statistical indicators above can only suggest hidden data, not decode it.")


@app.post("/api/watermark/add")
@image_job
def api_wm_add():
    name, ext, data = _upload({"png", "jpg", "jpeg"})
    text, mode = request.form.get("text", "").strip(), request.form.get("mode", "both")
    key = request.form.get("key", "")
    if not text:
        raise stego.StegoError("Type the watermark text.")
    if mode not in ("visible", "invisible", "both"):
        raise stego.StegoError("Unknown mode.")
    im = stego.load_image(data)
    if mode in ("visible", "both"):
        try:
            op = float(request.form.get("opacity", "0.45"))
        except ValueError:
            op = 0.45
        im = stego.visible_watermark(im, text, request.form.get("position", "corner"), op)
    if mode in ("invisible", "both"):
        im = stego.dct_watermark(im, text, key)
    return _img_out(stego.to_png(im), name, "watermarked",
                    note={"visible": "Visible watermark added.", "invisible": "Invisible watermark added. Share as PNG, or JPG at quality 70 or higher.",
                          "both": "Visible and invisible watermarks added. Share as PNG, or JPG at quality 70 or higher."}[mode])


@app.post("/api/watermark/detect")
@image_job
def api_wm_detect():
    name, ext, data = _upload({"png", "jpg", "jpeg"})
    im = stego.load_image(data)
    r = stego.dct_detect(im, request.form.get("key", ""))
    r["provenance"] = stego.provenance(data)
    return jsonify(r)


@app.errorhandler(Busy)
def busy(_):
    r = jsonify(error="The server is busy scanning other files. Please try again in a few seconds.")
    r.status_code = 503
    r.headers["Retry-After"] = "5"
    return r


@app.errorhandler(413)
def too_big(_):
    return jsonify(error=f"The file is larger than the {MAX_FILE_BYTES // 1024 // 1024} MB limit."), 413


@app.errorhandler(Exception)
def any_error(e):
    if isinstance(e, HTTPException):          # 404, 405, 400 ... keep their own status and a readable message
        return jsonify(error=e.description), e.code
    app.logger.exception("request failed")
    return jsonify(error="The scan failed on the server. Please try again, or try a different file."), 500


if __name__ == "__main__":        # development only. In production run: gunicorn -c gunicorn.conf.py app:app
    app.run(host=os.getenv("HOST", "127.0.0.1"), port=int(os.getenv("PORT", "5000")), debug=False)
