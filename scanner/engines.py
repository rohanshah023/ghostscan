"""Optional external engines. Both are off unless available, and neither ever uploads the file.
  * ClamAV: talks to a running clamd (unix socket or TCP, INSTREAM) - fast, the signature DB stays loaded.
            Falls back to the local 'clamscan' program, which reloads the whole DB per file and is slow.
  * VirusTotal: looks up the file's SHA-256 only (needs GHOSTSCAN_VT_API_KEY and internet).
            Answers are cached, and after a failure or rate limit it is skipped for a short time.
"""
import json, os, re, shutil, socket, struct, subprocess, threading, time, urllib.error, urllib.request
from config import (CLAMD_SOCKET, CLAMD_HOST, CLAMD_PORT, CLAMD_TIMEOUT_S, CLAMSCAN_FALLBACK, CLAMSCAN_TIMEOUT_S,
                    VT_TIMEOUT_S, VT_CACHE_TTL_S)

VT_URL = "https://www.virustotal.com/api/v3/files/"
VT_LABEL = {"malicious": "Detected", "suspicious": "Suspicious", "undetected": "Undetected", "harmless": "Undetected",
            "type-unsupported": "Unable to process file type", "timeout": "Timed out", "failure": "Failed", "confirmed-timeout": "Timed out"}
DEFAULT_CLAMD_SOCKETS = ("/run/clamav/clamd.ctl", "/var/run/clamav/clamd.ctl", "/tmp/clamd.socket")


def _clamd_connect():
    """Returns a connected socket, or None when no clamd is configured or found."""
    if CLAMD_SOCKET or (not CLAMD_HOST and any(os.path.exists(p) for p in DEFAULT_CLAMD_SOCKETS)):
        path = CLAMD_SOCKET or next(p for p in DEFAULT_CLAMD_SOCKETS if os.path.exists(p))
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(CLAMD_TIMEOUT_S)
        s.connect(path)
        return s
    if CLAMD_HOST:
        return socket.create_connection((CLAMD_HOST, CLAMD_PORT), timeout=CLAMD_TIMEOUT_S)
    return None


def _clamd(data: bytes):
    """Scan through clamd. Returns an engine result dict, or None if clamd is not configured."""
    try:
        s = _clamd_connect()
    except OSError as e:
        return {"engine": "ClamAV", "status": "error", "detail": f"Could not reach the ClamAV daemon ({type(e).__name__})."}
    if s is None:
        return None
    try:
        with s:
            s.sendall(b"zINSTREAM\0")
            for i in range(0, len(data), 1 << 20):
                chunk = data[i:i + (1 << 20)]
                s.sendall(struct.pack(">I", len(chunk)) + chunk)
            s.sendall(struct.pack(">I", 0))
            buf = b""
            while not buf.endswith(b"\0") and len(buf) < 4096:
                part = s.recv(4096)
                if not part:
                    break
                buf += part
    except OSError as e:
        return {"engine": "ClamAV", "status": "error", "detail": f"ClamAV daemon error ({type(e).__name__})."}
    out = buf.decode("utf-8", "replace").strip("\0 \n")
    if out.endswith("FOUND"):
        sig = re.sub(r"^\w+:\s*|\s*FOUND$", "", out).strip() or "unknown"
        return {"engine": "ClamAV", "status": "detected", "signature": sig, "detail": f"Signature match: {sig}"}
    if out.endswith("OK"):
        return {"engine": "ClamAV", "status": "clean", "detail": "No signature matched."}
    return {"engine": "ClamAV", "status": "error", "detail": "ClamAV daemon returned an error (size limit or signature database?)."}


def clamav(data: bytes) -> dict:
    res = _clamd(data)
    if res is not None:
        return res
    exe = shutil.which("clamscan") if CLAMSCAN_FALLBACK else None
    if not exe:
        return {"engine": "ClamAV", "status": "not_installed", "detail": "ClamAV is not installed on this server. Install it to add a real antivirus engine."}
    try:
        r = subprocess.run([exe, "--no-summary", "--stdout", "-"], input=data, capture_output=True, timeout=CLAMSCAN_TIMEOUT_S)
    except subprocess.TimeoutExpired:
        return {"engine": "ClamAV", "status": "error", "detail": "ClamAV timed out. Run clamd so the signatures stay loaded."}
    except OSError as e:
        return {"engine": "ClamAV", "status": "error", "detail": f"Could not run ClamAV ({type(e).__name__})."}
    out = r.stdout.decode("utf-8", "replace").strip()
    if r.returncode == 1:
        sig = re.sub(r"^stream:\s*|^stdin:\s*|\s*FOUND\s*$", "", out.splitlines()[0] if out else "").strip() or "unknown"
        return {"engine": "ClamAV", "status": "detected", "signature": sig, "detail": f"Signature match: {sig}"}
    if r.returncode == 0:
        return {"engine": "ClamAV", "status": "clean", "detail": "No signature matched."}
    return {"engine": "ClamAV", "status": "error", "detail": "ClamAV returned an error (is the signature database installed?)."}


_vt_lock = threading.Lock()
_vt_cache = {}            # sha256 -> (expires_at, result)
_vt_pause_until = 0.0     # circuit breaker: skip VirusTotal until this time after a rate limit / outage


def _vt_remember(sha256, res, ttl=VT_CACHE_TTL_S):
    with _vt_lock:
        if len(_vt_cache) > 2048:
            now = time.monotonic()
            for k in [k for k, (t, _) in _vt_cache.items() if t < now] or list(_vt_cache)[:256]:
                _vt_cache.pop(k, None)
        _vt_cache[sha256] = (time.monotonic() + ttl, res)
    return res


def virustotal(sha256: str) -> dict:
    key = os.getenv("GHOSTSCAN_VT_API_KEY", "").strip()
    if not key:
        return {"status": "not_configured", "detail": "Not configured. Set GHOSTSCAN_VT_API_KEY to look up this file's hash on VirusTotal (only the hash is sent)."}
    if not re.fullmatch(r"[0-9a-f]{64}", sha256):
        return {"status": "error", "detail": "Invalid hash."}
    global _vt_pause_until
    with _vt_lock:
        hit = _vt_cache.get(sha256)
        paused = time.monotonic() < _vt_pause_until
    if hit and hit[0] > time.monotonic():
        return hit[1]
    if paused:
        return {"status": "error", "detail": "VirusTotal lookups are paused for a minute (rate limit or outage). The other checks still ran."}
    req = urllib.request.Request(VT_URL + sha256, headers={"x-apikey": key, "accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=VT_TIMEOUT_S) as r:
            body = json.load(r)
    except urllib.error.HTTPError as e:
        msg = {404: "This exact file is not known to VirusTotal.", 401: "VirusTotal rejected the API key.", 403: "VirusTotal rejected the API key.",
               429: "VirusTotal rate limit reached. Try again later."}.get(e.code, f"VirusTotal returned HTTP {e.code}.")
        res = {"status": "not_found" if e.code == 404 else "error", "detail": msg}
        if e.code == 404:
            return _vt_remember(sha256, res)
        if e.code in (429, 500, 502, 503, 504):
            _vt_pause_until = time.monotonic() + 60
        return res
    except Exception as e:
        _vt_pause_until = time.monotonic() + 30
        return {"status": "error", "detail": f"Could not reach VirusTotal ({type(e).__name__})."}
    attrs = (body.get("data") or {}).get("attributes") or {}
    stats = attrs.get("last_analysis_stats") or {}
    res = attrs.get("last_analysis_results") or {}
    order = {"malicious": 0, "suspicious": 1}
    engines = sorted(({"engine": n, "category": v.get("category", ""), "label": VT_LABEL.get(v.get("category", ""), v.get("category", "")),
                       "result": v.get("result") or ""} for n, v in res.items()), key=lambda e: (order.get(e["category"], 2), e["engine"].lower()))
    return _vt_remember(sha256, {"status": "found", "stats": stats, "engines": engines, "link": f"https://www.virustotal.com/gui/file/{sha256}",
                                 "detail": f"{stats.get('malicious', 0)} of {sum(stats.values())} engines flagged this file."})


def run_all(data: bytes, sha256: str) -> dict:
    """Sequential helper (kept for scripts). The web pipeline runs the two engines in parallel."""
    return {"clamav": clamav(data), "virustotal": virustotal(sha256)}


def engine_findings(engines: dict):
    f = []
    cl = engines.get("clamav", {})
    if cl.get("status") == "detected":
        f.append(("clamav_detection", 95, f"ClamAV detected: {cl.get('signature', 'unknown')}."))
    vt = engines.get("virustotal", {})
    m = (vt.get("stats") or {}).get("malicious", 0)
    if vt.get("status") == "found" and m:
        f.append(("vt_detections", min(95, 30 + 10 * m), f"{m} of {sum(vt['stats'].values())} VirusTotal engines flagged this exact file."))
    return f
