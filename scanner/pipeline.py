"""Glues the five stages together, with load control for a multi-user server."""
import json, os, subprocess, sys, tempfile, threading, time
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from config import (WORKER_TIMEOUT_S, MAX_CONCURRENT_SCANS, QUEUE_WAIT_S, CACHE_TTL_S, CACHE_MAX_ENTRIES)
from .validation import validate
from .scoring import score
from .report import build_checks, detection_label
from . import engines as engines_mod
from .url_analysis import analyze_url, safe_download

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class Busy(Exception):
    """All analysis slots stayed taken for too long. The caller should answer HTTP 503."""


_slots = threading.BoundedSemaphore(MAX_CONCURRENT_SCANS)
_engine_pool = ThreadPoolExecutor(max_workers=8, thread_name_prefix="engine")


class TTLCache:
    """Tiny thread-safe LRU with expiry. Identical files (same SHA-256) are analysed once per TTL."""

    def __init__(self, ttl, size):
        self.ttl, self.size, self.d, self.lock = ttl, size, OrderedDict(), threading.Lock()

    def get(self, key):
        with self.lock:
            hit = self.d.get(key)
            if not hit or hit[0] < time.monotonic():
                self.d.pop(key, None)
                return None
            self.d.move_to_end(key)
            return hit[1]

    def put(self, key, value):
        with self.lock:
            self.d[key] = (time.monotonic() + self.ttl, value)
            self.d.move_to_end(key)
            while len(self.d) > self.size:
                self.d.popitem(last=False)


_analysis_cache = TTLCache(CACHE_TTL_S, CACHE_MAX_ENTRIES)
_engine_cache = TTLCache(min(CACHE_TTL_S, 300), CACHE_MAX_ENTRIES)   # engine answers can change (new signatures)


def _failed(rule, text):
    return {"findings": [(rule, 40, text)], "metadata": {}, "entropy": {"overall": 0, "blocks": []}, "contents": []}


def _child_env():
    env = {"PATH": "", "OPENBLAS_NUM_THREADS": "1", "OMP_NUM_THREADS": "1", "MKL_NUM_THREADS": "1"}
    if os.name == "nt":                                   # Windows needs these to start Python
        env.update({k: os.environ[k] for k in ("SYSTEMROOT", "TEMP", "TMP") if k in os.environ})
    return env


def _spawn_worker(data: bytes, ftype: str, ext: str, sha: str) -> dict:
    """Write bytes to a private temp file (mode 600, never executable) and analyse in a sandboxed child.
    The child applies its own CPU/memory/file limits (see worker.py), so no preexec_fn is needed."""
    with tempfile.TemporaryDirectory(prefix="ghostscan_") as d:
        p = os.path.join(d, "sample.bin")
        fd = os.open(p, os.O_WRONLY | os.O_CREAT, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        try:
            r = subprocess.run([sys.executable, "-I", "-B", os.path.join(ROOT, "scanner", "worker.py"), p, ftype, ext, sha],
                               capture_output=True, timeout=WORKER_TIMEOUT_S, cwd=ROOT, env=_child_env(),
                               start_new_session=(os.name == "posix"))
        except subprocess.TimeoutExpired:
            return _failed("worker_timeout", "Analysis exceeded the time limit (possible parser bomb).")
        if r.returncode != 0:
            return _failed("worker_crash", "Analyser crashed or hit a resource limit on this file.")
        try:
            out = json.loads(r.stdout)
        except ValueError:
            return _failed("worker_crash", "Analyser returned unreadable output.")
        out["findings"] = [tuple(x) for x in out["findings"]]
        return out


def run_isolated(data: bytes, ftype: str, ext: str, sha: str) -> dict:
    key = (sha, ftype, ext)
    hit = _analysis_cache.get(key)
    if hit is not None:
        return hit
    if not _slots.acquire(timeout=QUEUE_WAIT_S):          # bounded wait, then a clear "busy" answer
        raise Busy()
    try:
        out = _spawn_worker(data, ftype, ext, sha)
    finally:
        _slots.release()
    if not any(f[0] in ("worker_timeout", "worker_crash") for f in out["findings"]):
        _analysis_cache.put(key, out)                      # never cache failures that may only reflect server load
    return out


def run_engines(data: bytes, sha: str):
    """Start ClamAV and the VirusTotal lookup in the background so they overlap with the analysis worker."""
    cached = _engine_cache.get(sha)
    if cached is not None:
        return lambda: cached
    fc, fv = _engine_pool.submit(engines_mod.clamav, data), _engine_pool.submit(engines_mod.virustotal, sha)

    def collect():
        def get(f, fallback):
            try:
                return f.result(timeout=max(engines_mod.CLAMD_TIMEOUT_S, engines_mod.CLAMSCAN_TIMEOUT_S) + 5)
            except Exception:
                return fallback
        res = {"clamav": get(fc, {"engine": "ClamAV", "status": "error", "detail": "ClamAV did not answer in time."}),
               "virustotal": get(fv, {"status": "error", "detail": "VirusTotal did not answer in time."})}
        _engine_cache.put(sha, res)
        return res
    return collect


def scan_file(filename: str, data: bytes) -> dict:
    v = validate(filename, data)
    if not v["ok"]:
        return {"kind": "file", "rejected": True, "errors": v["errors"], "properties": v["props"]}
    p = v["props"]
    ftype = p["detected_type"]
    collect = run_engines(data, p["sha256"])               # engines work while the worker analyses
    st = run_isolated(data, ftype, p["extension"], p["sha256"])
    eng = collect()
    res = score(v["findings"] + st["findings"] + engines_mod.engine_findings(eng), st["entropy"], ftype)
    return {"kind": "file", "rejected": False, **res, "properties": p, "metadata": st["metadata"], "entropy": st["entropy"],
            "contents": st.get("contents", []), "engines": eng, "checks": build_checks(ftype, res["evidence"], eng),
            "label": detection_label(res["evidence"])}


def scan_url(url: str, download: bool = False) -> dict:
    a = analyze_url(url)
    if not a["ok"]:
        return {"kind": "url", "rejected": True, "errors": a["errors"], "properties": a["props"]}
    findings, extra = a["findings"], {}
    if download:
        try:
            name, data = safe_download(url)
            file_res = scan_file(name, data)
            extra["downloaded_file"] = {k: file_res.get(k) for k in ("verdict", "score", "properties")}
            if not file_res.get("rejected"):
                findings += [(e["rule"], e["weight"], "Downloaded file: " + e["evidence"]) for e in file_res["evidence"]]
        except Exception as e:
            findings.append(("download_failed", 5, f"Download was not scanned: {e}"))
    res = score(findings)
    return {"kind": "url", "rejected": False, **res, "properties": a["props"], "metadata": extra,
            "entropy": {"overall": 0, "blocks": []}}
