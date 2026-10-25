"""Central configuration. Override with environment variables (see .env.example)."""
import os


def _int(name, default):
    try:
        return int(os.getenv(name, default))
    except ValueError:
        return default


def _float(name, default):
    try:
        return float(os.getenv(name, default))
    except ValueError:
        return default


MAX_FILE_BYTES = _int("GHOSTSCAN_MAX_BYTES", 10 * 1024 * 1024)   # 10 MB
ALLOWED_EXT = {"jpg", "jpeg", "png", "pdf", "docx", "docm", "xlsx", "xlsm",
               "pptx", "doc", "xls", "zip", "txt", "rtf",
               "php", "phtml", "php5", "js", "html", "htm", "asp", "aspx", "jsp", "py", "sh", "ps1", "vbs", "bat", "cmd"}

# --- isolated analysis worker (one short-lived child process per file) ---
WORKER_TIMEOUT_S = _int("GHOSTSCAN_TIMEOUT", 20)                       # wall-clock limit
WORKER_MEM_BYTES = _int("GHOSTSCAN_WORKER_MEM_MB", 1536) * 1024 * 1024  # address-space cap for the worker
WORKER_CPU_S = _int("GHOSTSCAN_WORKER_CPU_S", 15)

# --- load control (per web-server process) ---
# How many files may be analysed at the same time in ONE server process. Extra requests wait up to
# QUEUE_WAIT_S for a free slot and then get a friendly "busy, try again" answer instead of piling up.
MAX_CONCURRENT_SCANS = _int("GHOSTSCAN_MAX_CONCURRENT", max(2, os.cpu_count() or 2))
QUEUE_WAIT_S = _float("GHOSTSCAN_QUEUE_WAIT_S", 20)
# Heavy image tools (hide/reveal/watermark) run inside the web process, so they get their own small limit.
MAX_CONCURRENT_IMAGE_JOBS = _int("GHOSTSCAN_MAX_IMAGE_JOBS", 2)

# --- caches: the same file (same SHA-256) is not analysed twice within the TTL ---
CACHE_TTL_S = _int("GHOSTSCAN_CACHE_TTL_S", 600)
CACHE_MAX_ENTRIES = _int("GHOSTSCAN_CACHE_MAX", 128)

# --- abuse protection: requests per client IP per window (per server process) ---
RATE_LIMIT = _int("GHOSTSCAN_RATE_LIMIT", 30)
RATE_WINDOW_S = _int("GHOSTSCAN_RATE_WINDOW_S", 60)
TRUST_PROXY = _int("GHOSTSCAN_TRUST_PROXY", 0)      # number of reverse proxies in front (nginx = 1)

# --- optional engines ---
CLAMD_SOCKET = os.getenv("GHOSTSCAN_CLAMD_SOCKET", "")             # e.g. /run/clamav/clamd.ctl
CLAMD_HOST = os.getenv("GHOSTSCAN_CLAMD_HOST", "")                 # e.g. clamav (docker-compose)
CLAMD_PORT = _int("GHOSTSCAN_CLAMD_PORT", 3310)
CLAMD_TIMEOUT_S = _int("GHOSTSCAN_CLAMD_TIMEOUT", 15)
CLAMSCAN_FALLBACK = os.getenv("GHOSTSCAN_CLAMSCAN_FALLBACK", "1") == "1"   # slow: loads the whole signature DB per file
CLAMSCAN_TIMEOUT_S = _int("GHOSTSCAN_CLAMSCAN_TIMEOUT", 30)
VT_TIMEOUT_S = _float("GHOSTSCAN_VT_TIMEOUT", 6)
VT_CACHE_TTL_S = _int("GHOSTSCAN_VT_CACHE_TTL_S", 3600)

ALLOW_URL_DOWNLOAD = os.getenv("GHOSTSCAN_ALLOW_DOWNLOAD", "0") == "1"  # off by default
MAX_ZIP_RATIO = 100          # uncompressed/compressed ratio => zip bomb
MAX_ZIP_ENTRIES = 2000
MAX_ZIP_UNCOMPRESSED = 200 * 1024 * 1024
