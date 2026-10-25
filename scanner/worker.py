"""Isolated worker: parses ONE file and prints JSON. Runs in a child process with
rlimits (CPU, memory, no core dumps, no new files) and a wall-clock timeout set by the parent.
The limits are applied here, inside the child, before the untrusted bytes are read. That avoids
preexec_fn in the parent, which is unsafe in a multi-threaded web server."""
import json, os, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from config import WORKER_MEM_BYTES, WORKER_CPU_S
from scanner.static_analysis import analyze, load_known_bad


def apply_limits():
    """Each limit is applied on its own: some are unsupported on macOS (e.g. RLIMIT_AS) and must not abort the scan."""
    try:
        import resource
    except ImportError:          # Windows: no rlimits, the parent's timeout is the only guard
        return
    for name, val in (("RLIMIT_CPU", WORKER_CPU_S), ("RLIMIT_AS", WORKER_MEM_BYTES),
                      ("RLIMIT_CORE", 0), ("RLIMIT_FSIZE", 0)):
        try:
            resource.setrlimit(getattr(resource, name), (val, val))
        except (ValueError, OSError, AttributeError):
            pass


if __name__ == "__main__":
    path, ftype, ext, sha = sys.argv[1:5]
    with open(path, "rb") as fh:
        data = fh.read()
    apply_limits()
    db = load_known_bad(os.path.join(ROOT, "data", "known_bad_hashes.txt"))
    out = analyze(data, ftype, ext, db, sha)
    out["findings"] = [list(x) for x in out["findings"]]
    sys.stdout.write(json.dumps(out))
