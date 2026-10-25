"""Production server settings: gunicorn -c gunicorn.conf.py app:app
Sizing rule of thumb: each analysed file runs in its own short-lived child process (about 100-300 MB).
Concurrent analyses = WEB_CONCURRENCY x GHOSTSCAN_MAX_CONCURRENT. Keep that below (RAM - 1 GB) / 300 MB."""
import multiprocessing, os

bind = f"{os.getenv('HOST', '0.0.0.0')}:{os.getenv('PORT', '8000')}"
workers = int(os.getenv("WEB_CONCURRENCY", max(2, min(4, multiprocessing.cpu_count()))))
worker_class = "gthread"                      # threads let one process serve many people while scans wait on child processes
threads = int(os.getenv("GUNICORN_THREADS", 8))
timeout = 90                                  # > queue wait (20 s) + worker limit (20 s) + engines
graceful_timeout = 30
keepalive = 5
max_requests = 1000                           # recycle processes now and then to cap memory growth
max_requests_jitter = 100
worker_tmp_dir = "/dev/shm" if os.path.isdir("/dev/shm") else None
limit_request_line = 4094
accesslog = "-"
errorlog = "-"
loglevel = os.getenv("LOG_LEVEL", "info")
forwarded_allow_ips = os.getenv("FORWARDED_ALLOW_IPS", "127.0.0.1")
