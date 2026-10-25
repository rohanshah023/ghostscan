"""Production-readiness checks: adversarial inputs finish fast, load control works, headers are safe.
Run: python -m unittest discover tests"""
import io, os, sys, threading, time, unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("GHOSTSCAN_RATE_LIMIT", "0")        # the rate-limit test builds its own limiter
from scanner import content_analysis as ca, pipeline
from scanner.pipeline import scan_file, scan_url, Busy
from scanner.static_analysis import analyze


class Adversarial(unittest.TestCase):
    """Inputs crafted to make regexes or loops blow up. Each must finish in a few seconds, not minutes."""
    LIMIT = 6.0

    def run_text(self, text, ext="php"):
        t = time.time()
        ca.analyze_text(text.encode(), ext)
        self.assertLess(time.time() - t, self.LIMIT)

    def test_many_matches_same_rule(self):
        self.run_text(("eval($_POST['a']);\n" * 100000)[:2_000_000])

    def test_many_urls(self):
        self.run_text(" ".join("http://1.2.3.4/x%d" % i for i in range(100000)), "txt")

    def test_unclosed_iframes(self):
        self.run_text("<iframe " * 250000, "html")

    def test_eval_followed_by_whitespace(self):
        self.run_text("<?php eval(" + " " * 1_900_000)

    def test_dotted_email_lookalike(self):
        self.run_text("a." * 1_000_000, "txt")

    def test_pdf_stream_flood(self):
        d = b"%PDF-1.4\n" + b"stream\n" * 300000
        t = time.time(); analyze(d, "pdf", "pdf", {}, "x"); ca.build(d, "pdf", "pdf")
        self.assertLess(time.time() - t, self.LIMIT)

    def test_full_scan_of_flood_is_bounded(self):
        t = time.time(); r = scan_file("a.php", ("eval($_POST['a']);\n" * 100000)[:2_000_000].encode())
        self.assertLess(time.time() - t, 15); self.assertGreaterEqual(r["score"], 70)


class LoadControl(unittest.TestCase):
    def test_same_file_is_analysed_once(self):
        calls = []
        orig = pipeline._spawn_worker
        pipeline._spawn_worker = lambda *a: (calls.append(1), orig(*a))[1]
        try:
            data = b"hello world, unique " + os.urandom(8).hex().encode()
            a = scan_file("a.txt", data); b = scan_file("b.txt", data)
        finally:
            pipeline._spawn_worker = orig
        self.assertEqual(len(calls), 1)
        self.assertEqual(a["score"], b["score"]); self.assertEqual(b["properties"]["filename"], "b.txt")

    def test_busy_when_no_free_slot(self):
        old = pipeline._slots, pipeline.QUEUE_WAIT_S
        pipeline._slots, pipeline.QUEUE_WAIT_S = threading.BoundedSemaphore(1), 0.2
        pipeline._slots.acquire()
        try:
            with self.assertRaises(Busy):
                scan_file("c.txt", b"fresh content " + os.urandom(8).hex().encode())
        finally:
            pipeline._slots, pipeline.QUEUE_WAIT_S = old

    def test_parallel_scans_complete(self):
        out, errs = [], []
        def go(i):
            try: out.append(scan_file(f"f{i}.txt", f"parallel sample {i} {os.urandom(4).hex()}".encode())["verdict"])
            except Exception as e: errs.append(e)
        ts = [threading.Thread(target=go, args=(i,)) for i in range(12)]
        t = time.time(); [x.start() for x in ts]; [x.join() for x in ts]
        self.assertEqual(errs, []); self.assertEqual(len(out), 12); self.assertLess(time.time() - t, 40)


class Web(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import app as appmod
        cls.appmod, cls.c = appmod, appmod.app.test_client()

    def test_health_and_headers(self):
        r = self.c.get("/healthz"); self.assertEqual(r.json, {"ok": True})
        r = self.c.get("/")
        self.assertEqual(r.status_code, 200)
        csp = r.headers["Content-Security-Policy"]
        for part in ("script-src 'self'", "frame-ancestors 'none'", "object-src 'none'"): self.assertIn(part, csp)
        self.assertEqual(r.headers["X-Frame-Options"], "DENY")
        html = r.get_data(as_text=True)
        self.assertNotIn(' style="', html)                  # inline styles would be blocked by the CSP
        self.assertIn("/static/app.js?v=", html)

    def test_errors_are_json_and_correct(self):
        r = self.c.get("/nope"); self.assertEqual(r.status_code, 404); self.assertIn("error", r.json)
        r = self.c.post("/api/scan/file"); self.assertEqual(r.status_code, 400)
        r = self.c.post("/api/scan/file", data={"file": (io.BytesIO(b"x" * (11 * 1024 * 1024)), "big.txt")}, content_type="multipart/form-data")
        self.assertEqual(r.status_code, 413)

    def test_scan_endpoint_and_no_store(self):
        r = self.c.post("/api/scan/file", data={"file": (io.BytesIO(b"just some text " + os.urandom(4).hex().encode()), "n.txt")}, content_type="multipart/form-data")
        self.assertEqual(r.status_code, 200); self.assertEqual(r.headers["Cache-Control"], "no-store")
        self.assertEqual(r.json["verdict"], "Clean")

    def test_rate_limit(self):
        rl = self.appmod.RateLimiter(3, 60)
        self.assertEqual([rl.check("ip") for _ in range(3)], [0, 0, 0]); self.assertGreater(rl.check("ip"), 0)
        self.assertEqual(rl.check("other"), 0)

    def test_rate_limit_returns_429(self):
        a = self.appmod
        old = a.limiter, a.RATE_LIMIT
        a.limiter, a.RATE_LIMIT = a.RateLimiter(1, 60), 1
        try:
            self.c.post("/api/scan/url", json={"url": "example.com"})
            r = self.c.post("/api/scan/url", json={"url": "example.com"})
            self.assertEqual(r.status_code, 429); self.assertIn("Retry-After", r.headers)
        finally:
            a.limiter, a.RATE_LIMIT = old

    def test_huge_dimension_image_rejected_cheaply(self):
        import struct, zlib
        def chunk(t, b): return struct.pack(">I", len(b)) + t + b + struct.pack(">I", zlib.crc32(t + b) & 0xffffffff)
        big = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", 30000, 30000, 8, 2, 0, 0, 0)) + chunk(b"IDAT", zlib.compress(b"\0" * 10)) + chunk(b"IEND", b"")
        t = time.time()
        r = self.c.post("/api/watermark/detect", data={"file": (io.BytesIO(big), "b.png")}, content_type="multipart/form-data")
        self.assertEqual(r.status_code, 400); self.assertLess(time.time() - t, 2)


class UrlDownloadGuard(unittest.TestCase):
    def test_private_addresses_blocked(self):
        from scanner.url_analysis import safe_download
        for u in ("http://127.0.0.1/a.exe", "http://localhost/x", "http://169.254.169.254/latest/meta-data/", "http://10.0.0.5/x", "http://[::1]/x"):
            with self.assertRaises(ValueError, msg=u):
                safe_download(u)

    def test_rebinding_uses_checked_ip(self):
        import socket
        from scanner import url_analysis as ua
        real = socket.getaddrinfo
        socket.getaddrinfo = lambda *a, **k: [(2, 1, 6, "", ("127.0.0.1", 0))]
        try:
            with self.assertRaises(ValueError):
                ua.safe_download("http://looks-public.example/x")
        finally:
            socket.getaddrinfo = real


if __name__ == "__main__":
    unittest.main()
