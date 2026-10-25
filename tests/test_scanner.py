"""Run: python -m unittest discover tests   (creates harmless synthetic samples only)"""
import io, struct, sys, os, unittest, zipfile, zlib
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scanner.pipeline import scan_file, scan_url


def png(trailing=b""):
    def chunk(t, b): return struct.pack(">I", len(b)) + t + b + struct.pack(">I", zlib.crc32(t + b) & 0xffffffff)
    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", zlib.compress(b"\x00\x00\x00\x00")) + chunk(b"IEND", b"") + trailing


class T(unittest.TestCase):
    def test_clean_png(self):
        r = scan_file("a.png", png()); self.assertEqual(r["verdict"], "Clean")

    def test_png_hidden_payload(self):
        r = scan_file("a.png", png(b"<?php eval($_POST['x']); ?>" + b"A" * 80))
        self.assertGreaterEqual(r["score"], 70)

    def test_disguised_exe(self):
        r = scan_file("photo.jpg", b"MZ" + b"\x90" * 200 + b"This program cannot be run in DOS mode")
        self.assertEqual(r["verdict"], "Malicious")

    def test_eicar(self):
        e = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        self.assertEqual(scan_file("t.txt", e)["score"], 100)

    def test_pdf_js_launch(self):
        d = b"%PDF-1.4\n1 0 obj<</OpenAction<</S/JavaScript/JS(app.alert(1))>>>>endobj\n%%EOF"
        self.assertIn(scan_file("x.pdf", d)["verdict"], ("Suspicious", "Malicious"))

    def test_docx_macro(self):
        b = io.BytesIO()
        with zipfile.ZipFile(b, "w") as z:
            z.writestr("[Content_Types].xml", "<x/>"); z.writestr("word/vbaProject.bin", b"AutoOpen Shell CreateObject")
        self.assertGreaterEqual(scan_file("x.docx", b.getvalue())["score"], 70)

    def test_zip_bomb(self):
        b = io.BytesIO()
        with zipfile.ZipFile(b, "w", zipfile.ZIP_DEFLATED) as z: z.writestr("a.txt", b"0" * 30_000_000)
        self.assertGreaterEqual(scan_file("b.zip", b.getvalue())["score"], 60)

    def test_rejects(self):
        self.assertTrue(scan_file("a.exe", b"MZ")["rejected"]); self.assertTrue(scan_file("a.png", b"")["rejected"])

    def test_urls(self):
        self.assertGreaterEqual(scan_url("http://paypal-secure-login.xn--tk.top/verify/account/login.exe")["score"], 70)
        self.assertLess(scan_url("https://www.python.org/downloads/")["score"], 10)


class Stego(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import numpy as np
        from PIL import Image, ImageFilter
        rng = np.random.default_rng(7)
        n = rng.normal(size=(384, 384, 3))
        im = Image.fromarray(((n - n.min()) / (n.max() - n.min()) * 255).astype("uint8")).filter(ImageFilter.GaussianBlur(6))
        a = np.array(im).astype(float); a = (a - a.min()) / (a.max() - a.min()) * 220 + 15 + rng.normal(0, 1.2, a.shape)
        cls.im = Image.fromarray(np.clip(a, 0, 255).astype("uint8"))
        cls.png = __import__("scanner.stego", fromlist=["x"]).to_png(cls.im)

    def test_lsb_roundtrip_and_passphrase(self):
        from scanner import stego
        self.assertEqual(stego.lsb_reveal(stego.lsb_hide(self.png, "hello")["png"]), "hello")
        p = stego.lsb_hide(self.png, "secret", "pw")["png"]
        self.assertEqual(stego.lsb_reveal(p, "pw"), "secret")
        self.assertIsNone(stego.lsb_reveal(p, "wrong"))
        self.assertIsNone(stego.lsb_reveal(self.png))

    def test_lsb_too_big(self):
        from scanner import stego
        with self.assertRaises(stego.StegoError): stego.lsb_hide(self.png, "x" * 60000)

    def test_dct_watermark_survives_jpeg(self):
        from scanner import stego
        w = stego.dct_watermark(self.im, "owner-42", "k")
        self.assertEqual(stego.dct_detect(w, "k")["text"], "owner-42")
        self.assertFalse(stego.dct_detect(w, "other")["found"])
        self.assertFalse(stego.dct_detect(self.im, "k")["found"])
        b = io.BytesIO(); w.save(b, "JPEG", quality=80)
        self.assertEqual(stego.dct_detect(stego.load_image(b.getvalue()), "k")["text"], "owner-42")

    def test_text_zero_width(self):
        from scanner import stego
        t = stego.text_hide("Normal looking sentence.", "meet at 9", "pw")
        self.assertEqual(stego.text_reveal(t, "pw"), "meet at 9")
        self.assertEqual(scan_file("n.txt", t.encode())["verdict"] in ("Suspicious", "Low risk"), True)

    def test_scanner_flags_lsb_fill(self):
        import numpy as np
        from PIL import Image
        arr = np.array(self.im); flat = arr.reshape(-1)
        flat[:] = (flat & 0xFE) | np.random.default_rng(1).integers(0, 2, len(flat)).astype(np.uint8)
        b = io.BytesIO(); Image.fromarray(flat.reshape(arr.shape)).save(b, "PNG")
        rules = [e["rule"] for e in scan_file("x.png", b.getvalue())["evidence"]]
        self.assertIn("lsb_stats_strong", rules)
        self.assertEqual(scan_file("clean.png", self.png)["verdict"], "Clean")


class Content(unittest.TestCase):
    SHELL = b"<?php\nerror_reporting(0);\n@eval($_POST['x']);\nmove_uploaded_file($_FILES['f']['tmp_name'],'/tmp/x');\necho 'File Manager Upload file chmod Symlink uname -a';\n?>"

    def test_php_webshell_detected_with_label_and_contents(self):
        r = scan_file("shell.php", self.SHELL)
        self.assertEqual(r["verdict"], "Malicious")
        self.assertEqual(r["label"], "Heuristic.Backdoor.PHP.WebShell")
        titles = [c["title"] for c in r["contents"]]
        self.assertIn("Dangerous code found", titles); self.assertIn("Functions and commands used", titles)
        st = {c["name"]: c["status"] for c in r["checks"]}
        self.assertEqual(st["Script and web shell analysis"], "Detected")
        self.assertEqual(st["Macros and active content"], "Not applicable")

    def test_benign_php_is_clean(self):
        r = scan_file("hello.php", b"<?php\n$n = htmlspecialchars($_GET['name']);\necho 'Hello ' . $n;\n")
        self.assertEqual(r["verdict"], "Clean")

    def test_shell_disguised_as_image(self):
        r = scan_file("photo.jpg", self.SHELL)
        rules = [e["rule"] for e in r["evidence"]]
        self.assertIn("ext_mismatch", rules); self.assertIn("php_eval_request", rules)
        r2 = scan_file("shell.php.jpg", self.SHELL)
        self.assertIn("double_ext", [e["rule"] for e in r2["evidence"]])

    def test_php_inside_png_and_trailing_section(self):
        import struct as st, zlib as zl
        def ch(t, b): return st.pack(">I", len(b)) + t + b + st.pack(">I", zl.crc32(t + b) & 0xffffffff)
        png = b"\x89PNG\r\n\x1a\n" + ch(b"IHDR", st.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)) + ch(b"IDAT", zl.compress(b"\x00\x00\x00\x00")) + ch(b"IEND", b"")
        r = scan_file("a.png", png + b"<?php echo 1; ?>" + b"A" * 80)
        self.assertIn("php_tag_embedded", [e["rule"] for e in r["evidence"]])
        self.assertTrue(any(c["title"].startswith("Data hidden after") for c in r["contents"]))

    def test_zip_contents_lists_nested_and_executables(self):
        inner = io.BytesIO()
        with zipfile.ZipFile(inner, "w") as z: z.writestr("payload.exe", b"MZ" + b"\x00" * 100)
        outer = io.BytesIO()
        with zipfile.ZipFile(outer, "w") as z: z.writestr("docs/readme.txt", b"hi"); z.writestr("inner.zip", inner.getvalue())
        r = scan_file("bundle.zip", outer.getvalue())
        rules = [e["rule"] for e in r["evidence"]]
        self.assertIn("nested_archive", rules); self.assertIn("member_executable", rules)
        names = [c["cells"][0] for c in r["contents"][0]["rows"]]
        self.assertTrue(any("payload.exe" in n for n in names))

    def test_virustotal_parsing_with_mock(self):
        import os, json, urllib.request
        from scanner import engines
        body = {"data": {"attributes": {"last_analysis_stats": {"malicious": 2, "undetected": 3, "type-unsupported": 1},
                "last_analysis_results": {"MaxSecure": {"category": "malicious", "result": "Backdoor.W32.PHP.WebShell.gen"},
                "Avast": {"category": "undetected", "result": None}, "Elastic": {"category": "type-unsupported", "result": None},
                "Rising": {"category": "malicious", "result": "Backdoor.WebShell/PHP!1.D563"}}}}}
        class Resp:
            def __enter__(s): return s
            def __exit__(s, *a): return False
            def read(s, *a): return json.dumps(body).encode()
        orig = urllib.request.urlopen
        urllib.request.urlopen = lambda req, timeout=0: Resp()
        os.environ["GHOSTSCAN_VT_API_KEY"] = "test"
        try:
            vt = engines.virustotal("a" * 64)
            self.assertEqual(vt["status"], "found"); self.assertEqual(vt["engines"][0]["category"], "malicious")
            self.assertEqual([e for e in vt["engines"] if e["engine"] == "Elastic"][0]["label"], "Unable to process file type")
            self.assertEqual(engines.engine_findings({"virustotal": vt})[0][0], "vt_detections")
        finally:
            urllib.request.urlopen = orig; del os.environ["GHOSTSCAN_VT_API_KEY"]
        self.assertEqual(engines.virustotal("a" * 64)["status"], "not_configured")


if __name__ == "__main__":
    unittest.main()
