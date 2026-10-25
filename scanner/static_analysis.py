"""Stage 3 - static analysis. Files are treated purely as bytes; nothing is executed or rendered."""
import io, math, re, struct, zipfile, zlib
import numpy as np
from config import MAX_ZIP_RATIO, MAX_ZIP_ENTRIES, MAX_ZIP_UNCOMPRESSED

from . import stego, content_analysis

F = list  # findings: list of (rule_id, weight 0-100, evidence)


def shannon_entropy(b: bytes) -> float:
    """Bits per byte, 0..8. Encrypted/packed payloads sit near 8."""
    if not b:
        return 0.0
    counts = np.bincount(np.frombuffer(b, dtype=np.uint8), minlength=256)
    p = counts[counts > 0] / len(b)
    return float(-(p * np.log2(p)).sum())


# ---------- generic signature / pattern layer (YARA-style, pure Python) ----------
EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
PATTERNS = [  # (rule_id, weight, regex, description)
    ("eicar", 100, re.compile(re.escape(EICAR)), "EICAR antivirus test signature."),
    ("php_webshell", 70, re.compile(rb"eval\s*\(\s*(base64_decode|\$_(POST|GET|REQUEST))|system\s*\(\s*\$_", re.I),
     "PHP web-shell pattern."),
    ("powershell", 55, re.compile(rb"powershell(\.exe)?\s+.{0,40}(-enc|-nop|-w\s+hidden|iex|downloadstring)", re.I | re.S),
     "Obfuscated or download-and-run PowerShell."),
    ("script_tag", 40, re.compile(rb"<script[\s>]|javascript:|onerror\s*=", re.I), "Embedded HTML/JS."),
    ("cmd_exec", 45, re.compile(rb"cmd(\.exe)?\s*/c|wscript\.shell|mshta|regsvr32|rundll32|certutil\s+-urlcache", re.I),
     "Windows command-execution / LOLBin reference."),
    ("shell_dl", 45, re.compile(rb"(curl|wget)\s+[^\n]{0,80}\|\s*(ba)?sh", re.I), "Download-and-pipe-to-shell."),
    ("pe_in_data", 55, re.compile(rb"This program cannot be run in DOS mode"), "Embedded Windows PE executable."),
    ("b64_pe", 50, re.compile(rb"TVqQAAMAAAAEAAAA"), "Base64-encoded Windows executable (MZ header)."),
    ("ip_url", 20, re.compile(rb"https?://\d{1,3}(\.\d{1,3}){3}"), "URL pointing at a raw IP address."),
]


# Cheap substring test (fast C search) that must be true before the slower regex can possibly match.
PREFILTER = {
    "eicar": (b"eicar-standard-antivirus-test-file",), "php_webshell": (b"eval", b"system"),
    "powershell": (b"powershell",), "script_tag": (b"<script", b"javascript:", b"onerror"),
    "cmd_exec": (b"cmd", b"wscript.shell", b"mshta", b"regsvr32", b"rundll32", b"certutil"),
    "shell_dl": (b"curl", b"wget"), "pe_in_data": (b"this program cannot be run in dos mode",),
    "b64_pe": (b"tvqqaamaaaaeaaaa",), "ip_url": (b"http",),
}


def scan_patterns(data: bytes, skip=()) -> F:
    out, low = [], None
    for rid, w, rx, desc in PATTERNS:
        if rid in skip:
            continue
        if low is None:
            low = data.lower()
        need = PREFILTER.get(rid)
        if need and not any(k in low for k in need):
            continue
        m = rx.search(data)
        if m:
            out.append((rid, w, f"{desc} (offset {m.start()})"))
    return out


def load_known_bad(path):
    db = {}
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    h, _, label = line.partition(" ")
                    db[h.lower()] = label.strip() or "known-bad"
    except OSError:
        pass
    return db


# ---------- PNG ----------
def analyze_png(data: bytes):
    f, meta = [], {}
    pos, chunks, text_chunks, saw_iend = 8, [], [], False
    while pos + 8 <= len(data):
        length, ctype = struct.unpack(">I4s", data[pos:pos + 8])
        end = pos + 8 + length + 4
        if end > len(data):
            f.append(("png_truncated", 25, f"Chunk {ctype!r} runs past end of file (malformed)."))
            break
        body = data[pos + 8:pos + 8 + length]
        crc = struct.unpack(">I", data[end - 4:end])[0]
        if zlib.crc32(ctype + body) & 0xffffffff != crc:
            f.append(("png_bad_crc", 20, f"Chunk {ctype.decode('latin1')} has an invalid CRC."))
        chunks.append(ctype.decode("latin1"))
        if ctype == b"IHDR" and length == 13:
            w, h, bd, ct = struct.unpack(">IIBB", body[:10])
            meta.update(width=w, height=h, bit_depth=bd, color_type=ct)
            if w * h > 100_000_000:
                f.append(("decompression_bomb", 40, f"Image is {w}x{h} px - possible decompression bomb."))
        if ctype in (b"tEXt", b"iTXt", b"zTXt"):
            text_chunks.append(body[:200])
            if len(body) > 4096 or shannon_entropy(body) > 7.0:
                f.append(("png_text_payload", 35, f"Large/high-entropy {ctype.decode()} chunk ({length} bytes)."))
        if ctype == b"IEND":
            saw_iend = True
            trailing = data[end:]
            meta["trailing_bytes"] = len(trailing)
            if len(trailing) > 0:
                w_ = 45 if len(trailing) > 64 else 15
                f.append(("trailing_data", w_, f"{len(trailing)} bytes appended after IEND (hidden/polyglot payload)."))
            break
        pos = end
    if not saw_iend:
        f.append(("png_no_iend", 20, "PNG has no IEND chunk."))
    meta["chunks"] = chunks[:30]
    meta["text_metadata"] = [t.decode("latin1", "replace") for t in text_chunks[:5]]
    return f, meta


# ---------- JPEG ----------
def analyze_jpg(data: bytes):
    f, meta, pos = [], {}, 2
    eoi = data.rfind(b"\xff\xd9")
    # walk segments until SOS
    while pos + 4 <= len(data) and data[pos] == 0xFF:
        marker = data[pos + 1]
        if marker == 0xDA:
            break
        seglen = struct.unpack(">H", data[pos + 2:pos + 4])[0]
        seg = data[pos + 4:pos + 2 + seglen]
        if marker == 0xE1 and seg.startswith(b"Exif"):
            meta["has_exif"] = True
            meta["exif_size"] = len(seg)
            for tag, label in ((b"Make", "camera make"), (b"Software", "software")):
                if tag in seg:
                    meta[label] = True
        if marker == 0xFE:
            meta["comment"] = seg[:120].decode("latin1", "replace")
            if re.search(rb"<\?php|<script|eval\(|powershell", seg, re.I):
                f.append(("jpg_comment_code", 60, "JPEG comment field contains executable code."))
        if marker in (0xE1, 0xE2, 0xED) and len(seg) > 60000:
            f.append(("jpg_big_segment", 25, f"Unusually large metadata segment ({len(seg)} bytes)."))
        if marker in (0xC0, 0xC2) and len(seg) >= 5:
            h, w = struct.unpack(">HH", seg[1:5])
            meta.update(width=w, height=h)
        pos += 2 + seglen
    if eoi != -1:
        trailing = len(data) - (eoi + 2)
        meta["trailing_bytes"] = trailing
        if trailing > 0:
            f.append(("trailing_data", 45 if trailing > 64 else 15,
                      f"{trailing} bytes appended after the JPEG end marker (hidden payload)."))
    else:
        f.append(("jpg_no_eoi", 15, "JPEG has no end-of-image marker (truncated or malformed)."))
    return f, meta


# ---------- PDF ----------
PDF_KEYS = {
    b"/JavaScript": (35, "Embedded JavaScript"), b"/JS": (30, "JavaScript action"),
    b"/OpenAction": (25, "Action runs when the document opens"), b"/AA": (15, "Additional auto-actions"),
    b"/Launch": (50, "Launch action (starts an external program)"),
    b"/EmbeddedFile": (30, "Embedded file attachment"), b"/RichMedia": (30, "Flash/RichMedia content"),
    b"/XFA": (25, "XFA form (frequent exploit vector)"), b"/URI": (5, "Link to external URL"),
    b"/SubmitForm": (20, "Form submission to remote server"), b"/GoToR": (25, "Remote go-to action"),
    b"/ObjStm": (5, "Object streams (can hide objects)"), b"/Encrypt": (10, "Encrypted content"),
}


def analyze_pdf(data: bytes):
    f, meta = [], {}
    meta["version"] = data[:8].decode("latin1", "replace").strip()
    meta["pages"] = len(re.findall(rb"/Type\s*/Page[^s]", data))
    hits = {}
    for key, (w, desc) in PDF_KEYS.items():
        n = len(re.findall(re.escape(key) + rb"(?![A-Za-z])", data))
        if n:
            hits[key.decode()] = n
            f.append((f"pdf{key.decode().lower()}", w, f"{desc} - {key.decode()} x{n}"))
    meta["keyword_counts"] = hits
    # name obfuscation: /J#61vaScript
    if re.search(rb"/[A-Za-z]*#[0-9A-Fa-f]{2}[A-Za-z#0-9]*", data):
        f.append(("pdf_name_obfuscation", 30, "PDF names use #xx hex escapes (obfuscation technique)."))
    # info dictionary
    for k in (b"Producer", b"Creator", b"Author", b"CreationDate", b"ModDate", b"Title"):
        m = re.search(rb"/" + k + rb"\s*\(([^)]{0,100})\)", data)
        if m:
            meta[k.decode().lower()] = m.group(1).decode("latin1", "replace")
    if b"%%EOF" in data:
        trailing = len(data) - (data.rfind(b"%%EOF") + 5)
        if trailing > 1024:
            f.append(("trailing_data", 30, f"{trailing} bytes after the final %%EOF."))
        meta["eof_count"] = data.count(b"%%EOF")
    else:
        f.append(("pdf_no_eof", 15, "PDF has no %%EOF marker."))
    # inflate a few streams and rescan - JS is often hidden in compressed streams
    inflated = 0
    for body in content_analysis.iter_streams(data):
        if inflated >= 40:
            break
        try:
            d = zlib.decompressobj().decompress(body, 2_000_000)
        except zlib.error:
            continue
        inflated += 1
        if re.search(rb"app\.(alert|launchURL)|this\.exportDataObject|util\.printf|unescape\(|eval\(", d):
            f.append(("pdf_stream_js", 45, "Compressed stream contains JavaScript exploit-style calls."))
            break
    meta["streams_inspected"] = inflated
    return f, meta


# ---------- OOXML / ZIP ----------
def analyze_zip(data: bytes, ext: str):
    f, meta = [], {}
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        return [("bad_zip", 30, "Archive structure is corrupt.")], meta
    infos = z.infolist()
    meta["entries"] = len(infos)
    total_u = sum(i.file_size for i in infos)
    total_c = sum(i.compress_size for i in infos) or 1
    meta["uncompressed_bytes"] = total_u
    meta["compression_ratio"] = round(total_u / total_c, 1)
    if len(infos) > MAX_ZIP_ENTRIES or total_u > MAX_ZIP_UNCOMPRESSED or total_u / total_c > MAX_ZIP_RATIO:
        f.append(("zip_bomb", 70, f"Archive expands to {total_u // 1024} KB at ratio {total_u / total_c:.0f}:1 (zip bomb)."))
        return f, meta       # never extract a suspected bomb
    names = [i.filename for i in infos]
    if any(n.startswith("/") or ".." in n.split("/") for n in names):
        f.append(("zip_traversal", 60, "Archive contains path-traversal entries (zip-slip)."))
    if any(i.flag_bits & 1 for i in infos):
        f.append(("zip_encrypted", 25, "Archive contains password-protected entries (evades scanners)."))
    exes = [n for n in names if n.lower().endswith(tuple("." + e for e in
            ("exe", "dll", "js", "vbs", "ps1", "bat", "scr", "jar", "lnk", "hta")))]
    if exes:
        f.append(("zip_executables", 55, f"Archive holds executable/script files: {', '.join(exes[:4])}"))

    low = [n.lower() for n in names]
    if any(n.endswith("vbaproject.bin") for n in low):
        f.append(("vba_macro", 55, "Document contains a VBA macro project (vbaProject.bin)."))
    if ext in ("docm", "xlsm"):
        f.append(("macro_ext", 15, f".{ext} is a macro-enabled format."))
    if any("/embeddings/" in n or n.endswith(".bin") and "vba" not in n for n in low):
        f.append(("ole_embedded", 35, "Document embeds OLE objects."))
    if any("activex" in n for n in low):
        f.append(("activex", 45, "Document contains ActiveX controls."))

    # relationships: external targets are template-injection / remote-content vectors
    ext_targets = []
    for i in infos:
        if i.filename.endswith(".rels") and i.file_size < 1_000_000:
            body = z.read(i)
            for m in re.finditer(rb'Target="([^"]+)"[^>]{0,500}TargetMode="External"', body):
                ext_targets.append(m.group(1).decode("latin1", "replace"))
            if re.search(rb"attachedTemplate", body) and re.search(rb'TargetMode="External"', body):
                f.append(("remote_template", 60, "Document loads a remote template (template injection)."))
    ext_targets = list(dict.fromkeys(ext_targets))
    meta["external_links"] = ext_targets[:10]
    if ext_targets:
        f.append(("external_rel", 20, f"{len(ext_targets)} external relationship(s), e.g. {ext_targets[0][:80]}"))

    # content scan of xml parts (bounded)
    scanned, scanned_bytes = 0, 0
    for i in infos:
        if scanned > 60 or i.file_size > 5_000_000 or scanned_bytes > 30_000_000:
            continue
        scanned_bytes += i.file_size
        if i.filename.endswith((".xml", ".rels")) or i.filename.lower().endswith("document.xml"):
            body = z.read(i)
            scanned += 1
            if re.search(rb"DDEAUTO|\bDDE\b\s", body) or re.search(rb"<w:instrText[^>]*>\s*DDE", body):
                f.append(("dde", 55, f"DDE field in {i.filename} (command execution without macros)."))
            if re.search(rb'w:fldSimple[^>]*w:instr="[^"]*(INCLUDETEXT|INCLUDEPICTURE)\s+"?https?', body, re.I):
                f.append(("field_remote", 35, "Field pulls remote content."))
            if re.search(rb"Auto_Open|AutoOpen|Document_Open|Workbook_Open", body):
                f.append(("autoexec", 45, "Auto-execute macro name present."))
            if i.filename.startswith(("word/", "xl/sharedStrings", "ppt/slides/")):
                f += stego.unicode_findings(re.sub(r"<[^>]+>", "", body.decode("utf-8", "ignore")))
    # docProps metadata
    for part, tags in (("docProps/core.xml", ("creator", "lastModifiedBy", "created", "modified", "title")),
                       ("docProps/app.xml", ("Application", "Company", "AppVersion"))):
        if part in names:
            body = z.read(part)
            for t in tags:
                m = re.search(rb"<[\w:]*" + t.encode() + rb"[^>]*>([^<]*)<", body)
                if m:
                    meta[t] = m.group(1).decode("utf-8", "replace")[:80]
    # binary payload inside vba project
    if "word/vbaProject.bin" in names or "xl/vbaProject.bin" in names:
        vb = z.read("word/vbaProject.bin" if "word/vbaProject.bin" in names else "xl/vbaProject.bin")
        if re.search(rb"Shell|CreateObject|WScript|URLDownloadToFile|powershell|Environ", vb, re.I):
            f.append(("vba_suspicious_api", 50, "Macro references Shell/CreateObject/download APIs."))
    return f, meta


# ---------- legacy OLE (doc/xls) ----------
def analyze_ole(data: bytes):
    f, meta = [], {}
    if re.search(rb"VBA|_VBA_PROJECT", data):
        f.append(("vba_macro", 55, "Legacy Office file contains a VBA macro stream."))
    if re.search(rb"AutoOpen|Auto_Open|Document_Open|Workbook_Open", data):
        f.append(("autoexec", 45, "Auto-execute macro name present."))
    if re.search(rb"Shell|CreateObject|WScript\.Shell|URLDownloadToFile|powershell", data, re.I):
        f.append(("vba_suspicious_api", 50, "Macro references Shell/CreateObject/download APIs."))
    return f, meta


def entropy_profile(data: bytes, blocks=16):
    """Entropy per block - spikes expose encrypted/packed regions inside a normal-looking file."""
    if not data:
        return []
    size = max(len(data) // blocks, 1)
    return [round(shannon_entropy(data[i:i + size]), 2) for i in range(0, len(data), size)][:blocks]


def analyze(data: bytes, ftype: str, ext: str, known_bad: dict, sha256: str) -> dict:
    findings, meta = [], {}
    if sha256 in known_bad:
        findings.append(("known_hash", 100, f"SHA-256 matches known threat: {known_bad[sha256]}."))
    handlers = {"png": lambda: analyze_png(data), "jpg": lambda: analyze_jpg(data),
                "pdf": lambda: analyze_pdf(data), "zip": lambda: analyze_zip(data, ext),
                "ole": lambda: analyze_ole(data)}
    if ftype in handlers:
        try:
            f, meta = handlers[ftype]()
            findings += f
        except Exception as e:                     # malformed on purpose? that is itself a signal
            findings.append(("parser_error", 20, f"Parser failed ({type(e).__name__}) - file may be deliberately malformed."))
    if ftype in ("png", "jpg"):
        try:
            sf, sm = stego.analyze_image(data)
            findings += sf
            meta.update(sm)
        except Exception as e:
            meta["stego_analysis"] = f"skipped ({type(e).__name__})"
    if ftype in ("text", "rtf"):
        findings += stego.unicode_findings(data.decode("utf-8", "ignore"))
    contents = []
    try:
        cf, contents = content_analysis.build(data, ftype, ext)
        findings += cf
    except Exception as e:
        contents = [content_analysis.sec("Contents", ["Note"], [content_analysis.row([f"Content breakdown skipped ({type(e).__name__})."])])]
    if ftype in ("png", "jpg", "pdf", "zip", "ole") and re.search(rb"<\?php", data):
        findings.append(("php_tag_embedded", 55, "PHP code tag found inside a file that should not contain PHP."))
    # images are binary data; skip noisy text patterns on compressed pixel data.
    # For text files the content analysis already covers scripts, so skip the older overlapping rules.
    skip = ("script_tag", "ip_url") if ftype in ("png", "jpg") else \
           ("php_webshell", "powershell", "cmd_exec", "shell_dl", "script_tag") if ftype in ("text", "script", "unknown") else ()
    findings += scan_patterns(data, skip=skip)
    profile = entropy_profile(data)
    overall = round(shannon_entropy(data), 2)
    if ftype in ("txt", "rtf", "text") and overall > 7.2:
        findings.append(("high_entropy_text", 35, f"Text file has entropy {overall}/8 (looks encrypted or packed)."))
    return {"findings": findings, "metadata": meta, "entropy": {"overall": overall, "blocks": profile}, "contents": contents}
