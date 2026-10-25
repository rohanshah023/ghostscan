"""Content breakdown: shows WHAT is inside a file, and analyses scripts and web shells.
Everything here runs on bytes inside the isolated worker. Nothing is executed or rendered.

Each section is {title, columns, rows:[{cells, flag}], note}; flag is 'high', 'medium' or ''.
"""
import base64, binascii, bisect, io, re, struct, zipfile, zlib
from collections import Counter
from itertools import islice
from .validation import detect_type

MAX_ROWS = 60
MAX_TEXT = 2_000_000
R = re.I


def clean(s, n=140):
    if isinstance(s, bytes):
        s = s.decode("latin1")
    s = re.sub(r"[^\x20-\x7e]", ".", str(s))
    return s[:n] + ("..." if len(s) > n else "")


def row(cells, flag=""):
    return {"cells": [clean(c, 160) for c in cells], "flag": flag}


def sec(title, columns, rows, note=""):
    extra = f" Showing the first {MAX_ROWS} of {len(rows)}." if len(rows) > MAX_ROWS else ""
    return {"title": title, "columns": columns, "rows": rows[:MAX_ROWS], "note": (note + extra).strip()}


def human(n):
    return f"{n} B" if n < 1024 else f"{n / 1024:.1f} KB" if n < 1048576 else f"{n / 1048576:.1f} MB"


def trailing_section(tail: bytes, what: str):
    if not tail:
        return None
    kind = detect_type(tail[:16])
    strings = re.findall(rb"[\x20-\x7e]{6,}", tail[:4000])
    rows = [row(["Size", human(len(tail))], "high" if len(tail) > 64 else "medium"),
            row(["Looks like", kind if kind != "unknown" else "binary data"]),
            row(["First bytes (hex)", tail[:24].hex(" ")]),
            row(["Readable text", clean(b" | ".join(strings[:3]), 150) if strings else "(none)"])]
    return sec(f"Data hidden after the {what}", ["Item", "Value"], rows,
               "Normal files have nothing after their end marker. Extra bytes are a common way to hide a payload.")


# ======================================================================= scripts and web shells
LANG_BY_EXT = {"php": "PHP", "phtml": "PHP", "php5": "PHP", "js": "JavaScript", "html": "HTML", "htm": "HTML",
               "asp": "ASP", "aspx": "ASP", "jsp": "JSP", "py": "Python", "sh": "Shell", "ps1": "PowerShell",
               "vbs": "VBScript", "bat": "Batch", "cmd": "Batch"}
ALL = None
PHP, JS, SH, PS, PY, VB, BAT = {"PHP"}, {"JavaScript", "HTML"}, {"Shell"}, {"PowerShell"}, {"Python"}, {"VBScript"}, {"Batch"}


def C(p, f=R):
    return re.compile(p, f)


TEXT_RULES = [
    ("php_eval_request", 90, C(r"\b(?:eval|assert|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\(\s*(?:@\s*)?(?:(?:base64_decode|gzinflate|str_rot13|rawurldecode|urldecode)\s*\(\s*)*(?:@\s*)?\$_(?:POST|GET|REQUEST|COOKIE|SERVER)\b"),
     "Code or a command is run straight from request data (classic web shell).", PHP),
    ("php_decode_eval", 75, C(r"\b(?:eval|assert)\s*\(\s*(?:@\s*)?(?:gzinflate|gzuncompress|gzdecode|base64_decode|str_rot13|strrev|convert_uudecode)\s*\("),
     "Decoded or decompressed data is passed to eval (hidden payload).", PHP),
    ("php_dynamic_call", 70, C(r"\$\{?\w+\}?\s*\(\s*(?:@\s*)?\$_(?:POST|GET|REQUEST|COOKIE)\b", 0),
     "A variable is called as a function with request data (can run any function).", PHP),
    ("php_include_request", 60, C(r"\b(?:include|require)(?:_once)?\s*\(?\s*(?:@\s*)?\$_(?:GET|POST|REQUEST|COOKIE)\b"),
     "File inclusion controlled by request data.", PHP),
    ("php_preg_e", 60, C(r"preg_replace\s*\(\s*(['\"])[^'\"\n]*/[a-z]*e[a-z]*\1"), "preg_replace with the /e modifier runs code.", PHP),
    ("php_known_shell", 85, C(r"\b(?:c99(?:shell|madshell)?|r57(?:shell)?|b374k|FilesMan|weevely|indoxploit|alfa\s*shell|p0wny|wso\s*(?:shell|\d))\b"),
     "Name of a well-known web shell.", PHP),
    ("php_create_function", 50, C(r"\bcreate_function\s*\("), "create_function builds code at run time.", PHP),
    ("php_exec_func", 35, C(r"(?<![\w$>:])(?:system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\("), "Operating system command functions are used.", PHP),
    ("php_socket", 35, C(r"(?<![\w$>:])(?:fsockopen|pfsockopen|stream_socket_client|socket_create)\s*\("), "Raw network socket (reverse shell or scanner).", PHP),
    ("php_file_write_request", 40, C(r"\b(?:file_put_contents|fwrite|fputs)\s*\([^;]{0,120}\$_(?:POST|GET|REQUEST|COOKIE)\b"), "A file is written with request data.", PHP),
    ("php_upload", 30, C(r"\bmove_uploaded_file\s*\("), "Accepts file uploads (a way to drop more code).", PHP),
    ("php_sysinfo", 20, C(r"\bphp_uname\s*\(|\bphpinfo\s*\(|/etc/passwd|\buname\s+-a|posix_getpwuid|disable_functions"), "Collects system information.", PHP),
    ("php_quiet", 15, C(r"error_reporting\s*\(\s*0\s*\)|ini_set\s*\(\s*['\"]display_errors['\"]\s*,\s*['\"]?0|set_time_limit\s*\(\s*0\s*\)"), "Hides errors or removes the time limit.", PHP),
    ("py_reverse_shell", 85, C(r"pty\.spawn|os\.dup2\s*\(\s*\w+\.fileno|socket\.socket\([^)]{0,100}\)[\s\S]{0,200}\.connect\("), "Reverse shell pattern.", PY),
    ("py_exec_decode", 60, C(r"\b(?:exec|eval)\s*\(\s*(?:base64\.b64decode|zlib\.decompress|marshal\.loads|codecs\.decode|bytes\.fromhex)\s*\("), "Decoded data is executed.", PY),
    ("js_eval_decode", 60, C(r"\beval\s*\(\s*(?:atob|unescape|decodeURIComponent|String\.fromCharCode)\s*\("), "Decoded data is passed to eval.", JS),
    ("js_write_unescape", 50, C(r"document\.write\s*\(\s*unescape\s*\("), "Writes decoded content into the page.", JS),
    ("js_activex", 55, C(r"ActiveXObject|WScript\.Shell|Scripting\.FileSystemObject"), "Windows scripting objects (can run programs and write files).", JS),
    ("js_fromcharcode", 35, C(r"String\.fromCharCode\s*\((?:\s*\d+\s*,){10,}"), "Text built from a long list of character codes (obfuscation).", JS),
    ("js_hidden_iframe", 45, C(r"<iframe[^>]{0,300}(?:width|height)\s*=\s*[\"']?0|<iframe[^>]{0,300}display\s*:\s*none"), "Hidden iframe (drive-by download or redirect).", JS),
    ("js_miner", 55, C(r"coinhive|cryptonight|coin-hive|coinimp|minero\.cc"), "Cryptocurrency miner reference.", JS),
    ("sh_reverse_shell", 90, C(r"/dev/tcp/\d|\bbash\s+-i\s*>&|\bmkfifo\b[^\n]{0,40}\bnc\b|\bnc(?:\.traditional|at)?\s+[^\n]{0,30}\s-e\s|socat\b[^\n]{0,80}exec:"), "Reverse shell pattern.", SH),
    ("sh_persistence", 40, C(r"crontab\s+-|/etc/cron\.|authorized_keys|/etc/rc\.local"), "Persistence (cron or SSH keys).", SH),
    ("sh_download_exec", 60, C(r"(?:curl|wget)\s[^\n|]{0,120}\|\s*(?:sudo\s+)?(?:ba)?sh\b"), "Downloads and runs a script in one step.", SH),
    ("ps_encoded", 60, C(r"-(?:enc|encodedcommand|ec)\s+[A-Za-z0-9+/=]{30,}"), "Encoded PowerShell command.", PS),
    ("ps_download", 60, C(r"DownloadString|DownloadFile|Net\.WebClient|Invoke-WebRequest|Start-BitsTransfer|\biwr\s"), "PowerShell downloads from the internet.", PS),
    ("ps_iex", 55, C(r"\bIEX\b|Invoke-Expression"), "Runs text as code (Invoke-Expression).", PS),
    ("ps_evasion", 35, C(r"-w(?:indowstyle)?\s+hidden|-nop\b|-noprofile|-ep\s+bypass|ExecutionPolicy\s+Bypass"), "Hidden window or policy bypass.", PS),
    ("ps_amsi", 70, C(r"AmsiUtils|amsiInitFailed|AmsiScanBuffer"), "Tampering with the Windows antimalware interface.", PS),
    ("vbs_shell", 55, C(r"CreateObject\s*\(\s*[\"']WScript\.Shell|Wscript\.Shell|Shell\.Application"), "Runs programs through Windows scripting.", VB),
    ("vbs_download", 55, C(r"MSXML2\.(?:Server)?XMLHTTP|ADODB\.Stream|URLDownloadToFile|WinHttp\.WinHttpRequest"), "Downloads and saves a file.", VB),
    ("bat_lolbin", 50, C(r"certutil[^\n]{0,60}-urlcache|bitsadmin\s+/transfer|\bmshta\b|regsvr32\s+/s|rundll32[^\n]{0,60}javascript"), "Windows tools abused to download or run code.", BAT),
]
SHELL_UI = ["file manager", "upload file", "chmod", "symlink", "safe mode", "server info", "execute command", "bypass",
            "/etc/passwd", "uname -a", "cmd.exe", "mass deface", "sql manager", "bind shell", "back-connect"]

FUNCS = {
    "PHP": [("eval", "high"), ("assert", "high"), ("system", "high"), ("exec", "high"), ("shell_exec", "high"), ("passthru", "high"),
            ("popen", "high"), ("proc_open", "high"), ("pcntl_exec", "high"), ("create_function", "high"), ("base64_decode", "medium"),
            ("gzinflate", "medium"), ("gzuncompress", "medium"), ("str_rot13", "medium"), ("file_put_contents", "medium"),
            ("move_uploaded_file", "medium"), ("fsockopen", "medium"), ("chmod", "medium"), ("preg_replace", ""), ("fwrite", ""),
            ("curl_exec", ""), ("mail", ""), ("unlink", ""), ("phpinfo", "")],
    "JavaScript": [("eval", "high"), ("ActiveXObject", "high"), ("atob", "medium"), ("unescape", "medium"), ("fromCharCode", "medium"),
                   ("document.write", "medium"), ("XMLHttpRequest", ""), ("WebSocket", "")],
    "PowerShell": [("Invoke-Expression", "high"), ("IEX", "high"), ("DownloadString", "high"), ("DownloadFile", "high"),
                   ("FromBase64String", "medium"), ("Start-Process", "medium"), ("Invoke-WebRequest", "medium"), ("Add-Type", "medium")],
    "Shell": [("eval", "high"), ("/dev/tcp", "high"), ("curl", "medium"), ("wget", "medium"), ("nc", "medium"), ("crontab", "medium"), ("base64", "medium"), ("chmod", "")],
    "Python": [("exec", "high"), ("eval", "high"), ("os.system", "high"), ("marshal.loads", "high"), ("subprocess", "medium"),
               ("socket", "medium"), ("base64.b64decode", "medium"), ("pickle.loads", "medium")],
}
SUSP_DECODED = re.compile(rb"eval|<\?php|powershell|cmd\.exe|/bin/sh|system\s*\(|https?://|^MZ", R)


def guess_language(text, ext):
    if ext in LANG_BY_EXT:
        return LANG_BY_EXT[ext]
    t = text[:20000]
    if "<?php" in t or "<?=" in t:
        return "PHP"
    if re.search(r"<html|<script|<iframe", t, R):
        return "HTML"
    first = t.split("\n", 1)[0]
    if first.startswith("#!"):
        return "Python" if "python" in first else "Shell"
    if re.search(r"\bpowershell\b|Invoke-Expression|\$PSVersionTable", t, R):
        return "PowerShell"
    return "Text"


_LC = [None, None]       # (text, newline offsets) of the text last indexed


def line_of(text, pos):
    """1-based line number of offset pos. Indexes the newlines once per text, so many lookups stay fast."""
    if _LC[0] is not text:
        nl, i = [], text.find("\n")
        while i != -1:
            nl.append(i)
            i = text.find("\n", i + 1)
        _LC[0], _LC[1] = text, nl
    return bisect.bisect_left(_LC[1], pos) + 1


def iter_streams(data: bytes, max_streams: int = 400):
    """Yield the raw bytes of PDF streams using find() only (no backtracking regex, linear time)."""
    pos = n = 0
    while n < max_streams:
        s = data.find(b"stream", pos)
        if s == -1:
            return
        pos = s + 6
        if data[max(s - 3, 0):s] == b"end":
            continue
        i = s + 6
        if data[i:i + 2] == b"\r\n":
            i += 2
        elif data[i:i + 1] == b"\n":
            i += 1
        else:
            continue
        e = data.find(b"endstream", i)
        if e == -1:
            return
        body = data[i:e]
        body = body[:-2] if body.endswith(b"\r\n") else body[:-1] if body.endswith(b"\n") else body
        pos, n = e + 9, n + 1
        yield body


def analyze_text(data: bytes, ext: str):
    findings, sections = [], []
    text = data[:MAX_TEXT].decode("utf-8", "replace")
    lang = guess_language(text, ext)
    active = {lang}
    if "<?php" in text or "<?=" in text:
        active.add("PHP")
    if lang == "HTML":
        active.add("JavaScript")
    lines = text.split("\n")
    longest = max((len(l) for l in lines), default=0)
    nonprint = sum(1 for b in data[:100000] if b < 9 or 13 < b < 32) / max(len(data[:100000]), 1)
    sections.append(sec("File overview", ["Item", "Value"], [
        row(["Language (guessed)", lang]), row(["Size", human(len(data))]), row(["Lines", len(lines)]),
        row(["Longest line", f"{longest} characters", ], "medium" if longest > 3000 else ""),
        row(["Control characters", f"{nonprint:.1%}"], "medium" if nonprint > 0.02 else "")]))

    hits = []
    for rid, w, rx, desc, langs in TEXT_RULES:
        if langs is not None and lang != "Text" and not (langs & active):
            continue
        ms = list(rx.finditer(text))
        if ms:
            ls = []
            for m in ms:
                ln = line_of(text, m.start())
                if ln not in ls:
                    ls.append(ln)
                if len(ls) >= 6:
                    break
            findings.append((rid, w, f"{desc} Line {ls[0]}: {clean(ms[0].group(0), 80)}"))
            hits.append(row([desc, len(ms), ", ".join(map(str, ls))], "high" if w >= 50 else "medium"))
    low = text.lower()
    ui = [s for s in SHELL_UI if s in low]
    if len(ui) >= 3:
        findings.append(("shell_ui_strings", 40, "Text typical of a web shell control panel: " + ", ".join(ui[:5])))
        hits.append(row(["Web shell control panel wording", len(ui), ", ".join(ui[:5])], "high"))
    if hits:
        sections.append(sec("Dangerous code found", ["What was found", "Times", "Lines"], hits,
                            "Each row is one detection rule. High means it is a strong sign of malicious code."))

    # function and command inventory
    inv = []
    for lg in (active & set(FUNCS)) or ({"PHP", "JavaScript", "PowerShell", "Shell", "Python"} if lang == "Text" else set()):
        for name, risk in FUNCS[lg]:
            pat = (r"(?<![\w$>:])" + re.escape(name) + r"\b") if lg in ("PowerShell", "Shell") else (r"(?<![\w$>:.])" + re.escape(name) + r"\s*\(")
            if name not in text:
                continue
            rx = re.compile(pat)
            n = sum(1 for _ in rx.finditer(text))
            if n:
                where = [line_of(text, m.start()) for m in islice(rx.finditer(text), 4)]
                inv.append((risk, row([f"{name}  ({lg})", n, ", ".join(map(str, where)), risk or "normal"], risk)))
    if inv:
        order = {"high": 0, "medium": 1, "": 2}
        inv.sort(key=lambda x: order[x[0]])
        sections.append(sec("Functions and commands used", ["Name", "Times", "First lines", "Risk"], [r for _, r in inv]))

    if "PHP" in active:
        src = [(v, text.count(v)) for v in ("$_POST", "$_GET", "$_REQUEST", "$_COOKIE", "$_FILES", "$_SERVER")]
        src = [row([v, n], "medium" if v in ("$_POST", "$_REQUEST", "$_COOKIE") else "") for v, n in src if n]
        if src:
            sections.append(sec("User input the code reads", ["Source", "Times"], src,
                                "Web shells take their commands from request data such as $_POST."))

    # obfuscation
    obf, hexn = [], len(re.findall(r"\\x[0-9a-fA-F]{2}", text))
    chr_chain = len(re.findall(r"chr\s*\(\s*\d+\s*\)(?:\s*\.\s*chr\s*\(\s*\d+\s*\)){5,}", text, R))
    if hexn >= 40:
        findings.append(("obf_hex", 35, f"{hexn} hex escape sequences (text is hidden as codes)."))
        obf.append(row(["Hex escape sequences", hexn], "high"))
    if chr_chain:
        findings.append(("obf_chr", 30, f"{chr_chain} strings built from chr() chains."))
        obf.append(row(["chr() chains", chr_chain], "high"))
    if longest > 3000:
        findings.append(("obf_longline", 20, f"A single line is {longest} characters long (packed code)."))
        obf.append(row(["Very long line", f"{longest} characters"], "medium"))

    # network, paths, encoded blobs
    net = []
    urls = re.findall(r"https?://[^\s'\"<>)\\]{4,200}", text)
    for u, n in Counter(urls).most_common(15):
        net.append(row(["URL", u, n]))
    ips = set(islice(re.findall(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b", text), 2000))
    for ip in sorted(ips)[:10]:
        net.append(row(["IP address", ip, text.count(ip)], "medium"))
    for em in sorted(set(re.findall(r"\b[\w.+-]{1,64}@[\w-]{1,63}\.[\w.-]{2,63}\b", text)))[:8]:
        net.append(row(["Email", em, 1]))
    if net:
        sections.append(sec("Network indicators", ["Type", "Value", "Times"], net))
    paths = re.findall(r"(/etc/passwd|/etc/shadow|/bin/(?:ba)?sh|/tmp/[\w./-]+|/var/www/[\w./-]+|[A-Za-z]:\\\\Windows[\\\\\w.]*|%APPDATA%|%TEMP%|\.htaccess|wp-config\.php)", text)
    if paths:
        sections.append(sec("System paths mentioned", ["Path", "Times"],
                            [row([p, paths.count(p)], "medium") for p in sorted(set(paths))[:15]]))
    enc = []
    for m in islice(re.finditer(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{60,}={0,2}", text), 15):
        s = m.group(0)
        try:
            dec = base64.b64decode(s + "=" * (-len(s) % 4))
        except (binascii.Error, ValueError):
            continue
        if sum(32 <= b < 127 or b in (9, 10, 13) for b in dec[:200]) / max(len(dec[:200]), 1) < 0.7 and not dec.startswith(b"MZ"):
            continue
        sus = bool(SUSP_DECODED.search(dec[:3000]))
        enc.append(row(["Base64", f"line {line_of(text, m.start())}, {len(s)} chars", clean(dec[:70], 70)], "high" if sus else ""))
        if sus:
            findings.append(("obf_base64_payload", 55, f"Base64 text on line {line_of(text, m.start())} decodes to suspicious content: {clean(dec[:50], 50)}"))
    for m in islice(re.finditer(r"(?<![0-9a-fA-F])(?:[0-9a-fA-F]{2}){32,}(?![0-9a-fA-F])", text), 5):
        try:
            dec = binascii.unhexlify(m.group(0))
        except (binascii.Error, ValueError):
            continue
        sus = dec.startswith((b"MZ", b"\x7fELF")) or bool(SUSP_DECODED.search(dec[:3000]))
        enc.append(row(["Hex string", f"line {line_of(text, m.start())}, {len(dec)} bytes", clean(dec[:50], 50)], "high" if sus else ""))
        if sus:
            findings.append(("obf_hex_payload", 55, "A hex string decodes to a program or script."))
    if obf:
        sections.append(sec("Obfuscation signs", ["Sign", "Amount"], obf, "Obfuscation hides what code does from people and scanners."))
    if enc:
        sections.append(sec("Encoded data inside the file", ["Encoding", "Where", "Decoded preview"], enc))
    return findings, sections


# ======================================================================= binary formats
PNG_NOTES = {b"IHDR": "image header", b"IDAT": "pixel data", b"IEND": "end of image", b"PLTE": "colour palette",
             b"tEXt": "text metadata", b"iTXt": "text metadata", b"zTXt": "compressed text metadata", b"pHYs": "pixel size",
             b"gAMA": "gamma", b"sRGB": "colour space", b"tRNS": "transparency", b"eXIf": "EXIF metadata", b"caBX": "C2PA content credentials",
             b"iCCP": "colour profile", b"tIME": "last change time", b"bKGD": "background colour", b"cHRM": "chromaticity"}


def png_contents(data):
    rows, extra, pos, tail_at = [], [], 8, None
    while pos + 8 <= len(data):
        ln, ct = struct.unpack(">I4s", data[pos:pos + 8])
        end = pos + 12 + ln
        if end > len(data):
            rows.append(row([len(rows) + 1, ct.decode("latin1"), ln, "runs past the end of the file"], "high"))
            break
        note, flag = PNG_NOTES.get(ct, "unknown chunk"), ""
        if ct not in PNG_NOTES:
            flag = "medium"
        if ct in (b"tEXt", b"iTXt") and ln:
            k, _, v = data[pos + 8:pos + 8 + ln].partition(b"\x00")
            extra.append(row([ct.decode(), clean(k, 40), clean(v, 90)], "high" if ln > 4096 else ""))
        rows.append(row([len(rows) + 1, ct.decode("latin1"), ln, note], flag))
        if ct == b"IEND":
            tail_at = end
            break
        pos = end
    out = [sec("Image structure (PNG chunks)", ["#", "Chunk", "Bytes", "Meaning"], rows)]
    if extra:
        out.append(sec("Text stored in the image", ["Chunk", "Key", "Value"], extra))
    t = trailing_section(data[tail_at:] if tail_at else b"", "end of the image")
    return out + ([t] if t else [])


JPG_NOTES = {0xE0: "JFIF header", 0xE1: "EXIF or XMP metadata", 0xE2: "colour profile", 0xED: "Photoshop data", 0xFE: "comment",
             0xDB: "quantisation table", 0xC0: "image size (baseline)", 0xC2: "image size (progressive)", 0xC4: "Huffman table", 0xDD: "restart interval"}


def jpg_contents(data):
    rows, pos = [], 2
    while pos + 4 <= len(data) and data[pos] == 0xFF:
        mk = data[pos + 1]
        if mk == 0xDA:
            rows.append(row(["0xFFDA", "start of image data", "-"]))
            break
        ln = struct.unpack(">H", data[pos + 2:pos + 4])[0]
        seg = data[pos + 4:pos + 2 + ln]
        note, flag = JPG_NOTES.get(mk, "other segment"), ""
        if mk == 0xFE:
            note += ": " + clean(seg, 70)
            flag = "high" if re.search(rb"<\?php|<script|eval\(|powershell", seg, R) else ""
        if mk in (0xE1, 0xE2, 0xED) and ln > 60000:
            flag = "medium"
        rows.append(row([f"0xFF{mk:02X}", note, ln], flag))
        pos += 2 + ln
    out = [sec("Image structure (JPEG segments)", ["Marker", "Meaning", "Bytes"], rows)]
    eoi = data.rfind(b"\xff\xd9")
    t = trailing_section(data[eoi + 2:] if eoi != -1 else b"", "end of the image")
    return out + ([t] if t else [])


def pdf_contents(data):
    out = []
    objs = len(re.findall(rb"\d+\s+\d+\s+obj\b", data))
    streams = len(re.findall(rb"\bstream\r?\n", data))
    pages = len(re.findall(rb"/Type\s*/Page[^s]", data))
    filt = {f: len(re.findall(re.escape(f.encode()), data)) for f in ("/FlateDecode", "/ASCIIHexDecode", "/ASCII85Decode", "/LZWDecode", "/RunLengthDecode", "/JBIG2Decode", "/DCTDecode")}
    rows = [row(["PDF version", data[:8].decode("latin1").strip()]), row(["Objects", objs]), row(["Pages", pages]), row(["Streams", streams]),
            row(["Updates (%%EOF markers)", data.count(b"%%EOF")], "medium" if data.count(b"%%EOF") > 3 else "")]
    for f, n in filt.items():
        if n:
            rows.append(row([f"Filter {f}", n], "medium" if f in ("/ASCIIHexDecode", "/ASCII85Decode", "/LZWDecode") and n else ""))
    out.append(sec("Document structure", ["Item", "Value"], rows, "Stacked or unusual filters can be used to hide content."))
    from .static_analysis import PDF_KEYS
    risky = []
    for key, (w, desc) in PDF_KEYS.items():
        n = len(re.findall(re.escape(key) + rb"(?![A-Za-z])", data))
        if n:
            risky.append(row([key.decode(), n, desc], "high" if w >= 30 else "medium" if w >= 15 else ""))
    if risky:
        out.append(sec("Active content and features", ["Keyword", "Times", "Meaning"], risky))
    uris = sorted(set(re.findall(rb"/URI\s*\(([^)]{1,150})\)", data)))[:20]
    if uris:
        out.append(sec("Links inside the PDF", ["URL"], [row([u.decode("latin1")]) for u in uris]))
    files = sorted(set(re.findall(rb"/F\s*\(([^)]{1,100})\)", data)))[:10] if b"/EmbeddedFile" in data else []
    if files:
        out.append(sec("Embedded files", ["Name"], [row([f.decode("latin1")], "high") for f in files]))
    js = []
    for m in re.finditer(rb"/JS\s*\(((?:[^)\\]|\\.){1,300})\)", data):
        js.append(row(["Direct /JS", clean(m.group(1), 150)], "high"))
    n = 0
    for body in iter_streams(data):
        if n >= 40:
            break
        try:
            d = zlib.decompressobj().decompress(body, 2_000_000)
        except zlib.error:
            continue
        n += 1
        if re.search(rb"app\.(alert|launchURL)|this\.exportDataObject|util\.printf|unescape\(|eval\(", d):
            js.append(row(["Inflated stream", clean(d[:200], 150)], "high"))
    if js:
        out.append(sec("Script code found inside", ["Where", "Start of the code"], js[:10]))
    meta = []
    for k in ("Title", "Author", "Creator", "Producer", "CreationDate", "ModDate"):
        m = re.search(rb"/" + k.encode() + rb"\s*\(([^)]{0,100})\)", data)
        if m:
            meta.append(row([k, m.group(1).decode("latin1")]))
    if meta:
        out.append(sec("Document information", ["Field", "Value"], meta))
    last = data.rfind(b"%%EOF")
    t = trailing_section(data[last + 5:].lstrip(b"\r\n ") if last != -1 and len(data) - last - 5 > 1024 else b"", "last %%EOF marker")
    return out + ([t] if t else [])


DANGEROUS_MEMBER = (".exe", ".dll", ".js", ".vbs", ".ps1", ".bat", ".scr", ".jar", ".lnk", ".hta", ".php", ".jsp", ".sh", ".msi", ".cmd")


def zip_contents(data, depth=0, prefix="", budget=None):
    """Returns (rows, findings, remaining_budget). Looks into nested archives up to 2 levels."""
    from .static_analysis import scan_patterns
    budget = budget if budget is not None else {"read": 30_000_000, "rows": 400}
    rows, findings = [], []
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        return rows, findings, budget
    for i in z.infolist()[:400]:
        if budget["rows"] <= 0:
            break
        budget["rows"] -= 1
        name = prefix + i.filename
        ratio = i.file_size / max(i.compress_size, 1)
        kind, flag, note = "", "", []
        low = i.filename.lower()
        if i.is_dir():
            continue
        if i.flag_bits & 1:
            flag, note = "medium", note + ["password protected"]
        if low.endswith(DANGEROUS_MEMBER):
            flag, note = "high", note + ["program or script"]
            findings.append(("member_executable", 55, f"Program or script inside the archive: {name}"))
        if low.endswith("vbaproject.bin"):
            flag, note = "high", note + ["macro project"]
        if ratio > 100 and i.file_size > 1_000_000:
            flag, note = "high", note + [f"expands {ratio:.0f}:1"]
        if not (i.flag_bits & 1) and i.file_size <= 2_000_000 and budget["read"] > 0:
            try:
                body = z.read(i)
            except Exception:
                body = b""
            budget["read"] -= len(body)
            kind = detect_type(body[:16])
            if kind in ("exe", "elf", "macho/java") and not low.endswith(DANGEROUS_MEMBER):
                flag, note = "high", note + [f"real type is {kind}"]
                findings.append(("member_disguised", 60, f"{name} is really a {kind} program."))
            if kind == "zip" and depth < 2:
                note.append("nested archive")
                flag = flag or "medium"
                findings.append(("nested_archive", 15, f"Archive inside an archive: {name}"))
                sub_rows, sub_f, budget = zip_contents(body, depth + 1, name + " > ", budget)
                rows += sub_rows
                findings += sub_f
            for rid, w, ev in scan_patterns(body[:1_000_000], skip=("script_tag", "ip_url")):
                if w >= 45:
                    flag, note = "high", note + [rid]
                    findings.append(("member_" + rid, w, f"{name}: {ev}"))
        rows.append(row([name, human(i.file_size), human(i.compress_size), f"{ratio:.1f}", kind or "-", "; ".join(note) or "-"], flag))
    return rows, findings, budget


def zip_sections(data):
    rows, findings, _ = zip_contents(data)
    order = {"high": 0, "medium": 1, "": 2}
    rows.sort(key=lambda r: order[r["flag"]])
    out = [sec("Files inside the archive", ["Name", "Size", "Packed", "Ratio", "Real type", "Notes"], rows,
               "Word, Excel and PowerPoint files are ZIP archives of small parts. Risky parts are listed first.")]
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
        ext = []
        for i in z.infolist():
            if i.filename.endswith(".rels") and i.file_size < 1_000_000:
                for m in re.finditer(rb'Target="([^"]+)"[^>]{0,500}TargetMode="External"', z.read(i)):
                    ext.append(row([i.filename, m.group(1).decode("latin1")], "medium"))
        if ext:
            out.append(sec("External links the document loads", ["Defined in", "Target"], ext))
        for part in ("word/vbaProject.bin", "xl/vbaProject.bin", "ppt/vbaProject.bin"):
            if part in z.namelist():
                vb = z.read(part)
                names = sorted(set(re.findall(rb"(AutoOpen|Auto_Open|Document_Open|Workbook_Open|Shell|CreateObject|WScript|URLDownloadToFile|powershell|Environ|GetObject|SaveToFile|XMLHTTP)", vb, R)))
                out.append(sec("Macro project details", ["Item", "Value"], [row(["Project file", part], "high"), row(["Size", human(len(vb))]),
                               row(["Keywords found", ", ".join(n.decode() for n in names) or "(none)"], "high" if names else "")]))
    except Exception:
        pass
    return out, findings


def ole_contents(data):
    kws = sorted(set(m.group(0).decode("latin1") for m in re.finditer(rb"AutoOpen|Auto_Open|Document_Open|Workbook_Open|Shell|CreateObject|WScript\.Shell|URLDownloadToFile|powershell|Environ|XMLHTTP", data, R)))
    macro = bool(re.search(rb"VBA|_VBA_PROJECT", data))
    return [sec("Legacy Office file details", ["Item", "Value"], [row(["Macro (VBA) stream", "present" if macro else "not found"], "high" if macro else ""),
                row(["Keywords found", ", ".join(kws) or "(none)"], "high" if kws else "")])]


INTERESTING = re.compile(rb"cmd\.exe|powershell|/bin/(?:ba)?sh|https?://|CreateObject|WScript|\.exe\b|password|passwd|eval\(|base64|VirtualAlloc|LoadLibrary|GetProcAddress", R)


def string_sections(data):
    hits = []
    for m in re.finditer(rb"[\x20-\x7e]{6,}", data[:3_000_000]):
        if INTERESTING.search(m.group(0)):
            hits.append(row([f"0x{m.start():x}", clean(m.group(0), 120)], "medium"))
        if len(hits) >= MAX_ROWS:
            break
    return [sec("Interesting text found in the file", ["Offset", "Text"], hits)] if hits else []


def build(data: bytes, ftype: str, ext: str):
    """Returns (findings, sections) for a file of the given real type."""
    if ftype in ("text", "script", "unknown", "rtf"):
        f, s = analyze_text(data, ext)
        if ftype == "unknown":
            s += string_sections(data)
        return f, s
    if ftype == "png":
        return [], png_contents(data) + string_sections(data[-200000:])
    if ftype == "jpg":
        return [], jpg_contents(data)
    if ftype == "pdf":
        return [], pdf_contents(data)
    if ftype == "zip":
        s, f = zip_sections(data)
        return f, s
    if ftype == "ole":
        return [], ole_contents(data) + string_sections(data)
    return [], string_sections(data)
