"""Stage 2 - safe intake and validation (nothing is opened or parsed here)."""
import hashlib, os, re
from config import MAX_FILE_BYTES, ALLOWED_EXT

SIGNATURES = [
    (b"\xff\xd8\xff", "jpg"),
    (b"\x89PNG\r\n\x1a\n", "png"),
    (b"%PDF-", "pdf"),
    (b"PK\x03\x04", "zip"),                          # zip / OOXML (docx, xlsx, pptx)
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole"),    # legacy doc/xls
    (b"MZ", "exe"),
    (b"\x7fELF", "elf"),
    (b"{\\rtf", "rtf"),
    (b"#!", "script"),
    (b"\xca\xfe\xba\xbe", "macho/java"),
]
EXT_TO_TYPES = {
    "jpg": {"jpg"}, "jpeg": {"jpg"}, "png": {"png"}, "pdf": {"pdf"},
    "docx": {"zip"}, "docm": {"zip"}, "xlsx": {"zip"}, "xlsm": {"zip"},
    "pptx": {"zip"}, "zip": {"zip"}, "doc": {"ole"}, "xls": {"ole"},
    "rtf": {"rtf"}, "txt": {"text"},
    **{e: {"text", "script"} for e in ("php", "phtml", "php5", "js", "html", "htm", "asp", "aspx", "jsp", "py", "sh", "ps1", "vbs", "bat", "cmd")},
}
SCRIPT_EXT = {"php", "phtml", "php5", "js", "html", "htm", "asp", "aspx", "jsp", "py", "sh", "ps1", "vbs", "bat", "cmd"}
WEB_EXEC_EXT = {"php", "phtml", "php5", "asp", "aspx", "jsp", "exe", "js", "vbs", "ps1", "bat", "sh"}
DANGEROUS_EXT = {"exe", "dll", "scr", "js", "vbs", "ps1", "bat", "cmd", "com",
                 "jar", "lnk", "hta", "msi", "wsf", "sh", "apk"}


def detect_type(head: bytes) -> str:
    for magic, name in SIGNATURES:
        if head.startswith(magic):
            return name
    try:
        head.decode("utf-8")
        return "text"
    except UnicodeDecodeError:
        return "unknown"


def sanitize_name(name: str) -> str:
    name = os.path.basename(name or "upload")
    return re.sub(r"[^A-Za-z0-9._-]", "_", name)[:120] or "upload"


def validate(filename: str, data: bytes) -> dict:
    """Returns {ok, errors, findings, props}. Findings are (rule_id, weight, evidence)."""
    errors, findings = [], []
    safe = sanitize_name(filename)
    parts = safe.lower().split(".")
    ext = parts[-1] if len(parts) > 1 else ""
    true_type = detect_type(data[:16])

    props = {
        "filename": safe, "size_bytes": len(data), "extension": ext or "(none)",
        "detected_type": true_type,
        "sha256": hashlib.sha256(data).hexdigest(),
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
    }
    if len(data) == 0:
        errors.append("The file is empty.")
    if len(data) > MAX_FILE_BYTES:
        errors.append(f"The file is larger than the {MAX_FILE_BYTES // 1024 // 1024} MB limit.")
    if ext not in ALLOWED_EXT:
        errors.append(f"The extension '.{ext or 'none'}' is not supported.")
    if errors:
        return {"ok": False, "errors": errors, "findings": findings, "props": props}

    if true_type in ("exe", "elf", "macho/java"):
        findings.append(("exe_disguised", 60, f"Content is an executable ({true_type}) but the name says .{ext}."))
    elif true_type == "script" and ext not in SCRIPT_EXT and ext != "txt":
        findings.append(("script_disguised", 40, "File starts with a script shebang (#!)."))
    elif true_type not in EXT_TO_TYPES.get(ext, set()) and true_type != "unknown":
        findings.append(("ext_mismatch", 30, f"Extension .{ext} does not match the real file type ({true_type})."))

    if len(parts) > 2 and parts[-1] in DANGEROUS_EXT:
        findings.append(("double_ext", 45, f"Double extension ending in .{parts[-1]}."))
    elif len(parts) > 2 and any(p in WEB_EXEC_EXT for p in parts[1:-1]) and parts[-1] not in SCRIPT_EXT:
        findings.append(("double_ext", 45, f"Executable extension hidden inside the name ({'.'.join(parts[1:])})."))
    if re.search(r"[\u202e\u200b]", filename or ""):
        findings.append(("rtlo", 50, "Filename contains hidden Unicode direction characters (RTLO trick)."))
    return {"ok": True, "errors": errors, "findings": findings, "props": props}
