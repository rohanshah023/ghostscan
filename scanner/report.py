"""Builds the 'analysis checks' table and a heuristic detection label from the scored evidence."""

TEXT_T = {"text", "script", "unknown", "rtf"}
GROUPS = [  # (name, matcher, applies_to ftypes or None)
    ("Known threat database", lambda r: r in {"known_hash", "eicar", "clamav_detection", "vt_detections"}, None),
    ("File type and disguise", lambda r: r in {"exe_disguised", "ext_mismatch", "double_ext", "rtlo", "script_disguised", "member_disguised"}, None),
    ("Script and web shell analysis", lambda r: r.startswith(("php_", "js_", "sh_", "ps_", "vbs_", "bat_", "py_")) or r in {"shell_ui_strings", "php_tag_embedded"}, TEXT_T | {"png", "jpg", "pdf", "zip", "ole"}),
    ("Obfuscation analysis", lambda r: r.startswith("obf_"), TEXT_T),
    ("Embedded programs and commands", lambda r: r in {"pe_in_data", "b64_pe", "cmd_exec", "powershell", "shell_dl", "php_webshell", "script_tag", "member_executable"} or r.startswith("member_"), None),
    ("Macros and active content", lambda r: r in {"vba_macro", "macro_ext", "vba_suspicious_api", "autoexec", "dde", "activex", "ole_embedded", "remote_template", "field_remote", "external_rel"} or r.startswith("pdf/"), {"pdf", "zip", "ole"}),
    ("Archive structure and bombs", lambda r: r in {"zip_bomb", "zip_traversal", "zip_encrypted", "zip_executables", "bad_zip", "nested_archive"}, {"zip"}),
    ("Hidden data and steganography", lambda r: r in {"trailing_data", "png_text_payload", "jpg_comment_code", "jpg_big_segment", "lsb_stats_strong", "lsb_chi_square", "lsb_rs", "hidden_unicode", "zw_message", "bidi_control", "ghostscan_lsb_message", "decompression_bomb"}, TEXT_T | {"png", "jpg", "zip", "pdf"}),
    ("Network indicators", lambda r: r in {"ip_url"}, None),
    ("Entropy and packing", lambda r: r in {"high_entropy_text"}, None),
    ("Metadata and provenance", lambda r: r in {"c2pa_marker", "rights_metadata", "ghostscan_watermark"}, {"png", "jpg", "pdf", "zip"}),
    ("File integrity", lambda r: r in {"parser_error", "worker_crash", "worker_timeout", "png_bad_crc", "png_truncated", "png_no_iend", "jpg_no_eoi", "pdf_no_eof", "png_no_iend"}, None),
]
LABELS = [  # first match wins
    (lambda r: r in {"eicar"}, "EICAR-Test-File"),
    (lambda r: r in {"php_eval_request", "php_decode_eval", "php_dynamic_call", "php_known_shell", "shell_ui_strings", "php_preg_e", "php_include_request"}, "Heuristic.Backdoor.PHP.WebShell"),
    (lambda r: r in {"sh_reverse_shell", "py_reverse_shell"}, "Heuristic.Backdoor.ReverseShell"),
    (lambda r: r in {"vba_macro", "vba_suspicious_api", "autoexec", "dde", "remote_template"}, "Heuristic.Office.MaliciousMacro"),
    (lambda r: r.startswith("pdf/") or r == "pdf_stream_js", "Heuristic.PDF.ActiveContent"),
    (lambda r: r in {"exe_disguised", "member_disguised", "double_ext", "pe_in_data", "b64_pe"}, "Heuristic.Disguised.Executable"),
    (lambda r: r.startswith(("ps_", "vbs_", "bat_", "js_")), "Heuristic.Script.Downloader"),
    (lambda r: r in {"zip_bomb"}, "Heuristic.Archive.Bomb"),
    (lambda r: r in {"lsb_stats_strong", "ghostscan_lsb_message", "trailing_data", "zw_message"}, "Heuristic.HiddenData"),
]


def build_checks(ftype, evidence, engines):
    by_rule = {e["rule"]: e for e in evidence}
    out = []
    for name, match, applies in GROUPS:
        if applies is not None and ftype not in applies:
            out.append({"name": name, "status": "Not applicable", "detail": "This check does not apply to this file type."})
            continue
        hit = [e for e in evidence if match(e["rule"])]
        if not hit:
            out.append({"name": name, "status": "Clean", "detail": "No indicators found."})
            continue
        top = max(hit, key=lambda e: e["weight"])
        info_only = name == "Metadata and provenance"
        status = "Found" if info_only else "Detected" if top["weight"] >= 40 else "Suspicious" if top["weight"] >= 15 else "Low"
        out.append({"name": name, "status": status, "detail": top["evidence"] + (f" (+{len(hit) - 1} more)" if len(hit) > 1 else "")})
    cl = engines.get("clamav", {})
    out.append({"name": "ClamAV antivirus engine",
                "status": {"detected": "Detected", "clean": "Clean", "not_installed": "Not available", "error": "Error"}.get(cl.get("status"), "Not available"),
                "detail": cl.get("detail", "")})
    vt = engines.get("virustotal", {})
    if vt.get("status") == "found":
        m = vt["stats"].get("malicious", 0)
        out.append({"name": "VirusTotal (hash lookup)", "status": "Detected" if m else "Clean", "detail": f"{m} of {sum(vt['stats'].values())} engines flagged this exact file."})
    else:
        out.append({"name": "VirusTotal (hash lookup)", "status": "Not available", "detail": vt.get("detail", "Not configured.")})
    return out


def detection_label(evidence):
    rules = {e["rule"] for e in evidence if e["weight"] >= 30}
    for match, label in LABELS:
        if any(match(r) for r in rules):
            return label
    return None
