"""Stage 4 - detection and scoring.

Each finding carries a weight w in [0,100] meaning "how likely is a file with only this
signal to be malicious". Signals are combined with a noisy-OR:

    risk = 1 - prod(1 - w_i/100)

so independent weak signals accumulate, one strong signal dominates, and the score
can never exceed 100. Correlated rules are de-duplicated by rule_id first.
An optional ML model (see ml_hook) can add one more probabilistic signal.
"""
from math import prod

CATEGORIES = {
    "known_hash": "Known threat", "eicar": "Known threat",
    "exe_disguised": "Disguised file", "ext_mismatch": "Disguised file", "double_ext": "Disguised file",
    "rtlo": "Disguised file", "script_disguised": "Disguised file",
    "trailing_data": "Hidden data", "png_text_payload": "Hidden data", "jpg_comment_code": "Hidden data",
    "vba_macro": "Active content", "autoexec": "Active content", "dde": "Active content",
    "activex": "Active content", "ole_embedded": "Active content", "vba_suspicious_api": "Active content",
    "ghostscan_lsb_message": "Hidden data", "lsb_stats_strong": "Hidden data", "lsb_chi_square": "Hidden data",
    "lsb_rs": "Hidden data", "hidden_unicode": "Hidden data", "zw_message": "Hidden data", "bidi_control": "Hidden data",
    "c2pa_marker": "Provenance", "rights_metadata": "Provenance", "ghostscan_watermark": "Provenance",
    "zip_bomb": "Resource abuse", "decompression_bomb": "Resource abuse",
}
NEXT_STEPS = {
    "Malicious": ["Do not open this file. Delete it, or keep it only in an isolated analysis machine.",
                  "If you already opened it, disconnect from the network and run a full antivirus scan.",
                  "Change passwords for accounts used on that device after cleaning it.",
                  "Report the sender or the link to your IT/security team."],
    "Suspicious": ["Do not open it on your main device. Use an isolated virtual machine if you must inspect it.",
                   "Confirm with the sender through another channel that they really sent it.",
                   "Upload the SHA-256 to a multi-engine service such as VirusTotal for a second opinion.",
                   "Keep Office macros and PDF JavaScript disabled."],
    "Low risk": ["No strong indicators were found, but static checks cannot prove a file is safe.",
                 "Open it only from trusted sources and keep your software updated."],
    "Clean": ["No suspicious indicators found. Keep your antivirus and software updated."],
}


def ml_hook(features: dict):
    """Optional: plug in a scikit-learn model here and return a probability in [0,1] or None."""
    return None


def category_for(rid):
    if rid in CATEGORIES:
        return CATEGORIES[rid]
    if rid.startswith(("php_", "js_", "sh_", "ps_", "vbs_", "bat_", "py_")) or rid == "shell_ui_strings":
        return "Script / web shell"
    if rid.startswith("obf_"):
        return "Obfuscation"
    if rid.startswith(("clamav", "vt_")):
        return "Known threat"
    if rid.startswith("member_") or rid == "nested_archive":
        return "Archive contents"
    return "Structure & content"


def score(findings: list, entropy: dict | None = None, ftype: str = "") -> dict:
    best = {}
    for rid, w, ev in findings:
        if rid not in best or w > best[rid][0]:
            best[rid] = (w, ev)
    items = [{"rule": r, "weight": w, "evidence": e, "category": category_for(r)}
             for r, (w, e) in best.items()]
    items.sort(key=lambda x: -x["weight"])

    risk = 1 - prod(1 - i["weight"] / 100 for i in items) if items else 0.0
    # contextual boost: active content AND disguise/remote-fetch together is the classic dropper chain
    cats = {i["category"] for i in items}
    if {"Active content", "Disguised file"} <= cats or ("Active content" in cats and "external_rel" in best):
        risk = min(1.0, risk + 0.08)
    # packed high-entropy blob inside a document
    if entropy and ftype in ("pdf", "zip", "ole") and entropy["blocks"] and max(entropy["blocks"]) > 7.9 and ftype == "ole":
        risk = min(1.0, risk + 0.05)
    ml = ml_hook({"findings": best, "entropy": entropy})
    if ml is not None:
        risk = 1 - (1 - risk) * (1 - ml * 0.5)

    value = round(risk * 100)
    if any(i["rule"] in ("known_hash", "eicar") for i in items):
        value = 100
    verdict = ("Malicious" if value >= 70 else "Suspicious" if value >= 35
               else "Low risk" if value >= 10 else "Clean")
    return {"score": value, "verdict": verdict, "evidence": items, "next_steps": NEXT_STEPS[verdict]}
