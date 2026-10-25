"""Hide / reveal messages and watermark images. Also statistical hidden-data indicators for the scanner.

Methods
  * LSB message hiding in PNG/JPG pixels (output is lossless PNG). Optional passphrase:
    keyed pixel order + PBKDF2/HMAC keystream encryption with an integrity tag.
  * Zero-width Unicode hiding in plain text.
  * Visible text watermark (corner or tiled).
  * Invisible DCT watermark: 8x8 block DCT of luminance, bit = sign of (c[3,2] - c[2,3]),
    repeated over every block with majority vote, CRC16-checked frame. Survives mild JPEG compression.
Detection
  * Chi-square pairs-of-values test and RS analysis for LSB embedding (indicators, never proof).
  * GhostScan LSB / DCT signatures (decisive for messages and watermarks made by this tool).
  * Provenance: C2PA marker, EXIF/XMP/PNG copyright fields (presence only, signatures are NOT verified).
Other watermark schemes need their own decoders; this module does not claim universal detection.
"""
import base64, binascii, hashlib, hmac, io, math, os, re, struct, zlib
import numpy as np
from PIL import Image, ImageDraw, ImageFont

MAX_PIXELS = int(os.getenv("GHOSTSCAN_MAX_PIXELS", 16_000_000))     # decoded image size cap (a small file can hold a huge image)
Image.MAX_IMAGE_PIXELS = MAX_PIXELS * 2
MAX_ANALYSIS_PIXELS = MAX_PIXELS
MAGIC = b"CVS1"
WM_MAGIC = b"\xc5\x57"
WM_MAX_BYTES = 16
MAX_MESSAGE_BYTES = 64 * 1024


class StegoError(ValueError):
    """Message safe to show to the user."""


# ------------------------------------------------------------------ helpers
def load_image(data: bytes) -> Image.Image:
    try:
        im = Image.open(io.BytesIO(data))
        too_big = im.width * im.height > MAX_PIXELS          # header only, nothing decoded yet
        if not too_big:
            im.load()
    except Exception:
        raise StegoError("This image could not be read. Use a valid PNG or JPG.")
    if too_big:
        raise StegoError(f"This image is too large ({im.width}x{im.height}). The limit is about {MAX_PIXELS // 1_000_000} megapixels.")
    has_alpha = im.mode in ("RGBA", "LA", "PA") or "transparency" in im.info
    return im.convert("RGBA" if has_alpha else "RGB")


def to_png(im: Image.Image) -> bytes:
    b = io.BytesIO()
    im.save(b, "PNG", optimize=False)
    return b.getvalue()


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def _key_params(key: str, n: int):
    """Keyed affine order pos_i = (a*i + b) mod n. Cheap, covers every slot exactly once."""
    if not key:
        return 1, 0
    h = hashlib.sha256(key.encode()).digest()
    a = int.from_bytes(h[:8], "big") % n or 1
    while math.gcd(a, n) != 1:
        a += 1
    return a, int.from_bytes(h[8:16], "big") % n


def _positions(n: int, count: int, key: str):
    a, b = _key_params(key, n)
    return (a * np.arange(count, dtype=np.int64) + b) % n


# ------------------------------------------------------------------ message sealing
def _keys(pw: str, salt: bytes):
    k = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, 200_000, 64)
    return k[:32], k[32:]


def _stream(key: bytes, n: int) -> bytes:
    out, c = b"", 0
    while len(out) < n:
        out += hmac.new(key, struct.pack(">Q", c), "sha256").digest()
        c += 1
    return out[:n]


def seal(message: str, pw: str) -> bytes:
    raw = message.encode("utf-8")
    if len(raw) > MAX_MESSAGE_BYTES:
        raise StegoError("The message is longer than 64 KB.")
    if not pw:
        return b"\x00" + raw
    import os
    salt = os.urandom(16)
    ek, mk = _keys(pw, salt)
    ct = bytes(a ^ b for a, b in zip(raw, _stream(ek, len(raw))))
    return b"\x01" + salt + ct + hmac.new(mk, salt + ct, "sha256").digest()[:16]


def unseal(body: bytes, pw: str) -> str:
    if not body:
        raise StegoError("Empty message.")
    if body[0] == 0:
        return body[1:].decode("utf-8", "replace")
    if body[0] != 1 or len(body) < 33:
        raise StegoError("Unknown message format.")
    if not pw:
        raise StegoError("This message is protected. Enter the passphrase.")
    salt, ct, tag = body[1:17], body[17:-16], body[-16:]
    ek, mk = _keys(pw, salt)
    if not hmac.compare_digest(tag, hmac.new(mk, salt + ct, "sha256").digest()[:16]):
        raise StegoError("Wrong passphrase, or the data was changed.")
    return bytes(a ^ b for a, b in zip(ct, _stream(ek, len(ct)))).decode("utf-8", "replace")


# ------------------------------------------------------------------ LSB hide / reveal
def lsb_capacity(im: Image.Image, protected: bool = False) -> int:
    samples = im.width * im.height * 3
    return max(0, samples // 8 - 13 - (1 + 32 if protected else 1))


def lsb_hide(data: bytes, message: str, pw: str = "") -> dict:
    im = load_image(data)
    body = seal(message, pw)
    frame = MAGIC + struct.pack(">I", len(body)) + body + struct.pack(">I", zlib.crc32(body) & 0xffffffff)
    arr = np.array(im)
    flat = arr[..., :3].reshape(-1)           # alpha channel is left untouched
    bits = np.unpackbits(np.frombuffer(frame, dtype=np.uint8))
    if len(bits) > len(flat):
        raise StegoError(f"The message is too large for this image. Capacity is about {lsb_capacity(im, bool(pw))} bytes.")
    pos = _positions(len(flat), len(bits), pw)
    flat[pos] = (flat[pos] & 0xFE) | bits
    arr[..., :3] = flat.reshape(arr[..., :3].shape)
    out = to_png(Image.fromarray(arr))
    return {"png": out, "used_bytes": len(frame), "capacity_bytes": lsb_capacity(im, bool(pw)),
            "pixels_changed_pct": round(len(bits) / len(flat) * 100, 2)}


def lsb_reveal(data: bytes, pw: str = ""):
    """Returns message string, or None if no GhostScan LSB frame is present. Raises StegoError for a wrong passphrase."""
    im = load_image(data)
    flat = np.array(im)[..., :3].reshape(-1)
    n = len(flat)
    if n < 100:
        return None
    head = np.packbits(flat[_positions(n, 72, pw)] & 1).tobytes()
    if head[:4] != MAGIC:
        return None
    length = struct.unpack(">I", head[4:8])[0]
    total_bits = (9 + length + 4) * 8
    if length > MAX_MESSAGE_BYTES + 64 or total_bits > n:
        return None
    raw = np.packbits(flat[_positions(n, total_bits, pw)] & 1).tobytes()
    body, crc = raw[8:8 + length], struct.unpack(">I", raw[8 + length:12 + length])[0]
    if zlib.crc32(body) & 0xffffffff != crc:
        return None
    return unseal(body, pw)


# ------------------------------------------------------------------ zero-width text
ZW0, ZW1, ZWD = "\u200b", "\u200c", "\u2060"
ZW_ALL = set("\u200b\u200c\u200d\u2060\ufeff\u180e")
BIDI = set("\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069")


def text_hide(cover: str, message: str, pw: str = "") -> str:
    body = seal(message, pw)
    raw = body + struct.pack(">I", zlib.crc32(body) & 0xffffffff)
    bits = "".join(f"{b:08b}" for b in raw)
    payload = ZWD + "".join(ZW1 if c == "1" else ZW0 for c in bits) + ZWD
    return cover[:1] + payload + cover[1:] if cover else payload


def text_reveal(text: str, pw: str = ""):
    m = re.search(ZWD + "([" + ZW0 + ZW1 + "]{40,})" + ZWD, text)
    if not m:
        return None
    bits = "".join("1" if c == ZW1 else "0" for c in m.group(1))
    raw = bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits) - len(bits) % 8, 8))
    body, crc = raw[:-4], raw[-4:]
    if len(raw) < 5 or zlib.crc32(body) & 0xffffffff != struct.unpack(">I", crc)[0]:
        return None
    return unseal(body, pw)


def unicode_findings(text: str):
    """Hidden / direction-control characters in documents (also Trojan Source)."""
    if text.startswith("\ufeff"):
        text = text[1:]
    f = []
    zw = sum(1 for c in text if c in ZW_ALL)
    bd = sum(1 for c in text if c in BIDI)
    if zw >= 8:
        f.append(("hidden_unicode", 25 if zw < 64 else 35, f"{zw} zero-width characters in the text (can carry a hidden message)."))
    if bd:
        f.append(("bidi_control", 35, f"{bd} bidirectional control characters (can make text read differently than it is stored)."))
    try:
        msg = text_reveal(text)
    except StegoError:
        msg = "(protected message)"
    if msg:
        f.append(("zw_message", 30, f"Hidden text decoded from zero-width characters: \"{msg[:60]}\""))
    return f


# ------------------------------------------------------------------ watermarks
def _font(size: int):
    for name in ("DejaVuSans-Bold.ttf", "DejaVuSans.ttf", "Arial Bold.ttf", "Arial.ttf",
                 "/System/Library/Fonts/Helvetica.ttc", "/Library/Fonts/Arial.ttf"):
        try:
            return ImageFont.truetype(name, size)
        except OSError:
            continue
    return ImageFont.load_default(size=size)


def visible_watermark(im: Image.Image, text: str, position: str = "corner", opacity: float = 0.45) -> Image.Image:
    base = im.convert("RGBA")
    alpha = int(255 * min(max(opacity, 0.1), 1.0))
    size = max(14, base.width // (22 if position == "tiled" else 16))
    font = _font(size)
    probe = ImageDraw.Draw(Image.new("RGBA", (1, 1)))
    l, t, r, b = probe.textbbox((0, 0), text, font=font)
    tw, th, pad = r - l, b - t, size // 2
    tile = Image.new("RGBA", (tw + pad * 2, th + pad * 2), (0, 0, 0, 0))
    d = ImageDraw.Draw(tile)
    d.text((pad - l + 2, pad - t + 2), text, font=font, fill=(0, 0, 0, alpha // 2))
    d.text((pad - l, pad - t), text, font=font, fill=(255, 255, 255, alpha))
    layer = Image.new("RGBA", base.size, (0, 0, 0, 0))
    if position == "tiled":
        tile = tile.rotate(30, expand=True, resample=Image.BICUBIC)
        for y in range(0, base.height, int(tile.height * 1.6)):
            for x in range(0, base.width, int(tile.width * 1.4)):
                layer.alpha_composite(tile, (x, y))
    else:
        m = max(8, base.width // 40)
        layer.alpha_composite(tile, (max(base.width - tile.width - m, 0), max(base.height - tile.height - m, 0)))
    return Image.alpha_composite(base, layer)


_C = np.cos((2 * np.arange(8)[None, :] + 1) * np.arange(8)[:, None] * np.pi / 16)
_C[0] *= 1 / np.sqrt(2)
D8 = _C * np.sqrt(2 / 8)
P1, P2 = (3, 2), (2, 3)


def _wm_frame(text: str) -> np.ndarray:
    raw = text.encode("utf-8")
    if not raw or len(raw) > WM_MAX_BYTES:
        raise StegoError(f"The invisible watermark text must be 1 to {WM_MAX_BYTES} bytes (about {WM_MAX_BYTES} letters).")
    body = bytes([len(raw)]) + raw.ljust(WM_MAX_BYTES, b"\x00")
    frame = WM_MAGIC + body + struct.pack(">H", binascii.crc_hqx(body, 0))
    return np.unpackbits(np.frombuffer(frame, dtype=np.uint8))


def _blocks(y: np.ndarray):
    h, w = (y.shape[0] // 8) * 8, (y.shape[1] // 8) * 8
    return y[:h, :w].reshape(h // 8, 8, w // 8, 8).transpose(0, 2, 1, 3), h, w


def _bit_index(nblocks: int, nbits: int, key: str):
    idx = np.empty(nblocks, dtype=np.int64)
    idx[_positions(nblocks, nblocks, key)] = np.arange(nblocks) % nbits
    return idx


def dct_watermark(im: Image.Image, text: str, key: str = "", strength: float = 16.0) -> Image.Image:
    bits = _wm_frame(text)
    rgb = im.convert("RGB")
    y, cb, cr = rgb.convert("YCbCr").split()
    ya = np.array(y, dtype=np.float64)
    blocks, h, w = _blocks(ya)
    nb = blocks.shape[0] * blocks.shape[1]
    if nb < len(bits) * 3:
        raise StegoError("The image is too small for an invisible watermark. Use at least about 200 x 200 pixels.")
    coef = D8 @ blocks @ D8.T
    want = bits[_bit_index(nb, len(bits), key)].reshape(blocks.shape[:2])
    diff = coef[..., P1[0], P1[1]] - coef[..., P2[0], P2[1]]
    need = np.where(want == 1, np.maximum(strength - diff, 0), -np.maximum(diff + strength, 0))
    coef[..., P1[0], P1[1]] += need / 2
    coef[..., P2[0], P2[1]] -= need / 2
    out = D8.T @ coef @ D8
    ya[:h, :w] = out.transpose(0, 2, 1, 3).reshape(h, w)
    y2 = Image.fromarray(np.clip(np.rint(ya), 0, 255).astype(np.uint8), "L")
    res = Image.merge("YCbCr", (y2, cb, cr)).convert("RGB")
    if im.mode == "RGBA":
        res.putalpha(im.getchannel("A"))
    return res


def dct_detect(im: Image.Image, key: str = "") -> dict:
    ya = np.array(im.convert("RGB").convert("YCbCr").split()[0], dtype=np.float64)
    blocks, _, _ = _blocks(ya)
    nb = blocks.shape[0] * blocks.shape[1]
    nbits = (2 + 1 + WM_MAX_BYTES + 2) * 8
    if nb < nbits * 3:
        return {"found": False, "reason": "too_small"}
    coef = D8 @ blocks @ D8.T
    diff = (coef[..., P1[0], P1[1]] - coef[..., P2[0], P2[1]]).reshape(-1)
    bi = _bit_index(nb, nbits, key)
    sums = np.bincount(bi, weights=diff, minlength=nbits)
    bits = (sums > 0).astype(np.uint8)
    agree = float(np.mean((diff > 0) == (bits[bi] == 1)))
    raw = np.packbits(bits).tobytes()
    body, crc = raw[2:-2], struct.unpack(">H", raw[-2:])[0]
    if raw[:2] == WM_MAGIC and binascii.crc_hqx(body, 0) == crc and 1 <= body[0] <= WM_MAX_BYTES:
        return {"found": True, "text": body[1:1 + body[0]].decode("utf-8", "replace"), "agreement": round(agree, 3),
                "confidence": "High" if agree > 0.8 else "Medium"}
    return {"found": False, "agreement": round(agree, 3), "reason": "no_signature"}


def provenance(data: bytes) -> dict:
    """Presence of provenance / rights markers. Signatures are NOT verified here."""
    info = {}
    if b"c2pa" in data or b"jumb" in data or b"caBX" in data:
        info["c2pa_manifest"] = "present (Content Credentials marker found; signature not verified by GhostScan)"
    try:
        im = Image.open(io.BytesIO(data))
        ex = im.getexif()
        for tag, label in ((0x8298, "copyright"), (0x013B, "artist"), (0x0131, "software"), (0x010E, "description")):
            if ex.get(tag):
                info[label] = str(ex.get(tag))[:100]
        for k, v in list(im.info.items())[:20]:
            if isinstance(k, str) and k.lower() in ("copyright", "author", "software", "description", "comment", "source") and isinstance(v, (str, bytes)):
                info["png_" + k.lower()] = (v if isinstance(v, str) else v.decode("latin1"))[:100]
    except Exception:
        pass
    m = re.search(rb"<dc:rights>.*?<rdf:li[^>]*>([^<]{1,100})<", data, re.S)
    if m:
        info["xmp_rights"] = m.group(1).decode("utf-8", "replace")
    return info


# ------------------------------------------------------------------ statistical analysis
def _chi_p(vals: np.ndarray):
    h = np.bincount(vals, minlength=256).astype(np.float64)
    ev, od = h[0::2], h[1::2]
    exp = (ev + od) / 2
    m = exp >= 5
    df = int(m.sum()) - 1
    if df < 10:
        return None
    chi = float((((ev[m] - exp[m]) ** 2) / exp[m]).sum())
    z = ((chi / df) ** (1 / 3) - (1 - 2 / (9 * df))) / math.sqrt(2 / (9 * df))
    return 0.5 * math.erfc(z / math.sqrt(2))        # high value => pairs are suspiciously equalised


def chi_square_lsb(flat: np.ndarray):
    best = 0.0
    for frac in (0.05, 0.1, 0.25, 0.5, 1.0):
        part = flat[: int(len(flat) * frac)]
        if len(part) >= 6000:
            p = _chi_p(part)
            if p is not None:
                best = max(best, p)
    return best


def _rs_counts(g: np.ndarray):
    base = np.abs(np.diff(g, axis=1)).sum(1)
    fm, fn = g.copy(), g.copy()
    fm[:, 1:3] = g[:, 1:3] ^ 1
    fn[:, 1:3] = ((g[:, 1:3] + 1) ^ 1) - 1
    a, b = np.abs(np.diff(fm, axis=1)).sum(1), np.abs(np.diff(fn, axis=1)).sum(1)
    n = len(g)
    return ((a > base).sum() - (a < base).sum()) / n, ((b > base).sum() - (b < base).sum()) / n


def rs_estimate(chan: np.ndarray):
    """Fridrich RS analysis: estimated fraction of LSBs used (0..1), or None."""
    x = chan.astype(np.int16).reshape(-1)
    n = min(len(x) // 4 * 4, 4_000_000)
    if n < 4000:
        return None
    g = x[:n].reshape(-1, 4)
    d0, dn0 = _rs_counts(g)
    d1, dn1 = _rs_counts(g ^ 1)
    a, b, c = 2 * (d1 + d0), dn0 - dn1 - d1 - 3 * d0, d0 - dn0
    if abs(a) < 1e-9:
        return None
    disc = b * b - 4 * a * c
    if disc < 0:
        return None
    roots = [(-b + s * math.sqrt(disc)) / (2 * a) for s in (1, -1)]
    z = min(roots, key=abs)
    if abs(z - 0.5) < 1e-9:
        return None
    return float(min(max(z / (z - 0.5), 0), 1))


def analyze_image(data: bytes):
    """Used by the scanner. Returns (findings, metadata)."""
    f, meta = [], {}
    prov = provenance(data)
    if prov:
        meta["provenance"] = prov
        if "c2pa_manifest" in prov:
            f.append(("c2pa_marker", 0, "Content Credentials (C2PA) marker present. Signature is not verified here."))
        if any(k in prov for k in ("copyright", "xmp_rights", "png_copyright")):
            f.append(("rights_metadata", 0, "Copyright or rights metadata is embedded in the image."))
    try:
        im = load_image(data)
    except StegoError:
        meta["stego_analysis"] = "skipped (image unreadable or too large)"
        return f, meta
    if im.width * im.height > MAX_ANALYSIS_PIXELS:
        meta["stego_analysis"] = "skipped (image too large)"
        return f, meta
    arr = np.array(im)[..., :3]
    try:
        if lsb_reveal(data) is not None:
            f.append(("ghostscan_lsb_message", 40, "A hidden message created with GhostScan's LSB method was found. Use Reveal to read it."))
    except StegoError:
        f.append(("ghostscan_lsb_message", 40, "A password-protected hidden message created with GhostScan was found."))
    wm = dct_detect(im)
    if wm.get("found"):
        f.append(("ghostscan_watermark", 0, f"Invisible GhostScan watermark detected: \"{wm['text']}\" ({wm['confidence']} confidence)."))
    p = chi_square_lsb(arr.reshape(-1))
    rs = [e for e in (rs_estimate(arr[..., c]) for c in range(3)) if e is not None]
    rs_med = float(np.median(rs)) if rs else None
    meta["lsb_chi_square_p"] = round(p, 4)
    meta["lsb_rs_estimate"] = None if rs_med is None else round(rs_med, 3)
    if p > 0.95 and rs_med is not None and rs_med > 0.15:
        f.append(("lsb_stats_strong", 45, f"Chi-square (p={p:.2f}) and RS analysis (~{rs_med:.0%} of LSBs) both point to LSB embedding."))
    elif p > 0.99:
        f.append(("lsb_chi_square", 20, f"Chi-square test: pixel value pairs are unusually equal (p={p:.2f}). Possible LSB embedding."))
    elif rs_med is not None and rs_med > 0.3:
        f.append(("lsb_rs", 20, f"RS analysis suggests about {rs_med:.0%} of LSBs may be used. Possible LSB embedding."))
    return f, meta


def confidence_label(weight: int) -> str:
    return "High" if weight >= 40 else "Medium" if weight >= 20 else "Low"
