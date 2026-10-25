"""Link analysis. By default URLs are scored lexically and NEVER fetched.
Optional download (GHOSTSCAN_ALLOW_DOWNLOAD=1) is guarded against SSRF."""
import ipaddress, math, re, socket
from collections import Counter
from urllib.parse import urlparse, unquote
from config import MAX_FILE_BYTES

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly"}
RISKY_TLDS = {"zip", "mov", "xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "country", "work", "support", "rest"}
BRANDS = ("paypal", "microsoft", "apple", "google", "amazon", "netflix", "bank", "office365", "outlook", "facebook", "dhl", "fedex")
LURES = ("login", "verify", "update", "secure", "account", "password", "invoice", "wallet", "confirm", "suspend")
DANGEROUS_EXT = (".exe", ".scr", ".js", ".vbs", ".ps1", ".bat", ".jar", ".msi", ".hta", ".apk", ".lnk", ".iso", ".dmg")


def _h(s):
    if not s: return 0
    n = len(s); return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def analyze_url(url: str) -> dict:
    f = []
    u = urlparse(url if "://" in url else "http://" + url)
    host = (u.hostname or "").lower()
    props = {"url": url, "scheme": u.scheme, "host": host, "path": u.path, "length": len(url)}
    if u.scheme not in ("http", "https"):
        f.append(("bad_scheme", 60, f"Scheme '{u.scheme}:' is not http/https."))
    if not host:
        return {"ok": False, "errors": ["The link has no valid host name."], "findings": f, "props": props}
    try:
        ipaddress.ip_address(host); f.append(("ip_host", 35, "Host is a raw IP address."))
    except ValueError:
        pass
    if "@" in u.netloc: f.append(("at_sign", 40, "Link contains '@' (hides the real destination)."))
    if host.startswith("xn--") or ".xn--" in host:
        f.append(("punycode", 40, "Punycode host - possible look-alike (homograph) domain."))
    labels = host.split(".")
    if len(labels) > 4: f.append(("many_subdomains", 20, f"{len(labels)} host labels - deep subdomain chain."))
    if labels[-1] in RISKY_TLDS: f.append(("risky_tld", 20, f"Top-level domain .{labels[-1]} is frequently abused."))
    if host in SHORTENERS: f.append(("shortener", 20, "URL shortener hides the destination."))
    if len(url) > 150: f.append(("long_url", 15, f"Very long link ({len(url)} characters)."))
    if _h(labels[0]) > 3.6 and len(labels[0]) > 12:
        f.append(("random_host", 25, "Host name looks randomly generated (DGA-like)."))
    for b in BRANDS:
        if b in host and not (host == b + ".com" or host.endswith("." + b + ".com")):
            f.append(("brand_spoof", 45, f"Host mentions '{b}' but is not the official domain.")); break
    lure = [l for l in LURES if l in unquote(u.path + "?" + (u.query or "")).lower()]
    if len(lure) >= 2: f.append(("phish_words", 20, f"Phishing keywords in path: {', '.join(lure)}"))
    if u.path.lower().endswith(DANGEROUS_EXT):
        f.append(("exe_download", 50, f"Link points directly to a {u.path.rsplit('.',1)[-1]} file."))
    if re.search(r"%[0-9a-f]{2}.*%[0-9a-f]{2}.*%[0-9a-f]{2}", url, re.I) and url.lower().count("%") > 8:
        f.append(("heavy_encoding", 15, "Heavy percent-encoding in the link."))
    if u.scheme == "http": f.append(("no_tls", 8, "Link does not use HTTPS."))
    return {"ok": True, "errors": [], "findings": f, "props": props}


def _resolve_public(host):
    """Resolve once and return a public IP, or raise ValueError. The same IP is then used to connect,
    so the name cannot be re-resolved to an internal address between the check and the request (DNS rebinding)."""
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        raise ValueError("The host name could not be resolved.")
    ips = [ipaddress.ip_address(sa[0]) for *_, sa in infos]
    if not ips or any(ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified for ip in ips):
        raise ValueError("Blocked: link resolves to a private or local address.")
    return str(ips[0])


def safe_download(url: str):
    """Fetch bytes with an SSRF guard, no redirects and a size cap. Returns (name, bytes). Raises ValueError."""
    import http.client, ssl
    u = urlparse(url)
    if u.scheme not in ("http", "https") or not u.hostname:
        raise ValueError("Only http/https links can be downloaded.")
    ip = _resolve_public(u.hostname)
    port = u.port or (443 if u.scheme == "https" else 80)

    class Pinned(http.client.HTTPSConnection if u.scheme == "https" else http.client.HTTPConnection):
        def connect(self):
            sock = socket.create_connection((ip, port), timeout=10)
            self.sock = self._context.wrap_socket(sock, server_hostname=u.hostname) if u.scheme == "https" else sock

    kw = {"context": ssl.create_default_context()} if u.scheme == "https" else {}
    conn = Pinned(u.hostname, port, timeout=10, **kw)
    try:
        conn.request("GET", (u.path or "/") + ("?" + u.query if u.query else ""),
                     headers={"Host": u.netloc.split("@")[-1], "User-Agent": "ghostscan/1.0", "Accept-Encoding": "identity"})
        r = conn.getresponse()
        if 300 <= r.status < 400:
            raise ValueError("The link redirects. Redirects are not followed.")
        if r.status != 200:
            raise ValueError(f"The server answered HTTP {r.status}.")
        data = r.read(MAX_FILE_BYTES + 1)
    except (OSError, http.client.HTTPException) as e:
        raise ValueError(f"The download failed ({type(e).__name__}).")
    finally:
        conn.close()
    if len(data) > MAX_FILE_BYTES:
        raise ValueError("Download exceeds the size limit.")
    return (u.path.rsplit("/", 1)[-1] or "download"), data
