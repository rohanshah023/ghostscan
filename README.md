# GhostScan - hidden malware finder (static analysis)

Scans files (JPG, PNG, PDF, DOCX/XLSX/PPTX, legacy DOC/XLS, ZIP, RTF, TXT) and links.
Files are analysed as data. Nothing is opened, rendered or executed.

## Run (development)
    pip install -r requirements.txt
    python app.py            # http://127.0.0.1:5000  (single-user development server)
    python -m unittest discover tests

## Deploy (production, many users)
Do not use `python app.py` live. Use gunicorn behind nginx (or the Docker image):

    gunicorn -c gunicorn.conf.py app:app          # reads settings from the environment, see .env.example
    docker compose up -d --build                  # web app;  add  --profile av  for the ClamAV engine

Files that help: `gunicorn.conf.py`, `Dockerfile`, `docker-compose.yml`, `deploy/nginx.conf` (TLS, gzip,
edge rate limit), `Procfile`, `.env.example`.

How it behaves under load
- Every file is analysed in its own child process with CPU, memory and file limits and a timeout.
  At most `GHOSTSCAN_MAX_CONCURRENT` analyses run at once per server process. A request that cannot get a slot
  within `GHOSTSCAN_QUEUE_WAIT_S` receives HTTP 503 "busy, try again" instead of making everyone slower.
- Capacity: concurrent analyses = `WEB_CONCURRENCY` x `GHOSTSCAN_MAX_CONCURRENT`; each uses about 100-300 MB.
  Typical documents scan in 0.2-0.5 s of CPU; worst-case 10 MB files take 1-2.5 s. Add CPU cores to scale.
- The same file (same SHA-256) is not analysed twice within `GHOSTSCAN_CACHE_TTL_S`.
- ClamAV and VirusTotal run in parallel with the analysis. Use the ClamAV daemon (`GHOSTSCAN_CLAMD_HOST` or
  `GHOSTSCAN_CLAMD_SOCKET`): the `clamscan` fallback reloads the whole signature database for every file and is slow.
  VirusTotal answers are cached and a rate limit pauses lookups for a minute.
- Abuse protection: per-IP rate limit in the app (`GHOSTSCAN_RATE_LIMIT`, per process) plus `limit_req` in nginx,
  request size limits, a decoded-image size limit (`GHOSTSCAN_MAX_PIXELS`), and a limit on simultaneous image tools.
- Set `GHOSTSCAN_TRUST_PROXY=1` only when a reverse proxy really is in front, so client IPs cannot be spoofed.
- Health check: `GET /healthz`. Security headers (CSP, HSTS over HTTPS, frame and referrer policy) are set by the app.
- Run behind HTTPS. Rate-limit counters are per process; for a hard global limit rely on nginx.
- Windows has no `resource` limits for the worker: deploy on Linux (Docker) for the full sandbox.

## Pipeline
1. Input - file upload or link (`app.py`)
2. Safe intake - size cap, extension allow-list, magic-byte signature, extension/type mismatch,
   double extension, RTLO trick, hashes (`scanner/validation.py`)
3. Static analysis - runs in a child process with CPU, memory and file-write limits and a timeout
   (`scanner/pipeline.py`, `scanner/worker.py`, `scanner/static_analysis.py`)
   - PNG: chunk walk, CRC check, text-chunk payloads, data after IEND, decompression bomb
   - JPEG: segment walk, EXIF/comment code, data after EOI
   - PDF: JavaScript, OpenAction, Launch, EmbeddedFile, name obfuscation, JS inside inflated streams
   - OOXML/ZIP: VBA macros, remote templates, external relationships, DDE, ActiveX, zip bomb, zip-slip
   - Legacy OLE: macro streams, auto-exec names, Shell/CreateObject APIs
   - All files: Shannon entropy (overall and per block), YARA-style regex rules, SHA-256 known-bad list
4. Scoring - noisy-OR: `risk = 1 - prod(1 - w_i/100)` with a boost for dropper-style combinations
   and a hook for an optional ML classifier (`scanner/scoring.py`)
5. Dashboard - risk score, evidence, properties, metadata, entropy chart, next steps

## Hide and reveal (new)
- **Hide a message:** LSB embedding in PNG/JPG pixels (saved as PNG), or zero-width Unicode characters in `.txt`.
  An optional passphrase scrambles the pixel order and encrypts the message (PBKDF2 + HMAC keystream with an integrity tag).
  This is a convenience for casual privacy, not a replacement for a vetted encryption tool.
- **Reveal a message:** reads GhostScan messages and reports statistical indicators of other LSB hiding
  (chi-square pairs-of-values test and RS analysis), each with a confidence label.
- **Add a watermark:** visible text (corner or tiled) and/or an invisible DCT watermark
  (luminance 8x8 blocks, bit = sign of c[3,2] - c[2,3], repeated over all blocks, majority vote, CRC16).
  It survives JPEG at about quality 70 and above, but not heavy resizing or cropping.
- **Detect a watermark:** decodes GhostScan invisible watermarks and lists provenance markers
  (C2PA presence, EXIF/XMP/PNG copyright fields). C2PA signatures are not verified.
- The main scan now also runs LSB statistics and hidden-Unicode checks (zero-width and bidirectional characters)
  on images, text and Office documents.
- Other vendors' invisible watermarks need their own decoders; this tool does not claim universal detection,
  and no steganalysis method detects every hiding technique. Not covered yet: JPEG DCT-domain steganalysis,
  CNN steganalysis, WebP, recursive archive inspection.

## Links
Scored lexically (IP host, punycode, brand spoofing, shorteners, risky TLDs, random hostnames,
direct executable downloads). Downloading is off by default. Enable with `GHOSTSCAN_ALLOW_DOWNLOAD=1`;
downloads block private addresses, refuse redirects and cap the size.

## Limits
Static analysis cannot prove a file is safe, and it will miss novel or heavily encrypted payloads.
Add real signatures to `data/known_bad_hashes.txt`, and for production run the app in a container or
VM, and consider adding ClamAV or YARA rules and a trained classifier.
Resource limits use POSIX `resource` (applied inside the worker) and need Linux or macOS.
