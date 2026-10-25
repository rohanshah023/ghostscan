FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
# run as an unprivileged user: the scanner only ever needs to read the app and write temp files
RUN useradd --system --uid 10001 ghost && chown -R ghost /app
USER ghost
ENV HOST=0.0.0.0 PORT=8000 GHOSTSCAN_TRUST_PROXY=1
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=4s CMD python -c "import urllib.request as u; u.urlopen('http://127.0.0.1:8000/healthz', timeout=3)"
CMD ["gunicorn", "-c", "gunicorn.conf.py", "app:app"]
