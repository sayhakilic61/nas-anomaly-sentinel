FROM python:3.12-slim

LABEL org.opencontainers.image.title="nas-anomaly-sentinel" \
      org.opencontainers.image.description="Early ransomware / anomaly detection for home NAS shares and Docker containers" \
      org.opencontainers.image.source="https://github.com/sayhakilic61/nas-anomaly-sentinel" \
      org.opencontainers.image.licenses="MIT"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY sentinel ./sentinel
COPY simulator ./simulator

EXPOSE 8080
HEALTHCHECK --interval=60s --timeout=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/api/status', timeout=3)" || exit 1

CMD ["python", "-m", "sentinel.main"]
