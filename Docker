# syntax=docker/dockerfile:1
FROM python:3.12-slim

LABEL org.opencontainers.image.title="Ultimate SSRF Arsenal"
LABEL org.opencontainers.image.title="Ultimate SSRF Framework"
LABEL org.opencontainers.image.url="https://github.com/KauanCosta2000/Ultimate-ssrf-Framework"
LABEL org.opencontainers.image.version="4.1"
LABEL org.opencontainers.image.authors="belladonnask"

# Install system dependencies for Playwright
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl \
        libnss3 \
        libnspr4 \
        libatk1.0-0 \
        libatk-bridge2.0-0 \
        libcups2 \
        libdrm2 \
        libdbus-1-3 \
        libxkbcommon0 \
        libxcomposite1 \
        libxdamage1 \
        libxfixes3 \
        libxrandr2 \
        libgbm1 \
        libpango-1.0-0 \
        libcairo2 \
        libasound2 \
        && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install Playwright browsers (Chromium only)
RUN playwright install chromium

# Copy the rest of the application
COPY . .

# Create output directory
RUN mkdir -p /app/output

# Default command
ENTRYPOINT ["python", "ssrf_arsenal.py"]
CMD ["--help"]
