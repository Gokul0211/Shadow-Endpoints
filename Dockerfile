# Reproducible scanner image (not built in CI yet). Build:   docker build -t shadow-scanner .
# Run:  docker run --rm -v "$PWD/output:/work/output" shadow-scanner --target https://app.example.test --no-probe
# Credentials: pass SHADOW_PASSWORD / SHADOW_BEARER / SHADOW_COOKIES / SHADOW_MFA_SECRET with -e rather than
# on the command line. Only scan applications you own or are authorised to test.
FROM mcr.microsoft.com/playwright/python:v1.60.0-jammy

# Node.js 22 for the value-flow sidecar (analysis/)
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates \
 && curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
 && apt-get install -y --no-install-recommends nodejs \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY analysis/package.json analysis/package-lock.json ./analysis/
RUN cd analysis && npm ci --ignore-scripts --no-audit --no-fund
COPY analysis/src ./analysis/src
COPY pyproject.toml ./
COPY shadow_scanner ./shadow_scanner
# the Excel extra needs Python >= 3.11; this base image has 3.10, so the image has JSON reports only
RUN pip install --no-cache-dir .
ENV SHADOW_ANALYSIS_DIR=/app/analysis

WORKDIR /work
ENTRYPOINT ["shadow-scanner"]
