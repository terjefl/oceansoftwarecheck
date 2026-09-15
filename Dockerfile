FROM python:3.12-slim

# WeasyPrint needs the pango/cairo libraries from the OS
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz-subset0 \
        libcairo2 libgdk-pixbuf-2.0-0 shared-mime-info fonts-dejavu-core curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /srv/oceansoftwarecheck

# requirements.lock is generated from requirements.txt with
#   uv pip compile requirements.txt --python-version 3.12 --python-platform linux --generate-hashes -o requirements.lock
COPY requirements.lock .
RUN pip install --no-cache-dir --require-hashes -r requirements.lock

COPY app/ ./app/
COPY requirements.example.yaml .

RUN useradd --create-home --uid 1000 osc \
    && mkdir -p /data /config \
    && cp requirements.example.yaml /config/requirements.yaml \
    && chown -R osc:osc /srv/oceansoftwarecheck /data /config

USER osc

ENV OSC_DATA_DIR=/data \
    OSC_UPLOADS_DIR=/data/uploads \
    OSC_REQUIREMENTS_PATH=/config/requirements.yaml

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -sf http://localhost:8000/healthz || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
