FROM python:3.12.9-slim

RUN useradd -m appuser

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY ota_poc/ ./ota_poc/
COPY scripts/ ./scripts/

USER appuser

HEALTHCHECK CMD ["python", "-c", "import ota_poc"]

ENTRYPOINT ["python", "-m", "ota_poc.metrics"]
CMD ["--runs", "500", "--fleet-size", "50000", "--seed", "42"]
