FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY ota_poc/ ./ota_poc/
COPY scripts/ ./scripts/

ENTRYPOINT ["python", "-m", "ota_poc.metrics"]
CMD ["--runs", "500", "--fleet-size", "50000", "--seed", "42"]
