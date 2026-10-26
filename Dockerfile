FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev tcpdump && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY config.yaml .
COPY src/ ./src/
COPY scripts/ ./scripts/
COPY tests/ ./tests/

CMD ["python", "src/sniffer.py", "--iface", "enp0s3"]