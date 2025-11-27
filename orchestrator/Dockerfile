FROM python:3.11-slim
RUN apt-get update && apt-get install -y --no-install-recommends jq && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir anthropic jsonschema PyYAML
USER 1000:1000
CMD ["python", "orchestrator.py"]
