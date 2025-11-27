FROM python:3.11-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
  binwalk exiftool xxd file bsdmainutils && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir psutil PyYAML
USER 1000:1000
CMD ["python", "worker.py"]
