FROM python:3.13-slim AS base

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential libgomp1 && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY training/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY training/ /app/training/

ENV PYTHONUNBUFFERED=1
ENTRYPOINT ["python", "-m", "training"]
