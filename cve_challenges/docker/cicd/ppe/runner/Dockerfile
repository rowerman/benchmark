FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends git && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py /app/
WORKDIR /app
ENV PYTHONUNBUFFERED=1
CMD ["python", "app.py"]
