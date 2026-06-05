FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir flask boto3

COPY app.py .

CMD ["python", "app.py"]
