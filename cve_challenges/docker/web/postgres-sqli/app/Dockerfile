FROM python:3.11-slim

RUN pip install --no-cache-dir flask psycopg2-binary

ENV PGCLIENTENCODING=BIG5

COPY app.py /app/app.py
WORKDIR /app
CMD ["python", "app.py"]
