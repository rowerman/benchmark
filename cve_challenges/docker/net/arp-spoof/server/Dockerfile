FROM python:3.11-slim

ARG CVE_FLAG=flag{net-01-default}
ENV ADMIN_PASSWORD=${CVE_FLAG}

COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir flask

COPY app.py /app/app.py
WORKDIR /app

EXPOSE 5000
CMD ["python", "app.py"]
