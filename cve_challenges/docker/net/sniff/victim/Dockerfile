FROM python:3.11-slim

COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir flask

ARG CVE_FLAG=flag{net-03-default}
ENV SECRET_TOKEN=${CVE_FLAG}

COPY app.py /app/app.py
WORKDIR /app

EXPOSE 5000
CMD ["python", "app.py"]
