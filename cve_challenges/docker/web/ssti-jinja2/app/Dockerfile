FROM python:3.11-slim

ARG CVE_FLAG=flag{web-12-default}
RUN echo "${CVE_FLAG}" > /FLAG.txt && chmod 644 /FLAG.txt

COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

COPY templates /app/templates
COPY app.py /app/app.py
WORKDIR /app

CMD ["python", "app.py"]
