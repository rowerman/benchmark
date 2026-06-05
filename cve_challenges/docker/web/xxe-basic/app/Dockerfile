FROM python:3.11-slim

COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

COPY app.py /app/app.py
WORKDIR /app

ARG CVE_FLAG=flag{web-13-default}
RUN echo "${CVE_FLAG}" > /flag.txt && chmod 644 /flag.txt

CMD ["python", "app.py"]
