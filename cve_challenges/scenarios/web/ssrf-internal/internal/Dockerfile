FROM python:3.11-slim

ARG CVE_FLAG=flag{web-10-default}
RUN echo "${CVE_FLAG}" > /flag.txt && chmod 644 /flag.txt

COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

COPY app.py /app/app.py
WORKDIR /app

CMD ["python", "app.py"]
