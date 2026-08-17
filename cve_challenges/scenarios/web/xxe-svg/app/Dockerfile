FROM python:3.11-slim

COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

COPY app.py /app/app.py
WORKDIR /app

ARG CVE_FLAG=flag{web-14-default}
RUN mkdir -p /app && echo "${CVE_FLAG}" > /app/flag.txt && chmod 644 /app/flag.txt

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "5000"]
