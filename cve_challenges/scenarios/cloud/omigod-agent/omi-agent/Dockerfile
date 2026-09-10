FROM python:3.11-slim
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt
COPY app.py /app/app.py
WORKDIR /app
ARG CVE_FLAG=flag{cloud-22-default}
RUN echo "${CVE_FLAG}" > /root/flag.txt && chmod 644 /root/flag.txt
EXPOSE 5986
CMD ["python", "app.py"]
