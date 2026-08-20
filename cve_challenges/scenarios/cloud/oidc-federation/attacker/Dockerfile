FROM python:3.11-slim
RUN pip install --no-cache-dir flask==3.1.1 requests==2.32.3
COPY app.py /app/app.py
WORKDIR /app
ARG CVE_FLAG=flag{cloud-08-default}
RUN echo "${CVE_FLAG}" > /flag.txt && chmod 644 /flag.txt
EXPOSE 5000
CMD ["python", "app.py"]
