FROM python:3.11-slim
RUN pip install --no-cache-dir flask pymongo
COPY app.py /app/
WORKDIR /app
ARG CVE_FLAG=flag{db-09-default}
ENV FLAG=${CVE_FLAG}
CMD ["python", "app.py"]
