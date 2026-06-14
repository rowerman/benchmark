FROM python:3.11-slim
RUN pip install --no-cache-dir flask==3.1.1 pyyaml==6.0
COPY app.py /app/app.py
WORKDIR /app
ENV FLAG2=flag{cloud-05-step2-cf-inject}
EXPOSE 5000
CMD ["python", "app.py"]
