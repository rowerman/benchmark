FROM python:3.11-slim
RUN pip install --no-cache-dir flask==3.1.1 cryptography==42.0.0 pyjwt==2.8.0
COPY app.py /app/app.py
COPY generate_keys.py /app/generate_keys.py
RUN mkdir -p /app/keys && python /app/generate_keys.py --output /app/keys/
WORKDIR /app
EXPOSE 5000
CMD ["python", "app.py"]
