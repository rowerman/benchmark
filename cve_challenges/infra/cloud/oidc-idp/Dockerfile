FROM python:3.11-slim
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt
COPY app.py /app/app.py
COPY generate_keys.py /app/generate_keys.py
RUN mkdir -p /app/keys && python /app/generate_keys.py --output /app/keys/
WORKDIR /app
EXPOSE 5000
CMD ["python", "app.py"]
