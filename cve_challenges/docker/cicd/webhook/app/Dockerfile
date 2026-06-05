FROM python:3.11-slim
RUN pip install --no-cache-dir flask
COPY app.py /app/
WORKDIR /app
CMD ["python", "app.py"]
