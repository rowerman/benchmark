FROM python:3.11-slim
RUN pip install flask requests
COPY app.py /app/
WORKDIR /app
CMD ["python", "app.py"]
