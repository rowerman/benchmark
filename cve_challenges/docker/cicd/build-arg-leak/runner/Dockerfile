FROM docker:27.0-cli

RUN apk add --no-cache git py3-pip python3 && \
    pip3 install --break-system-packages flask requests

COPY requirements.txt /tmp/
RUN pip3 install --break-system-packages -r /tmp/requirements.txt 2>/dev/null || true

COPY app.py /app/
WORKDIR /app
ENV PYTHONUNBUFFERED=1
CMD ["python3", "app.py"]
