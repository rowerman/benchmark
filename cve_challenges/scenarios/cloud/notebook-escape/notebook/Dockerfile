FROM python:3.11-slim
RUN pip install --no-cache-dir flask==3.1.1
COPY app.py /app/app.py
COPY workspace/ /app/workspace/
WORKDIR /app
# Flag is on the Docker host at /tmp/cloud-09-flag/flag.txt
# Attacker must use Docker socket escape to read it:
#   docker run -v /tmp/cloud-09-flag:/mnt alpine cat /mnt/flag.txt
EXPOSE 5000
CMD ["python", "app.py"]
