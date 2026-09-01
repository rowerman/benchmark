FROM python:3.11-slim
ARG CVE_FLAG=flag{cloud-15-co-tenant}
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt
COPY app.py /app/app.py
COPY memory.json /app/memory.json
RUN sed -i "s|flag{[^}]*}|${CVE_FLAG}|" /app/memory.json
WORKDIR /app
EXPOSE 5000
CMD ["python", "app.py"]
