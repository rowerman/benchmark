FROM python:3.11-slim
ARG CVE_FLAG=flag{cloud-29-cross-tenant-workspace}
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt
COPY app.py /app/app.py
COPY workspaces /app/workspaces
RUN sed -i "s|flag{[^}]*}|${CVE_FLAG}|" /app/workspaces/tenant-b/secret.txt
WORKDIR /app
EXPOSE 5000
CMD ["python", "app.py"]
