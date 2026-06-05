FROM python:3.11-slim

RUN set -ex; \
    apt-get update && apt-get install -y --no-install-recommends \
        sqlite3 && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Create Flask app with vulnerable SQLi endpoint
COPY backend/app.py /app/app.py

# Port for Flask
EXPOSE 5000

ARG CVE_FLAG=flag{def-01-default}

# Initialize flag in SQLite database
RUN python3 -c "
import sqlite3
conn = sqlite3.connect('/app/users.db')
c = conn.cursor()
c.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)')
c.execute(\"INSERT OR REPLACE INTO users (id, username, password) VALUES (1, 'admin', '${CVE_FLAG}')\")
c.execute(\"INSERT OR REPLACE INTO users (id, username, password) VALUES (2, 'user', 'password123')\")
conn.commit()
conn.close()
"

CMD ["python3", "/app/app.py"]
