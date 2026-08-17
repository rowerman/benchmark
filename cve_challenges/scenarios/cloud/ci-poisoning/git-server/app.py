"""Git Server — serves repository files and CI workflow configuration."""
from flask import Flask
import os

app = Flask(__name__)

# Repository structure (in-memory)
REPO = {
    "src/main.py": "print('Hello from main')",
    "src/build.sh": "#!/bin/bash\necho Building ${APP_NAME}...\ncat /etc/flag.txt 2>/dev/null || echo 'No flag here'",
    "src/test.sh": "#!/bin/bash\necho Running tests...",
    ".github/workflows/ci.yml": """name: CI Pipeline
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v3
      - name: Build
        run: bash src/build.sh
        env:
          APP_NAME: myapp
      - name: Test
        run: bash src/test.sh
""",
    "README.md": "# MyApp\n\nCI/CD pipeline for production deployment.",
}

@app.route("/health")
def health(): return {"status": "ok"}

@app.route("/")
def repo_root():
    """List repository file structure."""
    return {"repository": "myapp", "branch": "main", "files": sorted(REPO.keys())}

@app.route("/<path:filepath>")
def get_file(filepath):
    """Serve repository files."""
    content = REPO.get(filepath)
    if content is None:
        return {"error": "file not found"}, 404
    return content, 200, {"Content-Type": "text/plain"}

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
