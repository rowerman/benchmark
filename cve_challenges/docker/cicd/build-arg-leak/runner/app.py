"""CI-05: Build Arg Injection

A CI runner that builds a Docker image from a Gitea repo, passing the
FLAG as a build argument. The flag ends up in the image history layers.

VULNERABILITY: Build arguments injected during docker build are visible
in the image history (docker history --no-trunc).
"""
import base64
import os
import subprocess
import time

import requests
from flask import Flask, jsonify, request

app = Flask(__name__)

FLAG = os.environ.get('FLAG', 'flag{ci-05-default}')
GITEA_URL = os.environ.get('GITEA_URL', 'http://gitea:3000')
ADMIN_USER = os.environ.get('GITEA_ADMIN_USER', 'developer')
ADMIN_PASS = os.environ.get('GITEA_ADMIN_PASS', 'password123')
REPO_NAME = os.environ.get('GITEA_REPO', 'myapp')

_token = None


# ---------------------------------------------------------------------------
# Gitea initialization
# ---------------------------------------------------------------------------

def _wait_for_gitea():
    for i in range(60):
        try:
            r = requests.get(f'{GITEA_URL}/api/v1/version', timeout=5)
            if r.status_code == 200:
                return True
        except requests.RequestException:
            pass
        time.sleep(2)
    print('ERROR: Gitea did not become ready')
    return False


def _install_gitea():
    """POST to /install to create the initial admin user via the web form."""
    payload = {
        'db_type': 'SQLite3',
        'db_host': 'localhost:3306',
        'db_user': 'root',
        'db_passwd': '',
        'db_name': 'gitea',
        'ssl_mode': 'disable',
        'app_name': 'Gitea',
        'repo_root_path': '/data/git/repositories',
        'lfs_root_path': '/data/lfs',
        'run_user': 'git',
        'domain': 'localhost',
        'http_port': 3000,
        'app_url': f'{GITEA_URL}/',
        'log_root_path': '/data/gitea/log',
        'username': ADMIN_USER,
        'password': ADMIN_PASS,
        'reenter_password': ADMIN_PASS,
        'email': 'dev@example.com',
        'enable_captcha': 'false',
        'offline_mode': 'on',
        'disable_gravatar': 'on',
        'enable_open_id_sign_in': 'off',
        'enable_open_id_sign_up_auto': 'off',
    }
    for attempt in range(3):
        try:
            r = requests.post(f'{GITEA_URL}/install', data=payload, timeout=10)
            print(f'Gitea install attempt {attempt + 1}: {r.status_code} {r.reason}')
            if r.status_code in (200, 302):
                return True
        except requests.RequestException as e:
            print(f'Gitea install request failed: {e}')
        time.sleep(3)
    return False


def _get_token():
    global _token
    try:
        r = requests.post(
            f'{GITEA_URL}/api/v1/users/{ADMIN_USER}/tokens',
            json={'name': 'ci-runner'},
            auth=(ADMIN_USER, ADMIN_PASS),
            timeout=5,
        )
        if r.status_code == 201:
            _token = r.json()['sha1']
    except (requests.RequestException, KeyError):
        pass


def _auth_header():
    return {'Authorization': f'token {_token}'}


def _ensure_repo():
    """Create the repo with a Dockerfile if it doesn't exist."""
    r = requests.get(
        f'{GITEA_URL}/api/v1/repos/{ADMIN_USER}/{REPO_NAME}',
        headers=_auth_header(),
        timeout=5,
    )
    if r.status_code == 200:
        print('Repo already exists')
        return True

    r = requests.post(
        f'{GITEA_URL}/api/v1/user/repos',
        headers=_auth_header(),
        json={'name': REPO_NAME, 'auto_init': True, 'private': False},
        timeout=5,
    )
    print(f'Repo creation: {r.status_code}')
    if r.status_code not in (201, 200):
        return False
    time.sleep(2)

    # Create Dockerfile
    dockerfile = (
        'FROM alpine:3.19\n'
        'ARG SECRET_TOKEN\n'
        'RUN echo "Building image..." && \\\n'
        '    echo "Token configured for: $SECRET_TOKEN"\n'
        'COPY run.sh /run.sh\n'
        'CMD ["sh", "/run.sh"]\n'
    )
    b64 = base64.b64encode(dockerfile.encode()).decode()
    r = requests.put(
        f'{GITEA_URL}/api/v1/repos/{ADMIN_USER}/{REPO_NAME}/contents/Dockerfile',
        headers=_auth_header(),
        json={'content': b64, 'message': 'Add Dockerfile'},
        timeout=5,
    )
    print(f'Dockerfile creation: {r.status_code}')
    time.sleep(1)

    # Create run.sh
    runsh = (
        '#!/bin/sh\n'
        'echo "Application started"\n'
    )
    b64 = base64.b64encode(runsh.encode()).decode()
    requests.put(
        f'{GITEA_URL}/api/v1/repos/{ADMIN_USER}/{REPO_NAME}/contents/run.sh',
        headers=_auth_header(),
        json={'content': b64, 'message': 'Add run script'},
        timeout=5,
    )

    return True


def init_gitea():
    if not _wait_for_gitea():
        return False
    r = requests.get(
        f'{GITEA_URL}/api/v1/users/{ADMIN_USER}',
        timeout=5,
    )
    if r.status_code != 200:
        print('Gitea not installed yet — running install form...')
        _install_gitea()
        time.sleep(5)
    else:
        print(f'User {ADMIN_USER} already exists')
    _get_token()
    if not _token:
        print('ERROR: No API token')
        return False
    return _ensure_repo()


# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------

def build_image(repo_full_name, clone_url):
    """Clone repo, build Docker image with FLAG as build arg."""
    safe_name = repo_full_name.replace('/', '-').replace(':', '-')
    work_dir = f'/tmp/build-{safe_name}-{int(time.time())}'
    auth_url = clone_url.replace(
        '://', f'://{ADMIN_USER}:{ADMIN_PASS}@',
    )

    try:
        subprocess.run(
            ['git', 'clone', '--depth=1', auth_url, work_dir],
            capture_output=True, timeout=30, check=True,
        )
    except Exception as e:
        return f'Clone failed: {e}'

    image_tag = f'{safe_name}:latest'

    try:
        result = subprocess.run(
            [
                'docker', 'build',
                '--build-arg', f'SECRET_TOKEN={FLAG}',
                '-t', image_tag,
                work_dir,
            ],
            capture_output=True, text=True, timeout=60,
        )
        output = result.stdout + result.stderr
        if result.returncode == 0:
            output += f'\nImage built: {image_tag}\n'
            output += f'Run: docker history {image_tag} --no-trunc\n'
        else:
            output += f'\nBuild failed (exit {result.returncode})'
    except subprocess.TimeoutExpired:
        output = 'Build timed out'
    except Exception as e:
        output = f'Build error: {e}'
    finally:
        subprocess.run(['rm', '-rf', work_dir], capture_output=True)

    return output


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route('/trigger', methods=['POST'])
def trigger_build():
    """Trigger a Docker build on the repo."""
    data = request.get_json(silent=True) or {}
    repo = data.get('repo', f'{ADMIN_USER}/{REPO_NAME}')
    clone_url = data.get(
        'clone_url',
        f'{GITEA_URL}/{repo}.git',
    )
    output = build_image(repo, clone_url)
    return jsonify({'status': 'ok', 'output': output})


@app.route('/image', methods=['GET'])
def list_images():
    """List built Docker images (for attacker to inspect)."""
    try:
        result = subprocess.run(
            ['docker', 'images', '--format', '{{.Repository}}:{{.Tag}}'],
            capture_output=True, text=True, timeout=10,
        )
        images = result.stdout.strip().split('\n') if result.stdout else []
    except Exception:
        images = []
    return jsonify({'images': images})


@app.route('/', methods=['GET'])
def index():
    return jsonify({
        'service': 'Docker CI Runner',
        'endpoints': {
            'trigger': 'POST /trigger {"repo":"..."}',
            'images': 'GET /image',
        },
    })


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    init_gitea()
    print('Starting Docker CI runner...')
    app.run(host='0.0.0.0', port=5000)
