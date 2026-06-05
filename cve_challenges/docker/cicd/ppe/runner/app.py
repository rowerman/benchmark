"""CI-01: Poisoned Pipeline Execution

Runner service that initializes Gitea with a project repo and CI webhook.
When triggered (via webhook or /run endpoint), it clones the repo,
executes .ci/build.sh from the checked-out code, and returns the output.

VULNERABILITY: The CI runner executes user-contributed code from .ci/build.sh
without sandboxing. The FLAG environment variable is available during builds.
"""
import base64
import os
import subprocess
import time

import requests
from flask import Flask, jsonify, request

app = Flask(__name__)

FLAG = os.environ.get('FLAG', 'flag{ci-01-default}')
GITEA_URL = os.environ.get('GITEA_URL', 'http://gitea:3000')
ADMIN_USER = os.environ.get('GITEA_ADMIN_USER', 'developer')
ADMIN_PASS = os.environ.get('GITEA_ADMIN_PASS', 'password123')
REPO_NAME = os.environ.get('GITEA_REPO', 'project-x')
WEBHOOK_URL = os.environ.get('WEBHOOK_URL', 'http://runner:5000/webhook')

_token = None


# ---------------------------------------------------------------------------
# Gitea initialization
# ---------------------------------------------------------------------------

def _gitea_is_ready():
    """Wait for Gitea API to be fully operational (after install)."""
    for i in range(30):
        try:
            r = requests.get(f'{GITEA_URL}/api/v1/version', timeout=5)
            if r.status_code == 200:
                return True
        except requests.RequestException:
            pass
        time.sleep(2)
    return False


def _get_token():
    """Obtain an API token for the admin user."""
    global _token
    try:
        r = requests.post(
            f'{GITEA_URL}/api/v1/users/{ADMIN_USER}/tokens',
            json={
                'name': 'ci-runner',
                'scopes': [
                    'write:repository',
                    'read:repository',
                    'write:user',
                    'read:user',
                ],
            },
            auth=(ADMIN_USER, ADMIN_PASS),
            timeout=5,
        )
        if r.status_code == 201:
            _token = r.json()['sha1']
            return
        # Token may already exist — try listing them
        r = requests.get(
            f'{GITEA_URL}/api/v1/users/{ADMIN_USER}/tokens',
            auth=(ADMIN_USER, ADMIN_PASS),
            timeout=5,
        )
        if r.status_code == 200:
            tokens = r.json()
            if tokens:
                _token = tokens[0].get('sha1')
                return
            # Delete stale and retry
            for t in tokens:
                requests.delete(
                    f'{GITEA_URL}/api/v1/users/{ADMIN_USER}/tokens/{t["id"]}',
                    auth=(ADMIN_USER, ADMIN_PASS),
                    timeout=5,
                )
            r = requests.post(
                f'{GITEA_URL}/api/v1/users/{ADMIN_USER}/tokens',
                json={'name': 'ci-runner'},
                auth=(ADMIN_USER, ADMIN_PASS),
                timeout=5,
            )
            if r.status_code == 201:
                _token = r.json()['sha1']
    except (requests.RequestException, KeyError, IndexError) as e:
        print(f'Token retrieval failed: {e}')


def _auth_header():
    return {'Authorization': f'token {_token}'}


def _ensure_repo():
    """Create repo + .ci/build.sh + webhook if they don't exist."""
    # Check if repo exists
    r = requests.get(
        f'{GITEA_URL}/api/v1/repos/{ADMIN_USER}/{REPO_NAME}',
        headers=_auth_header(),
        timeout=5,
    )
    if r.status_code == 200:
        print('Repo already exists')
        return True

    # Create repo
    r = requests.post(
        f'{GITEA_URL}/api/v1/user/repos',
        headers=_auth_header(),
        json={'name': REPO_NAME, 'auto_init': True, 'private': False},
        timeout=5,
    )
    print(f'Repo creation: {r.status_code}')
    if r.status_code not in (201, 200):
        print(f'Repo creation failed: {r.text}')
        return False
    time.sleep(2)

    # Create .ci/build.sh via git push (Gitea content API requires SHA in 1.21)
    clone_url = f'http://{ADMIN_USER}:{ADMIN_PASS}@gitea:3000/{ADMIN_USER}/{REPO_NAME}.git'
    work_dir = f'/tmp/git-init-{REPO_NAME}'
    subprocess.run(['rm', '-rf', work_dir], capture_output=True)
    try:
        subprocess.run(['git', 'clone', clone_url, work_dir],
            capture_output=True, timeout=30, check=True)
        os.makedirs(f'{work_dir}/.ci', exist_ok=True)
        with open(f'{work_dir}/.ci/build.sh', 'w') as f:
            f.write('#!/bin/sh\nset -e\n'
                    'echo "========================================="\n'
                    'echo "  CI Build for project-x"\n'
                    'echo "========================================="\n'
                    'echo "Running build steps..."\n'
                    'echo "Build complete."\n')
        subprocess.run(['git', '-C', work_dir, 'add', '.ci/build.sh'],
            capture_output=True, timeout=10, check=True)
        subprocess.run(['git', '-C', work_dir, '-c', 'user.name=CI Runner',
            '-c', 'user.email=ci@corp.com', 'commit', '-m', 'Add CI build script'],
            capture_output=True, timeout=10, check=True)
        subprocess.run(['git', '-C', work_dir, 'push', 'origin', 'main'],
            capture_output=True, timeout=30, check=True)
        print('Build script: created via git push')
    except subprocess.CalledProcessError as e:
        print(f'Build script git error: {e.stderr.decode(errors="replace")[:200]}')
    except Exception as e:
        print(f'Build script error: {e}')
    finally:
        subprocess.run(['rm', '-rf', work_dir], capture_output=True)
    time.sleep(1)

    # Create webhook for pull_request events
    r = requests.post(
        f'{GITEA_URL}/api/v1/repos/{ADMIN_USER}/{REPO_NAME}/hooks',
        headers=_auth_header(),
        json={
            'type': 'gitea',
            'config': {
                'url': WEBHOOK_URL,
                'content_type': 'json',
            },
            'events': ['pull_request'],
            'active': True,
        },
        timeout=5,
    )
    print(f'Webhook: {r.status_code}')

    return True


def init_gitea():
    """Initialize Gitea repos and webhooks."""
    if not _gitea_is_ready():
        return False

    _get_token()
    if not _token:
        print('ERROR: No API token available')
        return False

    return _ensure_repo()


# ---------------------------------------------------------------------------
# Build execution
# ---------------------------------------------------------------------------

def run_build(repo_full_name, ref, clone_url):
    """Clone the repo, check out *ref*, run .ci/build.sh, return output."""
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
    except subprocess.CalledProcessError as e:
        return f'Clone failed: {e.stderr.decode(errors="replace")}'
    except Exception as e:
        return f'Clone error: {e}'

    # Try to fetch the target ref (PR branch)
    if ref and ref != 'refs/heads/main':
        try:
            subprocess.run(
                ['git', 'fetch', 'origin', f'{ref}:refs/remotes/origin/target'],
                capture_output=True, timeout=30, cwd=work_dir,
            )
            subprocess.run(
                ['git', 'checkout', 'origin/target'],
                capture_output=True, timeout=10, cwd=work_dir,
            )
        except Exception:
            pass  # fall back to whatever was cloned

    try:
        result = subprocess.run(
            ['sh', '.ci/build.sh'],
            capture_output=True, text=True, timeout=30, cwd=work_dir,
        )
        output = f'=== Build Output ===\n{result.stdout}'
        if result.stderr:
            output += f'\n=== Stderr ===\n{result.stderr}'
        if result.returncode != 0:
            output += f'\n(exit code: {result.returncode})'
    except subprocess.TimeoutExpired:
        output = 'Build timed out after 30s'
    except Exception as e:
        output = f'Build error: {e}'
    finally:
        subprocess.run(['rm', '-rf', work_dir], capture_output=True)

    return output


def post_pr_comment(repo_full_name, pr_number, body):
    """Post a comment on the PR with build results."""
    url = f'{GITEA_URL}/api/v1/repos/{repo_full_name}/issues/{pr_number}/comments'
    try:
        r = requests.post(
            url,
            headers=_auth_header(),
            json={'body': body},
            timeout=5,
        )
        return r.status_code == 201
    except requests.RequestException:
        return False


# ---------------------------------------------------------------------------
# Flask routes
# ---------------------------------------------------------------------------

@app.route('/webhook', methods=['POST'])
def webhook():
    """Receive Gitea webhook events for pull_request actions."""
    data = request.get_json(silent=True) or {}
    event = request.headers.get('X-Gitea-Event', '')

    if event == 'pull_request':
        action = data.get('action', '')
        if action in ('opened', 'synchronize'):
            pr = data.get('pull_request', {})
            repo = data.get('repository', {})
            repo_full = repo.get('full_name', f'{ADMIN_USER}/{REPO_NAME}')
            pr_num = pr.get('number', 1)
            ref = pr.get('head', {}).get('ref', 'main')
            clone = repo.get('clone_url', f'{GITEA_URL}/{repo_full}.git')

            output = run_build(repo_full, f'refs/pull/{pr_num}/head', clone)
            comment = f'**CI Build Results**\n\n```\n{output}\n```'
            post_pr_comment(repo_full, pr_num, comment)

    return jsonify({'status': 'ok'})


@app.route('/run', methods=['POST'])
def manual_trigger():
    """Manually trigger a build (bypass webhook)."""
    data = request.get_json(silent=True) or {}
    repo = data.get('repo', f'{ADMIN_USER}/{REPO_NAME}')
    ref = data.get('ref', 'refs/heads/main')
    clone_url = data.get(
        'clone_url',
        f'{GITEA_URL}/{repo}.git',
    )
    output = run_build(repo, ref, clone_url)
    return jsonify({'status': 'ok', 'output': output})


@app.route('/', methods=['GET'])
def index():
    return jsonify({
        'service': 'CI Runner',
        'gitea': GITEA_URL,
        'endpoints': {
            'webhook': 'POST /webhook (Gitea events)',
            'manual': 'POST /run {"repo":"...","ref":"..."}',
        },
    })


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    init_gitea()
    print('Starting CI runner web server...')
    app.run(host='0.0.0.0', port=5000)
