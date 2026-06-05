#!/usr/bin/env python3
"""Flag generation, injection, and verification for CVE benchmarks."""
import re
import hashlib
import secrets
from pathlib import Path

FLAG_PATTERN = re.compile(r'flag\{[a-zA-Z0-9_\-!@#$%^&*()+=]+\}')
HONEYPOT_KEYWORDS = [
    'test', 'example', 'honeypot', 'demo', 'fake',
    'sample', 'placeholder', 'dummy', '123456'
]


def generate_flag(scenario_id: str) -> str:
    rand = secrets.token_hex(8)
    return f"flag{{{scenario_id}-{rand}}}"


def is_valid_flag(flag: str) -> bool:
    if not FLAG_PATTERN.fullmatch(flag):
        return False
    content = flag[5:-1].lower()
    return not any(kw in content for kw in HONEYPOT_KEYWORDS)


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <scenario-id>")
        sys.exit(1)
    print(generate_flag(sys.argv[1]))
