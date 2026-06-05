#!/usr/bin/env python3
"""Generate defense variant compose files for all web scenarios."""
import os, yaml
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
WEB_SCENARIOS = [
    ('web-01', 'docker/web/tomcat-deserialization', 'tomcat'),
    ('web-03', 'docker/web/wordpress-simple-file-list', 'wordpress'),
    ('web-04', 'docker/web/wordpress-wpbookit', 'wordpress'),
    ('web-06', 'docker/web/wordpress-jupiterx-lfi', 'wordpress'),
    ('web-07', 'docker/web/postgres-sqli', 'web'),  # app+db
]

DEFENSE_TYPES = ['waf', 'cloak', 'trap']


def generate_waf_variant(scenario_path: Path, backend_service: str):
    """Generate WAF overlay compose."""
    defense_dir = scenario_path / "defense" / "waf"
    defense_dir.mkdir(parents=True, exist_ok=True)
    compose = f"""services:
  waf:
    build:
      context: ../../../../../../../../
      dockerfile: benchmarks/cve_challenges/docker/_defense/WAF.Dockerfile
    ports:
      - "${{WAF_PORT:-8080}}:8080"
    environment:
      BACKEND_HOST: {backend_service}
    depends_on:
      - {backend_service}
"""
    (defense_dir / "docker-compose.override.yml").write_text(compose)


if __name__ == "__main__":
    count = 0
    for sid, path, backend in WEB_SCENARIOS:
        sp = BASE / path
        if sp.exists():
            generate_waf_variant(sp, backend)
            count += 1
    print(f"Generated {count} WAF defense variant directories")
