# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Context

This directory is part of the **DARWIN** framework — an LLM-based automated penetration testing system. It contains benchmark adapters and challenge definitions for evaluating DARWIN's performance. The sibling `benchmark_open/` directory holds open-source benchmark suites (GOAD, cloudgoat, GCPGoat, TerraformGoat, cicd-goat, kubernetes-goat, metarget, PACEbench, XBOW).

DARWIN core (`darwin.orchestrator`, `darwin.utils.llm`, `experiments.metrics`) is imported from outside this directory — these benchmarks are test harnesses, not the orchestrator itself.

## Architecture

### Three Benchmark Types

| Benchmark | Location | Delivery | Defense Layer? |
|-----------|----------|----------|:---:|
| **Custom Defense** | `custom_defense/` | Local Python HTTP server (no Docker) | Yes — Cloak, Honey, Trap, Combined |
| **CVE Challenges** | `cve_challenges/` | Docker Compose / KIND / Vagrant | Optional (via `_defense` variants) |
| **Local WAF** | `local_waf/` | Python reverse proxy | Yes — ModSecurity-style rules |

### Two Adapter Protocols

- **PACEBench** (`pacebench_adapter.py`): FastAPI server with 4 endpoints — `POST /model`, `POST /chat`, `GET /result`, `POST /stop`. Used by the PACEBench evaluation framework.
- **XBOW** (`xbow_adapter.py`): Python adapter class that manages Docker Compose lifecycle per challenge. Run directly or imported.

### Custom Defense Challenge Architecture

Each challenge is a Python `http.server` handler inheriting from `_BaseVulnHandler`, which embeds 5 intentional vulnerability types:
- `sqli_login` — raw string interpolation in SQL query
- `sqli_blind` — LIKE-based blind SQLi
- `xss_reflected` — raw HTML injection of query param
- `cmdi_ping` — `shell=True` subprocess execution
- `lfi_path` — unsanitized file open

Defense layers are applied via **handler class factories** (e.g., `apply_cloak_banner(config) -> type`). For Combined challenges, multiple defenses are stacked. For WAF challenges, a pass-through handler runs behind the `local_waf` proxy.

### Local WAF Architecture

A reverse proxy that inspects request path + headers + body against regex patterns (OWASP CRS style). Blocked requests return 403 with ModSecurity headers. Unblocked requests are forwarded to the backend. Multiple rules may match — first match wins.

## Common Commands

### Custom Defense Benchmark

```bash
# List all 20 challenges
python3 benchmarks/custom_defense/challenges.py --list

# Start a single challenge (local HTTP server)
python3 benchmarks/custom_defense/challenges.py cloak-01
python3 benchmarks/custom_defense/challenges.py waf-01

# Run DARWIN against one challenge
python3 -m benchmarks.custom_defense.runner cloak-01

# Run all challenges in a defense category
python3 -m benchmarks.custom_defense.runner --category cloak
python3 -m benchmarks.custom_defense.runner --category honey
python3 -m benchmarks.custom_defense.runner --category trap
python3 -m benchmarks.custom_defense.runner --category combined

# Run all 20 challenges
python3 -m benchmarks.custom_defense.runner --all

# Multiple attempts per challenge (pass@k)
python3 -m benchmarks.custom_defense.runner --category waf --pass-at-k 3
```

### Local WAF

```bash
# Start WAF reverse proxy (listen_port → backend_port)
python3 benchmarks/local_waf/waf_server.py 8001 8002
```

### CVE Challenges (Primary Benchmark)

**IMPORTANT:** When adding or modifying ANY scenario, chain, or documentation in `cve_challenges/`, you MUST first read the full skill file at `.claude/skills/cve-benchmark.md`. This skill enforces 10 rules covering port allocation, nmap service detection, flag management, documentation format, build testing, and modular design. Do not make any changes to cve_challenges without consulting this skill.

```bash
cd benchmarks/cve_challenges

# List all scenarios
./scripts/list-scenarios.sh

# Start/stop Docker scenarios
./scripts/start-scenario.sh web-03        # WordPress RCE
./scripts/start-scenario.sh db-05         # Redis unauth
./scripts/stop-scenario.sh web-03

# K8s scenarios (requires KIND + kubectl)
./scripts/start-scenario.sh k8s-06

# AD scenarios (requires Samba AD DC first)
docker compose -f ad/docker-compose.yml up -d --build
./scripts/start-scenario.sh ad-01

# Attack chains
bash chains/container-to-admin/deploy.sh

# Reset everything
./scripts/reset-all.sh

# Validate all scenarios
./scripts/validate-all.sh

# Verify a flag
./scripts/verify-flag.sh web-01 <flag>
```

### Regenerate Documentation

```bash
# Regenerate benchmark overview table
python benchmarks/cve_challenges/scripts/build_benchmark_overview.py

# Regenerate full exploitation summary
python benchmarks/cve_challenges/scripts/build_benchmark_summary.py
```

## Challenge ID Conventions

- **Custom Defense**: `{defense}-{number}` — e.g. `cloak-01`, `honey-03`, `trap-05`, `combined-02`, `waf-01`
- **CVE Scenarios**: `{domain}-{number}` — e.g. `web-01`, `db-05`, `k8s-06`, `ad-01`, `lnx-05`
- **Defense categories**: `cloak` (stealth), `honey` (deception), `trap` (resource attacks), `combined` (layered)

## Key Dependencies

- **DARWIN Orchestrator**: `from darwin.orchestrator import Orchestrator, TaskResult` — the LLM-driven pentest agent
- **Experiment Metrics**: `from experiments.metrics import ExperimentMetrics, compute_pass_at_k` — result tracking
- **LLM Session**: `from darwin.utils.llm import LLMSession` — configured via `config/llm.yaml` (`profile="default"`)
- **Docker + Compose v2**: CVE challenges (Web, DB, LNX-05, AD)
- **KIND + kubectl**: K8s CVE challenges
- **Vagrant + VirtualBox** (optional): Linux kernel exploitation challenges (requires VT-x)

## Flag Format

Custom Defense flags: `flag{<defense>_<subtype>_<year>}` (e.g., `flag{cloak_b4nn3r_2026}`)
CVE flags: `flag{<scenario-id>-<8-hex>}` (verified via `./scripts/verify-flag.sh`)

## Adding a New Custom Defense Challenge

1. Add entry to `CHALLENGES` dict in `custom_defense/challenges.py` with unique ID, `defense`, `subtype`, `vuln`, `flag`, and `port`
2. If creating a new defense subtype, add a handler factory function and register it in `DEFENSE_FACTORIES`
3. If creating a new combined defense, add to `COMBINED_DEFENSES`
4. The runner (`custom_defense/runner.py`) auto-discovers challenges from the `CHALLENGES` dict

## WAF Rule Modification

WAF rules are in `local_waf/waf_server.py` → `WAFHandler.BLOCK_RULES`. Each rule is a `(compiled_regex, rule_id, description)` tuple. Rules are evaluated in order against the concatenated request path + body + headers — first match blocks.
