# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Context

This directory is part of the **DARWIN** framework — an LLM-based automated penetration testing system. It contains benchmark adapters and challenge definitions for evaluating DARWIN's performance.

- `benchmarks/` — adapters + challenge definitions (Custom Defense, CVE Challenges, Local WAF)
- `benchmark_open/` — open-source benchmark suites (GOAD, cloudgoat, GCPGoat, TerraformGoat, cicd-goat, kubernetes-goat, metarget, PACEbench, XBOW)
- `pub_cloud/` — public cloud attack case library with YAML-based case definitions (sibling to `benchmarks/`)

DARWIN core (`darwin.orchestrator`, `darwin.utils.llm`, `experiments.metrics`) is imported from outside this directory — these benchmarks are test harnesses, not the orchestrator itself.

## Architecture

### Benchmark Types

| Benchmark | Location | Delivery | Defense Layer? |
|-----------|----------|----------|:---:|
| **Custom Defense** | `custom_defense/` | Local Python HTTP server (no Docker) | Yes — Cloak, Honey, Trap, Combined |
| **CVE Challenges** | `cve_challenges/` | Docker Compose / KIND / LocalStack / Vagrant | Optional (via `_defense` variants) |
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

### CVE Challenge Architecture

The canonical registry of all scenarios is `cve_challenges/scripts/scenarios.yaml` (currently 125 scenarios across 11 domains). Each scenario is a self-contained directory with its own Docker Compose / KIND / Samba AD config.

**Scenario Domains:**

| Domain | Delivery | Directory | Port Block |
|--------|----------|-----------|------------|
| WEB | Docker Compose | `docker/web/` | 10100–10129 |
| DB | Docker Compose | `docker/db/` | 10200–10229 |
| LNX (Linux PrivEsc) | Docker (SSH) | `docker/linux/` | 10300–10399 |
| K8S (Kubernetes) | KIND cluster | `k8s/` | 10400–10499 (NodePort) |
| AD (Active Directory) | Samba AD DC (Docker) | `ad/scenarios/` | 10000–10099 (UDP), 10130–10149 (TCP proxy) |
| CLOUD | Docker + LocalStack | `docker/cloud/` | 10600–10699 |
| CI/CD | Docker Compose | `docker/cicd/` | 10700–10799 |
| DEF (Anti-Forensics) | Docker Compose | `docker/defense/` | 10800–10899 |
| NET (Network Attacks) | Docker Compose | `docker/net/` | 10900–10999 |
| LKX (Linux Kernel Exploit) | Vagrant | (external) | — |
| Defense Variants | Docker + WAF fragment | `docker/_defense/` | — |

**Cloud scenarios** use LocalStack to emulate AWS services (S3, IAM, Lambda, STS, KMS, SQS, IMDS). Cloud infrastructure is in `docker/cloud/_infra/` (IAM trust, IMDS server, OIDC IdP). Nmap service detection for cloud services uses `scripts/setup-cloud-nmap.sh` and `scripts/nmap-cloud-probes.txt`.

**Anti-forensics defense variants** (`docker/defense/`) implement 5 defense evasion techniques: log-clear, lotl (living-off-the-land), process-hide, timestomp, and waf-bypass. These are separate from the `_defense/` fragment-based defense layers (cloak, honey, trap, waf).

**Attack chains** compose existing scenarios into multi-step kill chains. Chain deploy scripts orchestrate starting component scenarios, placing chain-specific per-step flags, and verifying reachability. Each chain has a `chain.yaml` defining steps and per-step flags.

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

# List all scenarios (reads scripts/scenarios.yaml)
./scripts/list-scenarios.sh

# Start/stop Docker scenarios
./scripts/start-scenario.sh web-03        # WordPress RCE
./scripts/start-scenario.sh db-05         # Redis unauth
./scripts/start-scenario.sh cloud-01      # S3 Public Read (requires LocalStack)
./scripts/stop-scenario.sh web-03

# K8s scenarios (requires KIND + kubectl)
./scripts/start-scenario.sh k8s-06

# AD scenarios (requires Samba AD DC first)
docker compose -f ad/docker-compose.yml up -d --build
./scripts/start-scenario.sh ad-01

# Cloud scenarios (requires awscli + LocalStack)
./scripts/setup-cloud-nmap.sh             # fix nmap detection for cloud services
./scripts/start-scenario.sh cloud-01

# Attack chains
bash chains/container-to-admin/deploy.sh

# Reset everything
./scripts/reset-all.sh

# Validate all scenarios
./scripts/validate-all.sh

# Verify a flag
./scripts/verify-flag.sh web-01 <flag>
```

### Documentation

```bash
# Learning path guide (difficulty-graded scenario recommendations)
cat benchmarks/cve_challenges/docs/LEARNING_PATH.md

# Regenerate benchmark overview table
python benchmarks/cve_challenges/scripts/build_benchmark_overview.py

# Regenerate full exploitation summary
python benchmarks/cve_challenges/scripts/build_benchmark_summary.py
```

### Scenario Design Reference

When designing new scenarios, the skill file at `.claude/skills/cve-benchmark/SKILL.md` contains:
- Port Allocation Registry (10000–14000 range, sub-blocks for each domain)
- ATT&CK tactic-to-technique mapping for each domain
- Template Dockerfile, docker-compose.yml, K8s deploy.sh, AD config.yaml, and chain.yaml
- Naming conventions for scenario IDs, directories, and documentation files
- Domain priority: K8s > Docker > AD > Linux (prefer KIND and Docker; avoid Vagrant unless unavoidable)

## Challenge ID Conventions

- **Custom Defense**: `{defense}-{number}` — e.g. `cloak-01`, `honey-03`, `trap-05`, `combined-02`, `waf-01`
- **CVE Scenarios**: `{domain}-{number}` — e.g. `web-03`, `k8s-06`, `ad-01`, `cloud-01`, `ci-01`, `net-01`, `def-01`
- **Defense categories**: `cloak` (stealth), `honey` (deception), `trap` (resource attacks), `combined` (layered)
- **CVE domains**: `web`, `db`, `lnx`, `k8s`, `ad`, `cloud`, `ci`, `net`, `def`, `lkx`

## Key Dependencies

- **DARWIN Orchestrator**: `from darwin.orchestrator import Orchestrator, TaskResult` — the LLM-driven pentest agent
- **Experiment Metrics**: `from experiments.metrics import ExperimentMetrics, compute_pass_at_k` — result tracking
- **LLM Session**: `from darwin.utils.llm import LLMSession` — configured via `config/llm.yaml` (`profile="default"`)
- **Docker + Compose v2**: CVE challenges (Web, DB, Cloud, CI/CD, Net, Defense, Linux, AD)
- **KIND + kubectl**: K8s CVE challenges
- **LocalStack**: Cloud CVE challenges (AWS service emulation)
- **Vagrant + VirtualBox** (optional): Linux kernel exploitation challenges (requires VT-x)

## Flag Format

Custom Defense flags: `flag{<defense>_<subtype>_<year>}` (e.g., `flag{cloak_b4nn3r_2026}`)
CVE single-point flags: `flag{<scenario-id>-<8-hex>}` (verified via `./scripts/verify-flag.sh`)
Chain per-step flags: `flag{chain<N>-step<M>-<descriptor>}` (e.g., `flag{chain3-step2-db}`)

## Adding a New Custom Defense Challenge

1. Add entry to `CHALLENGES` dict in `custom_defense/challenges.py` with unique ID, `defense`, `subtype`, `vuln`, `flag`, and `port`
2. If creating a new defense subtype, add a handler factory function and register it in `DEFENSE_FACTORIES`
3. If creating a new combined defense, add to `COMBINED_DEFENSES`
4. The runner (`custom_defense/runner.py`) auto-discovers challenges from the `CHALLENGES` dict

## WAF Rule Modification

WAF rules are in `local_waf/waf_server.py` → `WAFHandler.BLOCK_RULES`. Each rule is a `(compiled_regex, rule_id, description)` tuple. Rules are evaluated in order against the concatenated request path + body + headers — first match blocks.
