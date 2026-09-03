# CVE Benchmark - DARWIN LLM Pentest Evaluation

Self-hosted penetration-testing benchmark built from public CVEs and realistic
misconfiguration scenarios. The active benchmark contains 89 single scenarios
and 37 attack chains across Web, database, cloud, and Kubernetes domains.

## Quick Start

```bash
cd cve_challenges

# Inspect the registered scenarios
./scripts/list-scenarios.sh

# Start and stop a single scenario by its stable ID
./scripts/start-scenario.sh web-03
./scripts/stop-scenario.sh web-03

# Run and stop a chain through the unified entrypoints
./scripts/start-chain.sh managed-db-lateral
./scripts/stop-chain.sh managed-db-lateral

# Check registry, scenario documentation, and chain references
python scripts/validate-structure.py
python scripts/validate-flag-contract.py

# Feature-driven nmap service identification for Docker cloud scenarios
bash scripts/setup-cloud-nmap.sh             # once: merge probes (iptables needs root)
bash scripts/validate-cloud-nmap.sh          # 30 cloud main ports, no Werkzeug/unknown
```

Docker Compose is required for Docker scenarios. KIND and kubectl are required
for Kubernetes scenarios.

## Scenario Layout

Every single scenario lives below `scenarios/`, independent of its delivery
mechanism. Its `GUIDE.md` is the authoritative scenario documentation.

```text
cve_challenges/
  scenarios/
    web/      # 18 scenarios
    db/       # 9 scenarios
    cloud/    # 30 public-cloud scenarios: Docker Compose
    k8s/      # 33 Kubernetes/KIND scenarios
  infra/
    cloud/    # shared provider simulators; not deployable scenarios
  chains/     # 37 multi-scenario attack paths
  scripts/    # lifecycle, validation, and flag helpers
```

The scenario registry at `scripts/scenarios.yaml` defines each stable ID,
delivery type, path, port, difficulty, and CVE/technique. Lifecycle scripts use
that registry rather than domain-specific hard-coded paths.

## Documentation Contract

Each registered single scenario must contain a non-empty `GUIDE.md` covering
the scenario, attack path, exploitation steps, flag capture, and remediation.
When adding a scenario, add its guide in the same change and run
`python scripts/validate-structure.py` before committing.

Cloud scenarios can share provider simulators in `infra/cloud`; those helpers
must not be registered as standalone scenarios.

## Flags

Flags follow `flag{<scenario-id>-<suffix>}`. Validate a captured value with:

```bash
./scripts/verify-flag.sh 'flag{example-value}'
```

Single scenarios use `CVE_FLAG`; scenarios or chains with multiple logical
flags use consecutive `CVE_FLAG1`, `CVE_FLAG2`, and so on. Explicitly supplied
values take precedence over generated values.
