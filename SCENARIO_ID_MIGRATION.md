# Scenario ID Migration

This benchmark now separates scenario semantics by directory:

- `scenarios/cloud/` contains public-cloud scenarios only.
- `scenarios/k8s/` contains all private-cloud scenarios, regardless of delivery type.
- Existing K8s scenario IDs are unchanged.
- The 29 private-cloud migrations fill the available K8s IDs: `04`, `31`, and `34..60`.

Flags use the new scenario ID as their prefix. Dependencies that persist scenario IDs should replace both the ID and its path using the table below.

## Public cloud renumbering

| Old ID | New ID | Scenario | Path |
|---|---|---|---|
| `cloud-11` | `cloud-01` | Global S3 Namespace Squatting | `scenarios/cloud/global-s3-squatting` |
| `cloud-26` | `cloud-02` | Dependency Confusion in Managed Data Platform | `scenarios/cloud/composer-depconf` |

## Private cloud migration

| Old ID | New ID | Scenario | Old path | New path |
|---|---|---|---|---|
| `cloud-01` | `k8s-04` | SSRF to Instance Metadata Credential Theft | `scenarios/cloud/ssrf-to-imds` | `scenarios/k8s/ssrf-to-imds` |
| `cloud-02` | `k8s-31` | CAP_NET_RAW to Metadata MITM | `scenarios/cloud/cap-netraw-metadata` | `scenarios/k8s/cap-netraw-metadata` |
| `cloud-03` | `k8s-34` | Serverless Code Injection to IAM PassRole | `scenarios/cloud/lambda-passrole` | `scenarios/k8s/lambda-passrole` |
| `cloud-04` | `k8s-35` | Private IaC Template Injection | `scenarios/cloud/cf-injection` | `scenarios/k8s/cf-injection` |
| `cloud-05` | `k8s-36` | Private CI/CD Pipeline Poisoning | `scenarios/cloud/ci-poisoning` | `scenarios/k8s/ci-poisoning` |
| `cloud-06` | `k8s-37` | Managed Notebook Escape | `scenarios/cloud/notebook-escape` | `scenarios/k8s/notebook-escape` |
| `cloud-07` | `k8s-38` | OIDC Claim Mismatch | `scenarios/cloud/oidc-federation` | `scenarios/k8s/oidc-federation` |
| `cloud-08` | `k8s-39` | IAM Cross-Project Trust Policy Takeover | `scenarios/cloud/cross-account-trust` | `scenarios/k8s/cross-account-trust` |
| `cloud-09` | `k8s-40` | Golden SAML Trust-Root Compromise | `scenarios/cloud/golden-saml` | `scenarios/k8s/golden-saml` |
| `cloud-10` | `k8s-41` | Tenant Policy Bypass via Legacy API | `scenarios/cloud/scp-bypass` | `scenarios/k8s/scp-bypass` |
| `cloud-12` | `k8s-42` | Managed Notebook Front-End Cross-Tenant RCE | `scenarios/cloud/cosmiss-notebook` | `scenarios/k8s/cosmiss-notebook` |
| `cloud-13` | `k8s-43` | Managed PostgreSQL FDW Host File Read | `scenarios/cloud/rds-logfdw` | `scenarios/k8s/rds-logfdw` |
| `cloud-14` | `k8s-44` | Managed PostgreSQL Engine Patch Host RCE | `scenarios/cloud/cloudsql-index-rce` | `scenarios/k8s/cloudsql-index-rce` |
| `cloud-15` | `k8s-45` | Shared Integration Runtime Credentials | `scenarios/cloud/synlapse-ir` | `scenarios/k8s/synlapse-ir` |
| `cloud-16` | `k8s-46` | Managed DB Internal Subnet and CN Bypass | `scenarios/cloud/extrareplica-repl` | `scenarios/k8s/extrareplica-repl` |
| `cloud-17` | `k8s-47` | K8s Host-Agent Bootstrap Secret Theft | `scenarios/cloud/wireserver-bootstrap` | `scenarios/k8s/wireserver-bootstrap` |
| `cloud-18` | `k8s-48` | Build Fleet and Private Registry Overwrite | `scenarios/cloud/buildfleet-registry` | `scenarios/k8s/buildfleet-registry` |
| `cloud-19` | `k8s-49` | Malicious Model Loading to Node Metadata | `scenarios/cloud/pickle-model` | `scenarios/k8s/pickle-model` |
| `cloud-20` | `k8s-50` | Predictable Volume ID Ownership Bypass | `scenarios/cloud/attachme-volume` | `scenarios/k8s/attachme-volume` |
| `cloud-21` | `k8s-51` | Directory Actor Token Identity Confusion | `scenarios/cloud/actor-token` | `scenarios/k8s/actor-token` |
| `cloud-22` | `k8s-52` | Platform Middleware Management Channel | `scenarios/cloud/omigod-agent` | `scenarios/k8s/omigod-agent` |
| `cloud-23` | `k8s-53` | IAM Enumeration AccessDenied Oracle | `scenarios/cloud/iam-enum-oracle` | `scenarios/k8s/iam-enum-oracle` |
| `cloud-24` | `k8s-54` | Private Service Catalog Invisible Write | `scenarios/cloud/beta-endpoint` | `scenarios/k8s/beta-endpoint` |
| `cloud-25` | `k8s-55` | Private Resource Explorer Enumeration | `scenarios/cloud/resource-explorer` | `scenarios/k8s/resource-explorer` |
| `cloud-27` | `k8s-56` | Low-Code Connector Secret Disclosure | `scenarios/cloud/lowcode-secrets` | `scenarios/k8s/lowcode-secrets` |
| `cloud-28` | `k8s-57` | Shared NAT Source-IP Allowlist Bypass | `scenarios/cloud/shared-nat` | `scenarios/k8s/shared-nat` |
| `cloud-29` | `k8s-58` | Managed Data Workflow Path Traversal | `scenarios/cloud/dataform-pt` | `scenarios/k8s/dataform-pt` |
| `cloud-30` | `k8s-59` | Serverless Default Service Account Escalation | `scenarios/cloud/serverless-sa` | `scenarios/k8s/serverless-sa` |
| `cloud-31` | `k8s-60` | Managed Automation Persistence | `scenarios/cloud/persistence-as-a-service` | `scenarios/k8s/persistence-as-a-service` |
