# Scenario ID Migration

This benchmark separates scenario semantics by directory and keeps the
historical evaluation IDs traceable through two renumbering steps.

- `scenarios/cloud/` contains public-cloud scenarios only.
- `scenarios/k8s/` contains all private-cloud scenarios, regardless of delivery type.
- The private-cloud identifiers are now grouped into the paper's main set
  `k8s-01..k8s-40` and reserve set `k8s-41..k8s-60`.
- Scenario directories remain semantic; only stable IDs and persisted ID
  references changed.

Flags use the final scenario ID as their prefix. Dependencies that persist
scenario IDs should use the final mapping below.

## Public cloud renumbering

| Old ID | New ID | Scenario | Path |
|---|---|---|---|
| `cloud-11` | `cloud-01` | Global S3 Namespace Squatting | `scenarios/cloud/global-s3-squatting` |
| `cloud-26` | `cloud-02` | Dependency Confusion in Managed Data Platform | `scenarios/cloud/composer-depconf` |

## Private cloud migration from the original evaluation IDs

The 29 scenarios migrated from the former `cloud-*` namespace now use the
following final private-cloud IDs.

| Old ID | New ID | Scenario | Old path | New path |
|---|---|---|---|---|
| `cloud-01` | `k8s-41` | SSRF to Instance Metadata Credential Theft | `scenarios/cloud/ssrf-to-imds` | `scenarios/k8s/ssrf-to-imds` |
| `cloud-02` | `k8s-23` | CAP_NET_RAW to Metadata MITM | `scenarios/cloud/cap-netraw-metadata` | `scenarios/k8s/cap-netraw-metadata` |
| `cloud-03` | `k8s-47` | Serverless Code Injection to IAM PassRole | `scenarios/cloud/lambda-passrole` | `scenarios/k8s/lambda-passrole` |
| `cloud-04` | `k8s-13` | Private IaC Template Injection | `scenarios/cloud/cf-injection` | `scenarios/k8s/cf-injection` |
| `cloud-05` | `k8s-48` | Private CI/CD Pipeline Poisoning | `scenarios/cloud/ci-poisoning` | `scenarios/k8s/ci-poisoning` |
| `cloud-06` | `k8s-25` | Managed Notebook Escape | `scenarios/cloud/notebook-escape` | `scenarios/k8s/notebook-escape` |
| `cloud-07` | `k8s-49` | OIDC Claim Mismatch | `scenarios/cloud/oidc-federation` | `scenarios/k8s/oidc-federation` |
| `cloud-08` | `k8s-05` | IAM Cross-Project Trust Policy Takeover | `scenarios/cloud/cross-account-trust` | `scenarios/k8s/cross-account-trust` |
| `cloud-09` | `k8s-06` | Golden SAML Trust-Root Compromise | `scenarios/cloud/golden-saml` | `scenarios/k8s/golden-saml` |
| `cloud-10` | `k8s-07` | Tenant Policy Bypass via Legacy API | `scenarios/cloud/scp-bypass` | `scenarios/k8s/scp-bypass` |
| `cloud-12` | `k8s-50` | Managed Notebook Front-End Cross-Tenant RCE | `scenarios/cloud/cosmiss-notebook` | `scenarios/k8s/cosmiss-notebook` |
| `cloud-13` | `k8s-33` | Managed PostgreSQL FDW Host File Read | `scenarios/cloud/rds-logfdw` | `scenarios/k8s/rds-logfdw` |
| `cloud-14` | `k8s-34` | Managed PostgreSQL Engine Patch Host RCE | `scenarios/cloud/cloudsql-index-rce` | `scenarios/k8s/cloudsql-index-rce` |
| `cloud-15` | `k8s-35` | Shared Integration Runtime Credentials | `scenarios/cloud/synlapse-ir` | `scenarios/k8s/synlapse-ir` |
| `cloud-16` | `k8s-51` | Managed DB Internal Subnet and CN Bypass | `scenarios/cloud/extrareplica-repl` | `scenarios/k8s/extrareplica-repl` |
| `cloud-17` | `k8s-26` | K8s Host-Agent Bootstrap Secret Theft | `scenarios/cloud/wireserver-bootstrap` | `scenarios/k8s/wireserver-bootstrap` |
| `cloud-18` | `k8s-40` | Build Fleet and Private Registry Overwrite | `scenarios/cloud/buildfleet-registry` | `scenarios/k8s/buildfleet-registry` |
| `cloud-19` | `k8s-27` | Malicious Model Loading to Node Metadata | `scenarios/cloud/pickle-model` | `scenarios/k8s/pickle-model` |
| `cloud-20` | `k8s-52` | Predictable Volume ID Ownership Bypass | `scenarios/cloud/attachme-volume` | `scenarios/k8s/attachme-volume` |
| `cloud-21` | `k8s-53` | Directory Actor Token Identity Confusion | `scenarios/cloud/actor-token` | `scenarios/k8s/actor-token` |
| `cloud-22` | `k8s-54` | Platform Middleware Management Channel | `scenarios/cloud/omigod-agent` | `scenarios/k8s/omigod-agent` |
| `cloud-23` | `k8s-55` | IAM Enumeration AccessDenied Oracle | `scenarios/cloud/iam-enum-oracle` | `scenarios/k8s/iam-enum-oracle` |
| `cloud-24` | `k8s-56` | Private Service Catalog Invisible Write | `scenarios/cloud/beta-endpoint` | `scenarios/k8s/beta-endpoint` |
| `cloud-25` | `k8s-57` | Private Resource Explorer Enumeration | `scenarios/cloud/resource-explorer` | `scenarios/k8s/resource-explorer` |
| `cloud-27` | `k8s-36` | Low-Code Connector Secret Disclosure | `scenarios/cloud/lowcode-secrets` | `scenarios/k8s/lowcode-secrets` |
| `cloud-28` | `k8s-58` | Shared NAT Source-IP Allowlist Bypass | `scenarios/cloud/shared-nat` | `scenarios/k8s/shared-nat` |
| `cloud-29` | `k8s-59` | Managed Data Workflow Path Traversal | `scenarios/cloud/dataform-pt` | `scenarios/k8s/dataform-pt` |
| `cloud-30` | `k8s-60` | Serverless Default Service Account Escalation | `scenarios/cloud/serverless-sa` | `scenarios/k8s/serverless-sa` |
| `cloud-31` | `k8s-37` | Managed Automation Persistence | `scenarios/cloud/persistence-as-a-service` | `scenarios/k8s/persistence-as-a-service` |

## Final private-cloud renumbering

The left side is the private-cloud ID used immediately before the paper
selection; the right side is the final benchmark ID. The first 40 scenarios
form the paper evaluation set and are grouped by mechanism family. The last
20 are retained as reserve scenarios.

### Main set: `k8s-01..k8s-40`

```text
01←06, 02←25, 03←26, 04←32, 05←39, 06←40, 07←41,
08←07, 09←10, 10←20, 11←21, 12←24, 13←35,
14←01, 15←02, 16←03, 17←05, 18←11, 19←12, 20←14,
21←17, 22←23, 23←31, 24←33, 25←37, 26←47, 27←49,
28←22, 29←27, 30←28, 31←29, 32←30,
33←43, 34←44, 35←45, 36←56, 37←60,
38←09, 39←15, 40←48
```

The main set contains 26 original private-cloud scenarios and 14 migrated
private-cloud scenarios. The scenarios that used the pre-renumbering IDs
`k8s-08`, `k8s-13`, `k8s-16`, `k8s-18`, and `k8s-19` are now the reserve IDs
`k8s-42`, `k8s-43`, `k8s-44`, `k8s-45`, and `k8s-46`.

### Reserve set: `k8s-41..k8s-60`

```text
41←04, 42←08, 43←13, 44←16, 45←18, 46←19,
47←34, 48←36, 49←38, 50←42, 51←46, 52←50,
53←51, 54←52, 55←53, 56←54, 57←55, 58←57,
59←58, 60←59
```
