# Cloud chain runtime

Cloud chain `deploy.sh` scripts use `deploy_chain.py` to start each referenced
Docker scenario without publishing its original host ports. Containers are
joined to a chain-specific bridge and exposed through one chain console at
`http://localhost:11600+<chain number>`.

The console proxies each step under `/step/<n>/` and records successful step
responses at `/artifacts/step-<n>-output`. Artifact requests require the chain
key in `X-Chain-Key`; the key is printed by the deployment environment and is
also available to chain smoke scripts.
