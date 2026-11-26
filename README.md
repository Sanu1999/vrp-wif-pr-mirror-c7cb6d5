# Synthetic fork-approval / WIF deployment boundary mirror

This repository contains only synthetic CI fixtures. It is not Google production code and contains no credentials.

The tests compare:

1. Unprivileged `pull_request` CI with only `contents: read` and no Skaffold execution.
2. Privileged `workflow_run` deployment with `id-token: write`, a fork-head checkout, and Skaffold custom-builder execution.
3. A lab-only OIDC/WIF service identity and generated IAM markers in a researcher-owned synthetic GCP project.

All present code is benign base-branch code. Later proof-of-concept changes must remain entirely synthetic and specifically authorized.
