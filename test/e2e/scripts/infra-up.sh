#!/usr/bin/env bash
# Creates the per-run e2e infrastructure.
# Run through `make e2e-infra-up`, which sets RUN_ID and CLUSTER (kind or aks).
set -euo pipefail
cd "$(dirname "$0")/../../.."
: "${RUN_ID:?}"
CLUSTER="${CLUSTER:-kind}"
case "$CLUSTER" in kind | aks) ;; *) echo "e2e: CLUSTER must be kind or aks, not $CLUSTER" >&2; exit 1 ;; esac
# shellcheck source=config.sh
source test/e2e/scripts/config.sh

mkdir -p "$E2E_WORK"

# For kind, the cluster comes first ('make e2e-up' runs cluster-up before
# this): its API server's JWKS, in .work/jwks.json, is published here. AKS
# publishes its own.
tf_init
terraform -chdir="$E2E_RUN_DIR" apply -auto-approve -input=false
terraform -chdir="$E2E_RUN_DIR" output -json > "$E2E_WORK/outputs.json"
