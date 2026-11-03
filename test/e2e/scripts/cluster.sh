#!/usr/bin/env bash
# Creates or deletes the cluster the e2e tests run on: `cluster.sh up|down`.
# Run through `make cluster-up` and `make cluster-down`, which set CLUSTER (kind
# or aks), E2E_CLUSTER and E2E_KUBECONFIG. This is the only place that branches
# on the cluster type, apart from the infrastructure scripts.
set -euo pipefail
cd "$(dirname "$0")/../../.."
# shellcheck source=config.sh
source test/e2e/scripts/config.sh

output() { jq -er ".$1.value" "$E2E_WORK/outputs.json"; }

case "${CLUSTER:-kind}/${1:?usage: cluster.sh up|down}" in
  kind/up)
    # The API server signs service-account tokens with the RSA key kubeadm
    # generates (Entra accepts only RS256) and names the run's issuer on the
    # static website. Its JWKS is saved for 'make e2e-infra-up' to publish
    # there, so Entra can verify the tokens. The private key never leaves the
    # node.
    : "${RUN_ID:?}"
    issuer="${OIDC_SITE_URL%/}/$RUN_ID"
    mkdir -p "$E2E_WORK"
    kind create cluster --name "$E2E_CLUSTER" --kubeconfig "$E2E_KUBECONFIG" --config - <<EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    kubeadmConfigPatches:
      - |
        kind: ClusterConfiguration
        encryptionAlgorithm: RSA-2048
        apiServer:
          extraArgs:
            - name: service-account-issuer
              value: $issuer
            - name: service-account-jwks-uri
              value: $issuer/openid/v1/jwks
EOF
    kubectl --kubeconfig "$E2E_KUBECONFIG" get --raw /openid/v1/jwks > "$E2E_WORK/jwks.json"
    ;;
  kind/down)
    kind delete cluster --name "$E2E_CLUSTER" --kubeconfig "$E2E_KUBECONFIG"
    ;;
  aks/up)
    # Terraform made the cluster. This gets a kubeconfig that holds no
    # credential: kubelogin asks the signed-in Azure CLI for a token. The suite
    # signs in to the registry itself, each time it pushes the image. The file
    # is this run's alone, and is removed first: a kind run before this one
    # leaves an empty stub that az refuses to merge into.
    rm -f "$E2E_KUBECONFIG"
    az aks get-credentials --resource-group "$E2E_RESOURCE_GROUP" --name "$(output aks_name)" \
      --file "$E2E_KUBECONFIG" --overwrite-existing
    kubelogin convert-kubeconfig --login azurecli --kubeconfig "$E2E_KUBECONFIG"
    ;;
  aks/down)
    rm -f "$E2E_KUBECONFIG" # Terraform destroys the cluster itself.
    ;;
  *)
    echo "e2e: cluster.sh up|down with CLUSTER=kind or aks" >&2
    exit 1
    ;;
esac
