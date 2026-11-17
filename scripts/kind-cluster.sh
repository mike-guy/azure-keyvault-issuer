#!/usr/bin/env bash
# Makes the kind cluster for the e2e suite, if it does not exist.
#
# When e2e:infra:apply has run, E2E_KIND_OIDC_ISSUER_URL is set, and the
# cluster is made to sign its ServiceAccount tokens as that issuer, with the
# keys discoverable at its address. Entra can then trust the tokens, which is
# what workload identity needs. kind-workload-identity.sh publishes the
# discovery documents there. Without the URL the cluster is plain, and needs no
# Azure.
set -euo pipefail

: "${E2E_CLUSTER:?not set, run this with mise}"
issuer="${E2E_KIND_OIDC_ISSUER_URL:-}"
context="kind-$E2E_CLUSTER"

if kind get clusters | grep -qx "$E2E_CLUSTER"; then
  if [[ -n "$issuer" ]]; then
    current="$(kubectl --context "$context" get --raw /.well-known/openid-configuration | jq -r .issuer)"
    [[ "$current" == "$issuer" ]] \
      || { echo "cluster $E2E_CLUSTER signs tokens as $current, not $issuer: run e2e:kind:cluster:delete and make it again" >&2; exit 1; }
  fi
  echo "cluster $E2E_CLUSTER exists"
  exit 0
fi

if [[ -z "$issuer" ]]; then
  kind create cluster --name "$E2E_CLUSTER"
  exit 0
fi

# The issuer ends in a slash, so the keys are at a path below it.
config="$(mktemp)"
trap 'rm -f "$config"' EXIT
cat > "$config" <<EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
kubeadmConfigPatches:
  - |
    kind: ClusterConfiguration
    apiServer:
      extraArgs:
        service-account-issuer: ${issuer}
        service-account-jwks-uri: ${issuer}openid/v1/jwks
EOF
kind create cluster --name "$E2E_CLUSTER" --config "$config"
