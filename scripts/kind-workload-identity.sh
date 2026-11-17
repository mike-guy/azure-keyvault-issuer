#!/usr/bin/env bash
# Sets the kind cluster up for workload identity, when e2e:infra:apply has run.
# Safe to run again. It does nothing without E2E_KIND_OIDC_ISSUER_URL.
#
# 1. Publishes the cluster's OpenID discovery document and keys at the issuer
#    URL, in the storage account's static website. Entra fetches them from there
#    to check the signature on a ServiceAccount token. The keys do not change
#    for the life of the cluster, so this is only needed once, but is repeated
#    for a cluster that was made again.
# 2. Installs the Azure workload identity webhook, which gives a pod labelled
#    azure.workload.identity/use the identity of its ServiceAccount, as AKS does.
#    Only the ambient identity needs it: an issuer that names a ServiceAccount
#    makes its own token request.
set -euo pipefail

: "${E2E_CLUSTER:?not set, run this with mise}"
: "${E2E_ALLOW_CONTEXT:?not set, run this with mise}"
: "${E2E_AZURE_SUBSCRIPTION:?not set, run this with mise}"
: "${WORKLOAD_IDENTITY_WEBHOOK_VERSION:?not set, run this with mise}"

issuer="${E2E_KIND_OIDC_ISSUER_URL:-}"
if [[ -z "$issuer" ]]; then
  echo "E2E_KIND_OIDC_ISSUER_URL is not set, so the kind cluster has no workload identity: run e2e:azure:provision, then make the cluster again"
  exit 0
fi
: "${E2E_OIDC_STORAGE_ACCOUNT:?not set, run e2e:infra:apply first}"
: "${E2E_TENANT_ID:?not set, run e2e:infra:apply first}"

context="$E2E_ALLOW_CONTEXT"

current="$(kubectl --context "$context" get --raw /.well-known/openid-configuration | jq -r .issuer)"
[[ "$current" == "$issuer" ]] \
  || { echo "the cluster signs tokens as $current, not $issuer: run e2e:kind:cluster:delete and make it again" >&2; exit 1; }

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
kubectl --context "$context" get --raw /.well-known/openid-configuration > "$work/openid-configuration"
kubectl --context "$context" get --raw /openid/v1/jwks > "$work/jwks"

# The issuer is the static website's address and a path, and the container behind it is $web.
path="${issuer#*://*/}"
# shellcheck disable=SC2016 # $web is the container's name, not a variable.
for pair in "openid-configuration:${path}.well-known/openid-configuration" "jwks:${path}openid/v1/jwks"; do
  az storage blob upload --subscription "$E2E_AZURE_SUBSCRIPTION" --account-name "$E2E_OIDC_STORAGE_ACCOUNT" \
    --auth-mode login --container-name '$web' --file "$work/${pair%%:*}" --name "${pair#*:}" \
    --content-type application/json --overwrite --only-show-errors --output none
done
echo "published the discovery document and keys at $issuer"

helm repo add azure-workload-identity https://azure.github.io/azure-workload-identity/charts --force-update > /dev/null
helm upgrade --install workload-identity-webhook azure-workload-identity/workload-identity-webhook \
  --kube-context "$context" --namespace azure-workload-identity-system --create-namespace \
  --version "$WORKLOAD_IDENTITY_WEBHOOK_VERSION" --set azureTenantID="$E2E_TENANT_ID" --wait
