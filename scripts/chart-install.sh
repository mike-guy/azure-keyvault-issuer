#!/usr/bin/env bash
# Installs the chart into the e2e cluster, or upgrades it, and restarts the
# controller. Safe to run again.
#
#   chart-install.sh kind   the image that e2e:kind:image:load loaded, never pulled
#   chart-install.sh aks    the image that e2e:aks:image:push pushed to the registry
#
# The controller is given the managed identity, which is what an
# AzureKeyVaultClusterIssuer with no auth block signs in with. kind has it only
# when e2e:infra:apply has run and the cluster was made to sign as its issuer.
set -euo pipefail

platform="${1:?usage: chart-install.sh kind|aks}"

: "${E2E_ALLOW_CONTEXT:?not set, run this with mise}"
: "${E2E_CONTROLLER_NAMESPACE:?not set, run this with mise}"

release="azure-keyvault-issuer"
client_id_annotation="serviceAccount.annotations.azure\.workload\.identity/client-id"

case "$platform" in
  kind)
    values=(--values test/e2e/chart-values.yaml)
    if [[ -n "${E2E_KIND_OIDC_ISSUER_URL:-}" ]]; then
      values+=(--values test/e2e/chart-values-workload-identity.yaml
        --set-string "$client_id_annotation=${E2E_KIND_CLIENT_ID:?not set, run e2e:infra:apply first}")
    fi
    ;;
  aks)
    # The tag does not change between builds, so the pull policy is Always and the restart below pulls the new image.
    values=(--values test/e2e/chart-values-workload-identity.yaml
      --set-string "image.repository=${E2E_ACR_LOGIN_SERVER:?not set, run e2e:infra:apply with E2E_ENABLE_AKS=true}/azure-keyvault-issuer"
      --set-string image.tag=e2e --set-string image.pullPolicy=Always
      --set-string "$client_id_annotation=${E2E_AKS_CLIENT_ID:?not set, run e2e:infra:apply first}")
    ;;
  *)
    echo "unknown platform $platform: use kind or aks" >&2
    exit 1
    ;;
esac

helm upgrade --install "$release" charts/azure-keyvault-issuer \
  --kube-context "$E2E_ALLOW_CONTEXT" --namespace "$E2E_CONTROLLER_NAMESPACE" --create-namespace \
  "${values[@]}" --wait
# The image tag does not change between builds, so Helm sees nothing to roll out.
kubectl --context "$E2E_ALLOW_CONTEXT" --namespace "$E2E_CONTROLLER_NAMESPACE" rollout restart "deployment/$release"
kubectl --context "$E2E_ALLOW_CONTEXT" --namespace "$E2E_CONTROLLER_NAMESPACE" rollout status "deployment/$release"
