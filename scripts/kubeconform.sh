#!/usr/bin/env bash
# Validates the chart, rendered with every ci/ values file, against the
# Kubernetes API of each supported version.
set -euo pipefail

chart="charts/azure-keyvault-issuer"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

for values in "$chart"/ci/*-values.yaml; do
  helm template release "$chart" --namespace default -f "$values" > "$tmp/$(basename "$values")"
done

# The CRDs are checked by envtest, so only the ServiceMonitor needs a schema beyond the built-in ones.
for version in 1.35.0 1.36.0 1.37.0; do
  kubeconform -strict -summary -kubernetes-version "$version" \
    -schema-location default \
    -schema-location 'https://raw.githubusercontent.com/datreeio/CRDs-catalog/main/{{.Group}}/{{.ResourceKind}}_{{.ResourceAPIVersion}}.json' \
    -skip CustomResourceDefinition \
    "$tmp"/*.yaml
done
