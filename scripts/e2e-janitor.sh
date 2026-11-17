#!/usr/bin/env bash
# Destroys the Azure resources of CI e2e runs that never cleaned up, because
# their runner may have died before the destroy step.
#
# Every instance keeps its Terraform state in e2e/<instance>.tfstate. CI
# instances are named ci<hash>, and each job of a run has its own, so a stale
# state blob is one job's leak. A state that still lists resources is destroyed
# with Terraform, which also removes the instance's Entra applications; a state
# that lists none is only an empty leftover. Either way the blob is then
# deleted.
#
# MAX_AGE_HOURS (default 24) is how old a state must be to count as abandoned.
# The longest job takes 90 minutes, so nothing live is touched.
#
# Developers' own instances (dev<hash>) are left alone.
set -euo pipefail

: "${E2E_TFSTATE_STORAGE_ACCOUNT:?not set, run this with mise}"
: "${E2E_TFSTATE_CONTAINER:?not set, run this with mise}"

MAX_AGE_HOURS="${MAX_AGE_HOURS:-24}"

# An RFC 3339 cutoff compares correctly as text. GNU date first, then BSD.
cutoff="$(date -u -d "-$MAX_AGE_HOURS hours" +%Y-%m-%dT%H:%M:%S 2> /dev/null ||
  date -u -v-"${MAX_AGE_HOURS}"H +%Y-%m-%dT%H:%M:%S)"
echo "janitor: removing instances last changed before $cutoff"

blob_args=(--auth-mode login --account-name "$E2E_TFSTATE_STORAGE_ACCOUNT" --container-name "$E2E_TFSTATE_CONTAINER")

# Listed on its own, so that a failure (an expired login, say) is reported
# rather than looking like a clean sweep.
listing="$(az storage blob list "${blob_args[@]}" --prefix e2e/ci \
  --query "[].[properties.lastModified, name]" -o tsv)" || {
  echo "janitor: could not list the state blobs in $E2E_TFSTATE_STORAGE_ACCOUNT" >&2
  exit 1
}
stale="$(awk -F'\t' -v cutoff="$cutoff" 'substr($1, 1, 19) < cutoff { print $2 }' <<< "$listing")"

failed=0
state_file="$(mktemp)"
trap 'rm -f "$state_file"' EXIT

for blob in $stale; do
  instance="$(basename "$blob" .tfstate)"

  # A runner killed while Terraform held the lock leaves the blob leased. The
  # state is old, so the lock can only be a dead runner's. Breaking a lease
  # that is not there fails harmlessly.
  if az storage blob lease break "${blob_args[@]}" --blob-name "$blob" --lease-break-period 0 \
    --output none 2> /dev/null; then
    echo "janitor: broke the state lock of $instance"
  fi

  if ! az storage blob download "${blob_args[@]}" --name "$blob" --file "$state_file" \
    --no-progress --output none; then
    echo "janitor: could not read the state of $instance" >&2
    failed=1
    continue
  fi

  if jq -e '.resources | length > 0' "$state_file" > /dev/null; then
    # Destroy has to know whether the run built AKS, or it skips the cluster.
    aks=false
    if jq -e '[.resources[] | select(.type == "azurerm_kubernetes_cluster")] | length > 0' "$state_file" > /dev/null; then
      aks=true
    fi
    echo "janitor: destroying $instance (aks=$aks)"
    if ! E2E_INSTANCE="$instance" E2E_ENABLE_AKS="$aks" mise run e2e:infra:destroy; then
      echo "janitor: could not destroy $instance, its state is kept for the next run" >&2
      failed=1
      continue
    fi
  fi

  az storage blob delete "${blob_args[@]}" --name "$blob" --output none || failed=1
done

exit "$failed"
