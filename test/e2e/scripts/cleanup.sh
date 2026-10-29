#!/usr/bin/env bash
# Cleans up after e2e runs whose runner died before it could destroy them.
# Run through `make e2e-cleanup`; MAX_AGE_HOURS (default 6) is how old a run
# must be before it counts as abandoned. The longest job is under an hour, so
# nothing live is touched.
#
#   1. Every run's Terraform state is a blob under run/ in the state container.
#      An old one is a run that never finished, so it gets a real `terraform
#      destroy` through infra-down.sh, which also deletes the blob. A runner
#      killed while Terraform held the state lock leaves the blob leased, so
#      the lease is broken first, as `terraform force-unlock` would.
#   2. A backstop for anything the state doesn't know about: resources in
#      rg-akvi-ci whose created_at tag is old, and OIDC documents and Entra
#      applications with no state blob.
set -euo pipefail
cd "$(dirname "$0")/../../.."
# shellcheck source=config.sh
source test/e2e/scripts/config.sh

# shellcheck disable=SC2016 # The static website's container is literally named $web.
web_container='$web'
MAX_AGE_HOURS="${MAX_AGE_HOURS:-6}"
# An RFC 3339 cutoff compares correctly as text (see older_than). GNU date
# first, then BSD.
cutoff="$(date -u -d "-$MAX_AGE_HOURS hours" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null ||
  date -u -v-"${MAX_AGE_HOURS}"H +%Y-%m-%dT%H:%M:%SZ)"
echo "cleanup: removing runs older than $cutoff"

# older_than reads "<timestamp><TAB><value>" lines and prints the values whose
# timestamp is before the cutoff. JMESPath can't order strings (a "<" on them is
# null, so a query that did it would match nothing and look like a clean sweep),
# so the comparison is made here. Both are UTC, and are compared to the second,
# which leaves out the offset az adds to a blob's time.
older_than() {
  awk -F'\t' -v cutoff="${cutoff:0:19}" 'substr($1, 1, 19) < cutoff { print $2 }'
}

state_blobs() {
  az storage blob list --auth-mode login --account-name "$TFSTATE_STORAGE_ACCOUNT" \
    --container-name "$TFSTATE_CONTAINER" --prefix run/ "$@"
}

failed=0

# 1. Abandoned runs, destroyed from their state. As in 2a, the listing is kept
# out of the loop's word list so that a failure (an expired az login, say) is
# reported rather than looking like a clean sweep.
old_blobs="$(state_blobs --query "[].[properties.lastModified, name]" -o tsv | older_than)" || {
  echo "cleanup: could not list the state blobs in $TFSTATE_STORAGE_ACCOUNT" >&2
  old_blobs=""
  failed=1
}
for blob in $old_blobs; do
  run_id="$(basename "$blob" .tfstate)"
  # The state says which cluster the run used, and destroy needs to know. It
  # goes through a temporary file: az takes "--file -" to mean a file called
  # "-", not stdout, which left a copy of the state in the working directory.
  cluster=kind
  state_file="$(mktemp)"
  if az storage blob download --auth-mode login --account-name "$TFSTATE_STORAGE_ACCOUNT" \
    --container-name "$TFSTATE_CONTAINER" --name "$blob" --file "$state_file" --no-progress --output none &&
    jq -e '[.resources[] | select(.type == "azurerm_kubernetes_cluster")] | length > 0' "$state_file" >/dev/null; then
    cluster=aks
  fi
  rm -f "$state_file"

  # Breaking a lease that isn't there fails harmlessly. The run is hours old,
  # so the lock can only be a dead runner's.
  if az storage blob lease break --auth-mode login --account-name "$TFSTATE_STORAGE_ACCOUNT" \
    --container-name "$TFSTATE_CONTAINER" --blob-name "$blob" --lease-break-period 0 \
    --output none 2>/dev/null; then
    echo "cleanup: broke the state lock of $run_id"
  fi

  echo "cleanup: destroying $run_id ($cluster)"
  RUN_ID="$run_id" CLUSTER="$cluster" test/e2e/scripts/infra-down.sh || {
    echo "cleanup: could not destroy $run_id; its state is kept for the next run" >&2
    failed=1
  }
done

# 2a. Tagged resources the state doesn't cover. Deleting a vault soft-deletes it,
# and the retention expires it without cost. az refuses --tag together with
# --resource-group, so the tags are filtered in the query. Only the per-run
# stack sets created_at, so the persistent bootstrap resources never match. The
# listing is kept out of the loop's word list: a failure there would otherwise
# end the loop with nothing to do, and no sign that the backstop didn't run.
stale="$(az resource list --subscription "$AZURE_SUBSCRIPTION_ID" --resource-group "$E2E_RESOURCE_GROUP" \
  --query "[?tags.purpose == 'e2e' && tags.created_at && tags.created_at != 'unknown'].[tags.created_at, id]" \
  -o tsv | older_than)" || {
  echo "cleanup: could not list resources in $E2E_RESOURCE_GROUP" >&2
  stale=""
  failed=1
}
for id in $stale; do
  echo "cleanup: deleting $id"
  az resource delete --ids "$id" --output none || failed=1
done

# 2b. OIDC documents under a run ID that has no state blob any more.
# If either listing fails, nothing is deleted: without the state listing every
# prefix would look orphaned, and a live run's documents would go.
if live="$(state_blobs --query '[].name' -o tsv)" &&
  old_docs="$(az storage blob list --auth-mode login --account-name "$OIDC_STORAGE_ACCOUNT" \
    --container-name "$web_container" --query "[].[properties.lastModified, name]" -o tsv | older_than)"; then
  prefixes="$(cut -d/ -f1 <<<"$old_docs" | sort -u)"
else
  echo "cleanup: could not list the OIDC documents or state blobs" >&2
  live="" prefixes="" failed=1
fi
for prefix in $prefixes; do
  if ! grep -qx "run/$prefix.tfstate" <<<"$live"; then
    echo "cleanup: deleting OIDC documents for $prefix"
    az storage blob delete-batch --auth-mode login --account-name "$OIDC_STORAGE_ACCOUNT" \
      --source "$web_container" --pattern "$prefix/*" --output none || failed=1
  fi
done

# 2c. Entra applications from runs with no state blob any more. Each run's is
# named akvi-e2e-<run ID>. CI may list and delete only the applications it owns,
# which are exactly these. Deleting an application also deletes its service
# principal; both then wait 30 days in Entra's deleted items, which infra-down.sh
# purges but this backstop leaves to expire. As in 2b, nothing is deleted if
# either listing fails.
if live="$(state_blobs --query '[].name' -o tsv)" &&
  old_apps="$(az ad app list --filter "startswith(displayName,'akvi-e2e-')" \
    --query "[].[createdDateTime, join('/', [id, displayName])]" -o tsv | older_than)"; then
  :
else
  echo "cleanup: could not list the e2e Entra applications or state blobs" >&2
  old_apps="" failed=1
fi
for app in $old_apps; do
  id="${app%%/*}" run_id="${app#*/akvi-e2e-}"
  if ! grep -qx "run/$run_id.tfstate" <<<"$live"; then
    echo "cleanup: deleting Entra application akvi-e2e-$run_id"
    az ad app delete --id "$id" --output none || failed=1
  fi
done

exit "$failed"
