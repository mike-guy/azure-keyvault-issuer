#!/usr/bin/env bash
# Destroys the per-run e2e infrastructure and deletes its state blob.
# Run through `make e2e-infra-down`, which sets RUN_ID and CLUSTER (kind or aks).
set -euo pipefail
cd "$(dirname "$0")/../../.."
: "${RUN_ID:?}"
CLUSTER="${CLUSTER:-kind}"
# shellcheck source=config.sh
source test/e2e/scripts/config.sh

tf_init

# The run's Entra application and service principal, read before the destroy
# forgets them. Entra keeps deleted objects for 30 days, where they still count
# towards the creator's directory quota, so they are purged afterwards.
entra_objects=""
for output in fallback_application_object_id fallback_service_principal_object_id; do
  id="$(terraform -chdir="$E2E_RUN_DIR" output -raw "$output" 2>/dev/null)" && entra_objects="$entra_objects $id"
done

terraform -chdir="$E2E_RUN_DIR" destroy -auto-approve -input=false

# Best effort: a failure here leaves the object to expire after 30 days, and
# must not fail the teardown. Entra can take a few seconds to list an object
# it has just deleted, so each purge is retried briefly.
for id in $entra_objects; do
  for attempt in 1 2 3 4 5 6; do
    if az rest --method DELETE --url "https://graph.microsoft.com/v1.0/directory/deletedItems/$id" \
      --output none 2>/dev/null; then
      echo "e2e: purged deleted Entra object $id"
      break
    fi
    [ "$attempt" = 6 ] && echo "e2e: could not purge deleted Entra object $id; it expires in 30 days" >&2
    sleep 5
  done
done

# A run that failed before creating any state has no blob to delete.
az storage blob delete --auth-mode login --account-name "$TFSTATE_STORAGE_ACCOUNT" \
  --container-name "$TFSTATE_CONTAINER" --name "run/$RUN_ID.tfstate" --output none ||
  echo "e2e: no state blob run/$RUN_ID.tfstate to delete" >&2
