#!/usr/bin/env bash
# Resolves the settings the e2e targets need and exports them. Source it; don't run it.
#
# Every value can be set in the environment, which is how CI supplies them (from
# the GitHub "e2e" environment's variables). Anything unset is found with the
# Azure CLI, so a local run needs only `az login` and access to the test
# subscription:
#
#   AZURE_SUBSCRIPTION_ID    the signed-in account's current subscription
#   TFSTATE_*                the state account in rg-akvi-tfstate
#   OIDC_STORAGE_ACCOUNT     the static-website account in rg-akvi-ci
#   OIDC_SITE_URL            that account's static website endpoint
#
# The resource group names are fixed by the bootstrap stack (test/e2e/README.md).

die() { echo "e2e: $*" >&2; exit 1; }

command -v az >/dev/null || die "the Azure CLI is required"

if [ -z "${AZURE_SUBSCRIPTION_ID:-}" ]; then
  AZURE_SUBSCRIPTION_ID="$(az account show --query id -o tsv 2>/dev/null)" ||
    die "not signed in: run 'az login'"
fi

E2E_RESOURCE_GROUP="${E2E_RESOURCE_GROUP:-rg-akvi-ci}"
TFSTATE_RESOURCE_GROUP="${TFSTATE_RESOURCE_GROUP:-rg-akvi-tfstate}"
TFSTATE_CONTAINER="${TFSTATE_CONTAINER:-tfstate}"

# first_account <resource group> <name prefix>: the one storage account there.
first_account() {
  az storage account list --subscription "$AZURE_SUBSCRIPTION_ID" --resource-group "$1" \
    --query "[?starts_with(name, '$2')].name | [0]" -o tsv 2>/dev/null
}

if [ -z "${TFSTATE_STORAGE_ACCOUNT:-}" ]; then
  TFSTATE_STORAGE_ACCOUNT="$(first_account "$TFSTATE_RESOURCE_GROUP" stakvitfstate)"
  [ -n "$TFSTATE_STORAGE_ACCOUNT" ] ||
    die "no state storage account in $TFSTATE_RESOURCE_GROUP of subscription $AZURE_SUBSCRIPTION_ID: is this the test subscription ('az account set'), and has test/e2e/README.md been followed?"
fi

if [ -z "${OIDC_STORAGE_ACCOUNT:-}" ]; then
  OIDC_STORAGE_ACCOUNT="$(first_account "$E2E_RESOURCE_GROUP" stakvioidc)"
  [ -n "$OIDC_STORAGE_ACCOUNT" ] ||
    die "no OIDC storage account in $E2E_RESOURCE_GROUP: has the bootstrap stack been applied?"
fi

if [ -z "${OIDC_SITE_URL:-}" ]; then
  OIDC_SITE_URL="$(az storage account show --subscription "$AZURE_SUBSCRIPTION_ID" \
    --resource-group "$E2E_RESOURCE_GROUP" --name "$OIDC_STORAGE_ACCOUNT" \
    --query primaryEndpoints.web -o tsv)"
  [ -n "$OIDC_SITE_URL" ] || die "$OIDC_STORAGE_ACCOUNT has no static website endpoint"
fi

# Terraform's provider and backend read these.
export ARM_SUBSCRIPTION_ID="$AZURE_SUBSCRIPTION_ID"
export AZURE_SUBSCRIPTION_ID E2E_RESOURCE_GROUP TFSTATE_RESOURCE_GROUP TFSTATE_CONTAINER \
  TFSTATE_STORAGE_ACCOUNT OIDC_STORAGE_ACCOUNT OIDC_SITE_URL

# The per-run stack's directory and the run's scratch directory, relative to the
# repository root, which every script runs from.
E2E_RUN_DIR="test/e2e/infra/run"
E2E_WORK="test/e2e/.work"
export E2E_RUN_DIR E2E_WORK

# tf_init: point the per-run stack at this run's state blob, and set its
# variables. Every Terraform command for a run goes through here, so apply and
# destroy always get the same variables, including from cleanup.sh, which has
# no .work directory: each value is known from the settings above alone.
tf_init() {
  export TF_VAR_subscription_id="$AZURE_SUBSCRIPTION_ID" \
    TF_VAR_run_id="$RUN_ID" \
    TF_VAR_cluster="${CLUSTER:-kind}" \
    TF_VAR_oidc_storage_account_name="$OIDC_STORAGE_ACCOUNT" \
    TF_VAR_oidc_site_url="$OIDC_SITE_URL" \
    TF_VAR_oidc_jwks_file="$PWD/$E2E_WORK/jwks.json"

  terraform -chdir="$E2E_RUN_DIR" init -input=false -reconfigure \
    -backend-config="resource_group_name=$TFSTATE_RESOURCE_GROUP" \
    -backend-config="storage_account_name=$TFSTATE_STORAGE_ACCOUNT" \
    -backend-config="container_name=$TFSTATE_CONTAINER" \
    -backend-config="key=run/$RUN_ID.tfstate"
}
