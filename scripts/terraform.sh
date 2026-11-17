#!/usr/bin/env bash
# Runs Terraform on the e2e root, with its backend and variables taken from the
# E2E_* environment that mise sets.
#
# Everything is per instance, so concurrent runs, in a workflow or on one
# machine, do not collide.
#
# Locally Terraform a logged in az session. In a workflow it uses the ARM_*
# variables that provide OIDC federated credentials.
set -euo pipefail

: "${E2E_AZURE_SUBSCRIPTION:?not set, run this with mise}"
: "${E2E_RESOURCE_GROUP:?not set, run this with mise}"
: "${E2E_INSTANCE:?not set, run this with mise}"
: "${E2E_ENABLE_AKS:?not set, run this with mise}"
: "${E2E_ENABLE_CLIENT_CREDENTIALS:?not set, run this with mise}"
: "${E2E_TFSTATE_RESOURCE_GROUP:?not set, run this with mise}"
: "${E2E_TFSTATE_STORAGE_ACCOUNT:?not set, run this with mise}"
: "${E2E_TFSTATE_CONTAINER:?not set, run this with mise}"

dir="test/infra/e2e"

export TF_IN_AUTOMATION=true
export TF_INPUT=0

export TF_DATA_DIR="$PWD/.e2e/terraform/$E2E_INSTANCE"

export TF_VAR_subscription_id="$E2E_AZURE_SUBSCRIPTION"
export TF_VAR_resource_group_name="$E2E_RESOURCE_GROUP"
export TF_VAR_instance="$E2E_INSTANCE"
export TF_VAR_enable_aks="$E2E_ENABLE_AKS"
export TF_VAR_enable_client_credentials="$E2E_ENABLE_CLIENT_CREDENTIALS"

terraform -chdir="$dir" init -input=false -reconfigure \
  -backend-config="subscription_id=$E2E_AZURE_SUBSCRIPTION" \
  -backend-config="resource_group_name=$E2E_TFSTATE_RESOURCE_GROUP" \
  -backend-config="storage_account_name=$E2E_TFSTATE_STORAGE_ACCOUNT" \
  -backend-config="container_name=$E2E_TFSTATE_CONTAINER" \
  -backend-config="key=e2e/$E2E_INSTANCE.tfstate" > /dev/null

args=("$@")
case "${1:-}" in
  apply | destroy) args+=(-auto-approve) ;;
esac

exec terraform -chdir="$dir" "${args[@]}"
