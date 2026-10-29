# Setting up Azure for the end-to-end tests

The e2e tests run against a real, dedicated Azure subscription. This page is the
one-off set-up, done by an administrator. How to run the tests, and how the
environment is built, are in [CONTRIBUTING.md](../../CONTRIBUTING.md#end-to-end-tests)
and [ARCHITECTURE.md](../../ARCHITECTURE.md#end-to-end-infrastructure).

There are three one-off steps. After them, CI creates and destroys its own
resources with the `run` stack and needs no administrator.

1. Create a storage account for Terraform state, with `az`.
2. Apply the `bootstrap` Terraform stack, which registers the resource providers
   and creates everything CI needs.
3. Create the GitHub `e2e` environment and its variables, with `gh`.

| Stack | Applied | By | Holds |
|---|---|---|---|
| State storage account (step 1) | Once | Administrator, with `az` | Terraform state for both stacks |
| `test/e2e/infra/bootstrap` | Once, and again when it changes | Administrator | Resource providers, resource group, custom role, CI identity and its Microsoft Graph permission, OIDC static website |
| `test/e2e/infra/run` | Every e2e job | CI | Key Vault, test identities, an Entra application for the fallback auth scenarios, kind OIDC documents or an AKS cluster |

## Prerequisites

- The Azure CLI, the GitHub CLI, Terraform and `mise` (`make tools`).
- **Owner** on the test subscription, or Contributor plus User Access
  Administrator. The bootstrap stack creates a custom role and role assignments.
- **Privileged Role Administrator** or **Global Administrator** in the Entra
  tenant, for one admin consent: the bootstrap stack grants CI the Microsoft Graph
  permission `Application.ReadWrite.OwnedBy` (see [What CI is allowed to
  do](#what-ci-is-allowed-to-do)).

## 1. Create the state storage account

Shared-key access is off, so every user, including CI, needs a data-plane role.

```sh
SUBSCRIPTION=<test subscription id>
LOCATION=northeurope
STATE_RG=rg-akvi-tfstate
STATE_SA=stakvitfstate$(openssl rand -hex 3)   # 3-24 lowercase letters and digits, globally unique

az login
az account set --subscription "$SUBSCRIPTION"

az group create --name "$STATE_RG" --location "$LOCATION"

az storage account create \
  --name "$STATE_SA" --resource-group "$STATE_RG" --location "$LOCATION" \
  --kind StorageV2 --sku Standard_LRS \
  --min-tls-version TLS1_2 --https-only true \
  --allow-blob-public-access false --allow-shared-key-access false

SA_ID=$(az storage account show --name "$STATE_SA" --resource-group "$STATE_RG" --query id -o tsv)
az role assignment create \
  --assignee-object-id "$(az ad signed-in-user show --query id -o tsv)" \
  --assignee-principal-type User \
  --role "Storage Blob Data Contributor" --scope "$SA_ID"

# The role can take a minute or two to apply. Retry if this is refused.
az storage container create --name tfstate --account-name "$STATE_SA" --auth-mode login

echo "$STATE_SA"   # you need this name in step 2
```

The resource group and storage account names matter: `test/e2e/scripts/config.sh`
finds the state account by the `stakvitfstate` prefix in `rg-akvi-tfstate`.

## 2. Apply the bootstrap stack

The administrator has subscription-level rights, so this stack registers the
resource providers the tests use (including `Microsoft.ContainerService` and
`Microsoft.ContainerRegistry`, for the AKS job). The per-run stack runs as CI, which
has none, and registers nothing; it relies on this step.

Create two git-ignored files in `test/e2e/infra/bootstrap/`, with your values:

```hcl
# backend.hcl
resource_group_name  = "rg-akvi-tfstate"
storage_account_name = "<the name from step 1>"
container_name       = "tfstate"
key                  = "bootstrap.tfstate"
```

```hcl
# bootstrap.tfvars
subscription_id            = "<test subscription id>"
state_resource_group_name  = "rg-akvi-tfstate"
state_storage_account_name = "<the name from step 1>"
github_repository_owner_id = "<owner ID>"
github_repository_id       = "<repository ID>"
```

GitHub puts the numeric owner and repository IDs in the OIDC subject, so Azure
keeps trusting the same repository if a name is later reused. Get them with
`gh api repos/<owner>/<repository> --jq '.owner.id, .id'`. `github_repository`
(`owner/name`) defaults to `mike-guy/azure-keyvault-issuer`; set it in
`bootstrap.tfvars` if the repository lives elsewhere. Then:

```sh
cd test/e2e/infra/bootstrap
terraform init -backend-config=backend.hcl
terraform apply -var-file=bootstrap.tfvars
```

The apply pauses for 30 seconds before it turns on the static website, because the
data-plane role it grants you takes a little while to take effect. If it still
fails with an authorisation error, apply again. It also grants CI's identity the
Microsoft Graph application permission `Application.ReadWrite.OwnedBy`, which an
administrator's consent is needed for, so it fails with an authorisation error
unless you hold Privileged Role Administrator or Global Administrator.

**Re-apply this stack after pulling a change to it** (`terraform init -upgrade
-backend-config=backend.hcl`, then the apply above). CI cannot apply it, by design.

## 3. Configure the GitHub environment

Create an environment named `e2e` with no branch restriction, so that pull requests
can use it, then add the variables. Pull requests from forks get no OIDC token, so
they skip e2e. Run this from `test/e2e/infra/bootstrap`:

```sh
REPO=<owner>/<repository>
gh api --method PUT "repos/$REPO/environments/e2e"

set_var() { gh variable set "$1" --env e2e --repo "$REPO" --body "$(terraform output -raw "$2")"; }
set_var AZURE_CLIENT_ID           ci_client_id
set_var AZURE_TENANT_ID           tenant_id
set_var AZURE_SUBSCRIPTION_ID     subscription_id
set_var OIDC_STORAGE_ACCOUNT      oidc_storage_account_name
set_var OIDC_SITE_URL             oidc_site_url
set_var TFSTATE_RESOURCE_GROUP    state_resource_group_name
set_var TFSTATE_STORAGE_ACCOUNT   state_storage_account_name
set_var TFSTATE_CONTAINER         state_container_name
```

These are environment **variables**, not secrets: none of them grants access on its
own. The CI identity's federated credential trusts only
`repo:<owner>@<owner ID>/<repository>@<repository ID>:environment:e2e`, so only jobs
that use this environment, in this repository, can sign in. Create the `e2e-aks` label too, which starts an AKS run on a pull
request:

```sh
gh label create e2e-aks --description "Run the e2e tests on AKS too"
```

## Running the tests from your own machine

CI's identity gets Key Vault data-plane rights from the bootstrap stack. The
bootstrap stack also gives your account the AKS and registry rights the AKS job uses,
but not Key Vault's. Owner covers the management plane only, so `make e2e-infra-up`
fails with `403 ForbiddenByRbac` when Terraform creates the first certificate. Grant
your user **Key Vault Certificates Officer** once, at subscription level:

```sh
az role assignment create \
  --assignee-object-id "$(az ad signed-in-user show --query id -o tsv)" \
  --assignee-principal-type User \
  --role "Key Vault Certificates Officer" \
  --scope "/subscriptions/$(az account show --query id -o tsv)"
```

The role can take a minute or two to apply. The subscription is dedicated to
testing, so this is safe there; don't copy the scope to a shared subscription. Your
account must also be able to register Entra applications, because each run creates
one. Members can by default; if the tenant has turned that off, you need the
Application Developer role.

Nothing needs exporting: the Makefile finds the state account, the OIDC storage
account and the subscription through `az` (`test/e2e/scripts/config.sh`), so you need
read access to `rg-akvi-tfstate` and `rg-akvi-ci`. CI supplies the same values from
the `e2e` environment's variables, and a variable set in your shell overrides what
`az` finds. The commands are in
[CONTRIBUTING.md](../../CONTRIBUTING.md#end-to-end-tests).

## Pull requests from forks

A fork's pull request gets no Azure sign-in, so its e2e job is skipped and it can't
merge while `kind / e2e` is a required check. To test one, review its code first (it
will run with the CI identity's rights), then push it to a branch here and open a
pull request from that branch:

```sh
gh pr checkout 123                         # the fork's pull request
git push origin HEAD:refs/heads/fork-pr-123
gh pr create --head fork-pr-123 --fill --body "Supersedes #123"
```

Merge without squashing, so the contributor keeps authorship. Review and push again
if the contributor adds commits.

## What CI is allowed to do

The CI identity (`id-akvi-ci`) can act only in `rg-akvi-ci` and on the state
container:

- Contributor and Key Vault Certificates Officer on `rg-akvi-ci`.
- Azure Kubernetes Service RBAC Cluster Admin and AcrPush on `rg-akvi-ci`. AKS
  clusters have local accounts off, so the tests reach the API with Azure RBAC and no
  cluster credential is ever stored in Terraform state; Contributor can't push images.
- Role Based Access Control Administrator on `rg-akvi-ci`, limited by a condition to
  three roles (the custom `akvi-e2e-issuer` role, Key Vault Secrets User and AcrPull)
  and to service principals. It can't grant itself anything else.
- Storage Blob Data Contributor on the state container and on the OIDC storage
  account.
- The Microsoft Graph application permission `Application.ReadWrite.OwnedBy`. It lets
  CI create Entra applications and manage, credential and delete only those it owns:
  one per run, named `akvi-e2e-<run ID>`. It cannot read or change any other
  application in the tenant, and it grants no directory roles. The run gives its
  application a role on that run's vault only.

The fallback auth scenarios add a client secret and a certificate to the run's
application through Microsoft Graph, valid for a day, and remove them when they
finish. Terraform creates the application with no credentials, so none is ever
written to state.

## Entra's recycle bin

Entra keeps a deleted application, and its service principal, in its deleted items
for 30 days, where they still count towards the directory quota of whoever created
them. Each run therefore purges both once Terraform has deleted them
(`infra-down.sh`). The purge is best effort, and a failure is only logged. The daily
cleanup deletes the application of any run that lost its state, but leaves the
deleted objects to expire. If runs start failing with a quota error, list what is
waiting with `az rest --url
https://graph.microsoft.com/v1.0/directory/deletedItems/microsoft.graph.application`
and purge it with `az rest --method DELETE --url
https://graph.microsoft.com/v1.0/directory/deletedItems/<id>`.

## Tearing it down

Destroy the `bootstrap` stack with `terraform destroy -var-file=bootstrap.tfvars`,
then delete `rg-akvi-tfstate`. Per-run resources, including each run's Entra
application, are removed by CI and by the daily cleanup.
