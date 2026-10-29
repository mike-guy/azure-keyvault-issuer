terraform {
  required_version = ">= 1.9"

  # Partial configuration: `make e2e-infra-up` supplies the storage account
  # and a per-run key (run/<run_id>.tfstate) at init time.
  backend "azurerm" {
    use_azuread_auth = true
  }

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.0"
    }
    # Records when the run was created, in state, for the created_at tag.
    time = {
      source  = "hashicorp/time"
      version = "~> 0.13"
    }
    # The Entra application for the client certificate and client secret
    # scenarios: a managed identity cannot hold either.
    azuread = {
      source  = "hashicorp/azuread"
      version = "~> 3.0"
    }
  }
}

# Signs in as the azurerm provider does: the job's OIDC token on GitHub Actions
# (ARM_USE_OIDC, ARM_CLIENT_ID, ARM_TENANT_ID), the Azure CLI locally. CI may
# manage only the applications it owns (Application.ReadWrite.OwnedBy, granted
# by the bootstrap stack).
provider "azuread" {}

provider "azurerm" {
  features {
    key_vault {
      # Destroy soft-deletes the vault, and the 7-day retention expires it at
      # no cost. CI has no purge rights.
      purge_soft_delete_on_destroy = false
    }
  }

  subscription_id = var.subscription_id

  # On GitHub Actions, use the job's OIDC token directly. Locally, the
  # Azure CLI sign-in is used instead (ARM_USE_OIDC is unset).
  storage_use_azuread = true

  # CI has no subscription-level rights. The providers are registered once by
  # an administrator (test/e2e/README.md).
  resource_provider_registrations = "none"
}
