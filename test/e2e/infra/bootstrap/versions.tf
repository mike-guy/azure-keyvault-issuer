terraform {
  required_version = ">= 1.9"

  # Partial configuration: the storage account is supplied at init time with
  # -backend-config=backend.hcl (see test/e2e/README.md).
  backend "azurerm" {
    use_azuread_auth = true
  }

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
    # Waits for a new role assignment to take effect (see main.tf).
    time = {
      source  = "hashicorp/time"
      version = "~> 0.13"
    }
    # Grants CI the Microsoft Graph permission the per-run stack needs (see main.tf).
    azuread = {
      source  = "hashicorp/azuread"
      version = "~> 3.0"
    }
  }
}

# The administrator's Azure CLI sign-in. Consenting to an application
# permission needs Privileged Role Administrator or Global Administrator.
provider "azuread" {}

provider "azurerm" {
  features {}

  subscription_id = var.subscription_id

  # The applying administrator is not given data-plane rights by default, and
  # the storage account below has shared-key access disabled.
  storage_use_azuread = true

  # The administrator applying this stack has subscription-level rights, so
  # this is where the resource providers get registered. The per-run stack runs
  # as CI, which has none, and registers nothing.
  resource_provider_registrations = "core"
  resource_providers_to_register = [
    "Microsoft.ContainerRegistry",
    "Microsoft.ContainerService",
  ]
}
