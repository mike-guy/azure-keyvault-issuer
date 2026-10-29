variable "subscription_id" {
  description = "The dedicated Azure subscription for e2e testing."
  type        = string
}

variable "location" {
  description = "The Azure region for every e2e resource."
  type        = string
  default     = "northeurope"
}

variable "github_repository" {
  description = "The GitHub repository (owner/name) whose e2e environment may sign in to Azure."
  type        = string
  default     = "mike-guy/azure-keyvault-issuer"
}

variable "github_repository_owner_id" {
  description = "The numeric ID of the repository's owner (`gh api repos/<owner>/<repo> --jq .owner.id`). GitHub puts it in the OIDC subject, so Azure only trusts the owner it names, not one that later reuses the name."
  type        = string
}

variable "github_repository_id" {
  description = "The numeric ID of the repository (`gh api repos/<owner>/<repo> --jq .id`), included in the OIDC subject for the same reason."
  type        = string
}

variable "github_environment" {
  description = "The GitHub environment that the CI federated credential trusts."
  type        = string
  default     = "e2e"
}

variable "state_resource_group_name" {
  description = "The resource group of the Terraform state storage account."
  type        = string
}

variable "state_storage_account_name" {
  description = "The Terraform state storage account, created by hand (test/e2e/README.md)."
  type        = string
}

variable "state_container_name" {
  description = "The blob container that holds Terraform state."
  type        = string
  default     = "tfstate"
}
