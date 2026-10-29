variable "subscription_id" {
  description = "The dedicated Azure subscription for e2e testing."
  type        = string
}

variable "run_id" {
  description = "Identifies this run: it names the OIDC prefix and tags every resource, so the cleanup can find leftovers."
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{2,30}$", var.run_id))
    error_message = "The run ID must be 3 to 31 lowercase letters, digits or hyphens, starting with a letter or digit."
  }
}

variable "cluster" {
  description = "Which cluster the tests run on: kind publishes its own OIDC documents, aks creates a cluster and a registry for its image."
  type        = string
  default     = "kind"

  validation {
    condition     = contains(["kind", "aks"], var.cluster)
    error_message = "The cluster must be kind or aks."
  }
}

variable "oidc_jwks_file" {
  description = "The path of the kind cluster's public JSON Web Key Set, which 'make cluster-up' reads from its API server. Read only when the blob is created (cluster = kind), so a destroy works without the file."
  type        = string
}

variable "aks_vm_size" {
  description = "The size of the AKS cluster's one node: 2 vCPUs and 8 GiB are enough for cert-manager and the controller. No burstable size is deployable by the test subscription in northeurope (restricted or no quota), so this is the cheapest mature general-purpose size that azskufinder found."
  type        = string
  default     = "Standard_D2as_v4"
}

variable "oidc_storage_account_name" {
  description = "The bootstrap stack's static-website storage account."
  type        = string
}

variable "oidc_site_url" {
  description = "That account's static website endpoint (the bootstrap stack's oidc_site_url output). Passed in rather than read from the account, because reading it would put the account's access keys in this stack's state."
  type        = string
}

variable "resource_group_name" {
  description = "The bootstrap stack's resource group."
  type        = string
  default     = "rg-akvi-ci"
}

variable "issuer_role_name" {
  description = "The bootstrap stack's custom role (certificates/read and keys/sign)."
  type        = string
  default     = "akvi-e2e-issuer"
}

variable "controller_namespace" {
  description = "The namespace the controller is installed in."
  type        = string
  default     = "akvi-system"
}

variable "controller_service_account" {
  description = "The controller's ServiceAccount, which holds the ambient identity."
  type        = string
  default     = "azure-keyvault-issuer"
}

variable "tenant_namespace" {
  description = "The namespace of the test tenant's namespaced Issuers."
  type        = string
  default     = "team-a"
}

variable "tenant_service_account" {
  description = "The ServiceAccount a namespaced Issuer references."
  type        = string
  default     = "team-a-issuer"
}
