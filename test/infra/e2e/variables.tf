variable "subscription_id" {
  description = "The subscription dedicated to e2e testing."
  type        = string
}

variable "resource_group_name" {
  description = "The existing resource group to build in, which bootstrap made and limited the workflows' identity to."
  type        = string
  default     = "rg-akv-e2e-testing-pr-runs"
}

variable "instance" {
  description = "Names this copy of the infrastructure and its state, so that people and concurrent workflow runs each have their own in the one resource group. It has no default, so nothing can land in a shared one by accident."
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9]{2,8}$", var.instance))
    error_message = "The instance must be 2 to 8 lowercase letters or digits, as it is part of storage account names."
  }
}

variable "workload_identity_service_accounts" {
  description = "The ServiceAccounts that may sign in as the e2e managed identities, by workload identity. They must match the chart's, and the namespaces the specs use."
  type = map(object({
    namespace = string
    name      = string
  }))
  default = {
    controller        = { namespace = "azure-keyvault-issuer", name = "azure-keyvault-issuer" }
    controller-issuer = { namespace = "azure-keyvault-issuer", name = "e2e-wi" }
    namespaced-issuer = { namespace = "e2e-wi", name = "e2e-wi" }
  }
}

variable "enable_aks" {
  description = "Make an AKS cluster, with a registry for the image and a federated credential for the cluster. Off for a run that uses kind alone."
  type        = bool
  default     = false
}

variable "aks_vm_size" {
  description = "The size of the AKS cluster's one node."
  type        = string
  default     = "Standard_D2als_v6"
}

variable "aks_kubernetes_version" {
  description = "The AKS Kubernetes version. Null uses the region's default."
  type        = string
  default     = null
}

variable "enable_client_credentials" {
  description = "Make an Entra application with a client secret and a certificate, for the clientSecret and clientCertificate methods, which managed identities cannot do. It needs Microsoft Graph rights: yours locally, and in a workflow the GitHub identity's, which bootstrap grants. It is destroyed with the rest."
  type        = bool
  default     = true
}
