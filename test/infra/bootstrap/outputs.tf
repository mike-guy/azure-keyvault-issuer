output "state_resource_group_name" {
  description = "The resource group of the state storage account."
  value       = azurerm_resource_group.bootstrap.name
}

output "state_storage_account_name" {
  description = "The storage account that holds the e2e root's state."
  value       = azurerm_storage_account.this.name
}

output "state_container_name" {
  description = "The container in it."
  value       = azurerm_storage_container.this.name
}

output "e2e_resource_group_name" {
  description = "The resource group the e2e root builds in."
  value       = azurerm_resource_group.e2e.name
}

output "tenant_id" {
  description = "The Entra tenant, for the workflows' AZURE_TENANT_ID."
  value       = data.azurerm_client_config.current.tenant_id
}

output "subscription_id" {
  description = "The subscription, for the workflows' AZURE_SUBSCRIPTION_ID."
  value       = var.subscription_id
}

output "github_client_id" {
  description = "The GitHub identity's client ID, for the workflows' AZURE_CLIENT_ID. It is not a secret."
  value       = azurerm_user_assigned_identity.this.client_id
}
