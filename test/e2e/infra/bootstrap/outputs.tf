# Set these as variables on the GitHub "e2e" environment (not secrets: none of
# them grants access on its own).

output "tenant_id" {
  description = "AZURE_TENANT_ID."
  value       = data.azurerm_client_config.current.tenant_id
}

output "subscription_id" {
  description = "AZURE_SUBSCRIPTION_ID."
  value       = var.subscription_id
}

output "ci_client_id" {
  description = "AZURE_CLIENT_ID: the identity GitHub Actions signs in as."
  value       = azurerm_user_assigned_identity.ci.client_id
}

output "resource_group_name" {
  description = "The resource group every per-run resource lives in."
  value       = azurerm_resource_group.ci.name
}

output "issuer_role_name" {
  description = "The custom role the per-run stack assigns to the test identities."
  value       = azurerm_role_definition.issuer.name
}

output "oidc_storage_account_name" {
  description = "The storage account that hosts the kind OIDC documents."
  value       = azurerm_storage_account.oidc.name
}

output "oidc_site_url" {
  description = "The static website endpoint (https, trailing slash)."
  value       = azurerm_storage_account.oidc.primary_web_endpoint
}

output "state_storage_account_name" {
  description = "TFSTATE_STORAGE_ACCOUNT."
  value       = var.state_storage_account_name
}

output "state_resource_group_name" {
  description = "TFSTATE_RESOURCE_GROUP."
  value       = var.state_resource_group_name
}

output "state_container_name" {
  description = "TFSTATE_CONTAINER."
  value       = var.state_container_name
}
