# The e2e tests read these through `make e2e-infra-up`, which writes them to
# test/e2e/.work/outputs.json.

output "vault_url" {
  description = "The per-run Key Vault's URL."
  value       = azurerm_key_vault.ca.vault_uri
}

output "ec_certificate_name" {
  description = "The pending EC P-256 CA the tests merge (two-tier)."
  value       = azurerm_key_vault_certificate.ca["ca-ec"].name
}

output "rsa_certificate_name" {
  description = "The pending RSA 2048 CA the tests merge (two-tier)."
  value       = azurerm_key_vault_certificate.ca["ca-rsa"].name
}

output "subordinate_certificate_name" {
  description = "The pending subordinate CA the tests merge, with the secret role assigned."
  value       = azurerm_key_vault_certificate.ca["sub-ca"].name
}

output "subordinate_norole_certificate_name" {
  description = "The pending subordinate CA without the secret role."
  value       = azurerm_key_vault_certificate.ca["sub-ca-norole"].name
}

output "tenant_id" {
  description = "The Entra tenant ID."
  value       = data.azurerm_client_config.current.tenant_id
}

output "ambient_client_id" {
  description = "The controller's ambient identity."
  value       = azurerm_user_assigned_identity.ambient.client_id
}

output "tenant_client_id" {
  description = "The identity a namespaced Issuer reaches through a ServiceAccount reference."
  value       = azurerm_user_assigned_identity.tenant.client_id
}

output "fallback_client_id" {
  description = "The Entra application the client certificate and client secret scenarios sign in as."
  value       = azuread_application.fallback.client_id
}

output "fallback_application_object_id" {
  description = "That application's object ID, which Microsoft Graph addresses it by: the tests add its credentials, and teardown purges it from Entra's deleted items."
  value       = azuread_application.fallback.object_id
}

output "fallback_service_principal_object_id" {
  description = "That application's service principal, which teardown also purges."
  value       = azuread_service_principal.fallback.object_id
}

output "oidc_issuer_url" {
  description = "The OIDC issuer the federated credentials trust."
  value       = local.oidc_issuer_url
}

output "run_id" {
  description = "The run ID."
  value       = var.run_id
}

output "acr_login_server" {
  description = "The registry that holds the run's controller image. Empty on kind, which loads the image from a tarball."
  value       = one(azurerm_container_registry.image[*].login_server)
}

output "aks_name" {
  description = "The AKS cluster's name. Empty on kind."
  value       = one(azurerm_kubernetes_cluster.aks[*].name)
}
