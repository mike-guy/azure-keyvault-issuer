output "env" {
  description = "The environment for the scripts and the suite, none of it secret."
  value = merge(
    {
      E2E_TENANT_ID            = data.azurerm_client_config.current.tenant_id
      E2E_VAULT_NAME           = azurerm_key_vault.this.name
      E2E_VAULT_URL            = azurerm_key_vault.this.vault_uri
      E2E_CA_CERTIFICATE_NAME  = local.ca_certificate_name
      E2E_OIDC_STORAGE_ACCOUNT = azurerm_storage_account.oidc.name
      E2E_KIND_OIDC_ISSUER_URL = local.kind_issuer_url
      E2E_KIND_CLIENT_ID       = azurerm_user_assigned_identity.kind.client_id
    },
    var.enable_aks ? {
      E2E_AKS_NAME            = azurerm_kubernetes_cluster.this[0].name
      E2E_AKS_RESOURCE_GROUP  = azurerm_kubernetes_cluster.this[0].resource_group_name
      E2E_AKS_OIDC_ISSUER_URL = azurerm_kubernetes_cluster.this[0].oidc_issuer_url
      E2E_AKS_CLIENT_ID       = azurerm_user_assigned_identity.aks[0].client_id
      E2E_ACR_NAME            = azurerm_container_registry.this[0].name
      E2E_ACR_LOGIN_SERVER    = azurerm_container_registry.this[0].login_server
    } : {},
    var.enable_client_credentials ? {
      E2E_CLIENT_ID         = azuread_application.client[0].client_id
      E2E_LIMITED_CLIENT_ID = azuread_application.limited[0].client_id
    } : {},
  )
}

output "secret_env" {
  description = "The environment that is secret."
  sensitive   = true
  value = var.enable_client_credentials ? {
    E2E_CLIENT_SECRET         = azuread_application_password.client[0].value
    E2E_LIMITED_CLIENT_SECRET = azuread_application_password.limited[0].value
  } : {}
}

output "client_certificate_pem" {
  description = "The client certificate, or null."
  value       = var.enable_client_credentials ? tls_self_signed_cert.client[0].cert_pem : null
}

output "client_private_key_pem" {
  description = "The client certificate's RSA key, or null."
  sensitive   = true
  value       = var.enable_client_credentials ? tls_private_key.client[0].private_key_pem : null
}
