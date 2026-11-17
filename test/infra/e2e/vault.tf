####################################################
# Key Vault
####################################################
resource "azurerm_key_vault" "this" {
  name                       = "kv-akvi-${var.instance}-${local.suffix}"
  resource_group_name        = data.azurerm_resource_group.this.name
  location                   = data.azurerm_resource_group.this.location
  tenant_id                  = data.azurerm_client_config.current.tenant_id
  sku_name                   = "standard"
  rbac_authorization_enabled = true
  soft_delete_retention_days = 7
  purge_protection_enabled   = false
  tags                       = local.tags
}

####################################################
# Access
####################################################
locals {
  vault_roles = toset(["Key Vault Certificate User", "Key Vault Crypto User", "Key Vault Secrets User"])
  vault_principals = merge(
    { kind = azurerm_user_assigned_identity.kind.principal_id },
    var.enable_aks ? { aks = azurerm_user_assigned_identity.aks[0].principal_id } : {},
    var.enable_client_credentials ? { client = azuread_service_principal.client[0].object_id } : {},
  )
  vault_role_assignments = {
    for pair in setproduct(keys(local.vault_principals), local.vault_roles) :
    "${pair[0]}/${pair[1]}" => { principal = pair[0], role = pair[1] }
  }
}

# The limited application reads certificates and signs, and cannot read secrets. Key Vault Certificate User cannot
# be used, as it includes reading the secret behind a certificate, but Key Vault Reader reads certificates and
# not secret values.
resource "azurerm_role_assignment" "vault_limited_certificates" {
  count                = var.enable_client_credentials ? 1 : 0
  scope                = azurerm_key_vault.this.id
  role_definition_name = "Key Vault Reader"
  principal_id         = azuread_service_principal.limited[0].object_id
  principal_type       = "ServicePrincipal"
}

resource "azurerm_role_assignment" "vault_limited_crypto" {
  count                = var.enable_client_credentials ? 1 : 0
  scope                = azurerm_key_vault.this.id
  role_definition_name = "Key Vault Crypto User"
  principal_id         = azuread_service_principal.limited[0].object_id
  principal_type       = "ServicePrincipal"
}

resource "azurerm_role_assignment" "vault_operator" {
  scope                = azurerm_key_vault.this.id
  role_definition_name = "Key Vault Certificates Officer"
  principal_id         = data.azurerm_client_config.current.object_id
}

resource "azurerm_role_assignment" "vault_user" {
  for_each             = local.vault_role_assignments
  scope                = azurerm_key_vault.this.id
  role_definition_name = each.value.role
  principal_id         = local.vault_principals[each.value.principal]
  principal_type       = "ServicePrincipal"
}
