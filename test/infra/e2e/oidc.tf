resource "azurerm_storage_account" "oidc" {
  name                            = "stakvi${var.instance}oidc${local.suffix}"
  resource_group_name             = data.azurerm_resource_group.this.name
  location                        = data.azurerm_resource_group.this.location
  account_kind                    = "StorageV2"
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  min_tls_version                 = "TLS1_2"
  shared_access_key_enabled       = true
  default_to_oauth_authentication = true
  allow_nested_items_to_be_public = true
  tags                            = local.tags
}

resource "azurerm_storage_account_static_website" "oidc" {
  storage_account_id = azurerm_storage_account.oidc.id
  index_document     = "index.html"
}

resource "azurerm_role_assignment" "oidc_operator" {
  scope                = azurerm_storage_account.oidc.id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = data.azurerm_client_config.current.object_id
}

locals {
  kind_issuer_url = "${trimsuffix(azurerm_storage_account.oidc.primary_web_endpoint, "/")}/kind/"
}
