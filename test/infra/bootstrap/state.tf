resource "azurerm_resource_group" "bootstrap" {
  name     = "rg-akv-e2e-testing-bootstrap"
  location = var.location
}

resource "azurerm_storage_account" "this" {
  name                            = "stmgakve2etfstate"
  resource_group_name             = azurerm_resource_group.bootstrap.name
  location                        = azurerm_resource_group.bootstrap.location
  account_kind                    = "StorageV2"
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  min_tls_version                 = "TLS1_2"
  shared_access_key_enabled       = false
  allow_nested_items_to_be_public = false
  default_to_oauth_authentication = true
}

resource "azurerm_storage_container" "this" {
  name                  = "tfstate"
  container_access_type = "private"
  storage_account_id    = azurerm_storage_account.this.id
}

resource "azurerm_role_assignment" "me" {
  scope                = azurerm_resource_group.bootstrap.id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = data.azurerm_client_config.current.object_id
}
