resource "azurerm_container_registry" "this" {
  count               = var.enable_aks ? 1 : 0
  name                = "acrakvi${var.instance}${local.suffix}"
  resource_group_name = data.azurerm_resource_group.this.name
  location            = data.azurerm_resource_group.this.location
  sku                 = "Basic"
  admin_enabled       = false
  tags                = local.tags
}

resource "azurerm_role_assignment" "aks_pull" {
  count                = var.enable_aks ? 1 : 0
  scope                = azurerm_container_registry.this[0].id
  role_definition_name = "AcrPull"
  principal_type       = "ServicePrincipal"
  principal_id         = azurerm_kubernetes_cluster.this[0].kubelet_identity[0].object_id
}

resource "azurerm_role_assignment" "acr_operator" {
  count                = var.enable_aks ? 1 : 0
  role_definition_name = "AcrPush"
  scope                = azurerm_container_registry.this[0].id
  principal_id         = data.azurerm_client_config.current.object_id
}
