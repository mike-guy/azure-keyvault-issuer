resource "azurerm_kubernetes_cluster" "this" {
  count                     = var.enable_aks ? 1 : 0
  name                      = "aks-akvi-${var.instance}"
  resource_group_name       = data.azurerm_resource_group.this.name
  location                  = data.azurerm_resource_group.this.location
  dns_prefix                = "akvi-${var.instance}"
  kubernetes_version        = var.aks_kubernetes_version
  sku_tier                  = "Free"
  oidc_issuer_enabled       = true
  workload_identity_enabled = true
  default_node_pool {
    name                        = "system"
    node_count                  = 1
    vm_size                     = var.aks_vm_size
    temporary_name_for_rotation = "systemtmp"
  }
  identity {
    type = "SystemAssigned"
  }
  network_profile {
    network_plugin      = "azure"
    network_plugin_mode = "overlay"
  }
  tags = local.tags
}
