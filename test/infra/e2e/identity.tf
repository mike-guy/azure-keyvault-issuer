locals {
  service_accounts = {
    for key, account in var.workload_identity_service_accounts :
    key => "system:serviceaccount:${account.namespace}:${account.name}"
  }
}

####################################################
# Kind
####################################################
resource "azurerm_user_assigned_identity" "kind" {
  name                = "id-akvi-${var.instance}-kind"
  resource_group_name = data.azurerm_resource_group.this.name
  location            = data.azurerm_resource_group.this.location
  tags                = local.tags
}

resource "azurerm_federated_identity_credential" "kind" {
  for_each                  = local.service_accounts
  name                      = each.key
  user_assigned_identity_id = azurerm_user_assigned_identity.kind.id
  issuer                    = local.kind_issuer_url
  audience                  = ["api://AzureADTokenExchange"]
  subject                   = each.value
}

####################################################
# AKS
####################################################
resource "azurerm_user_assigned_identity" "aks" {
  count               = var.enable_aks ? 1 : 0
  name                = "id-akvi-${var.instance}-aks"
  resource_group_name = data.azurerm_resource_group.this.name
  location            = data.azurerm_resource_group.this.location
  tags                = local.tags
}

resource "azurerm_federated_identity_credential" "aks" {
  for_each                  = var.enable_aks ? local.service_accounts : {}
  name                      = each.key
  user_assigned_identity_id = azurerm_user_assigned_identity.aks[0].id
  issuer                    = azurerm_kubernetes_cluster.this[0].oidc_issuer_url
  audience                  = ["api://AzureADTokenExchange"]
  subject                   = each.value
}
