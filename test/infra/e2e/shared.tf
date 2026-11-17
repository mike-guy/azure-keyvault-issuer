data "azurerm_client_config" "current" {}

data "azurerm_resource_group" "this" {
  name = var.resource_group_name
}

locals {
  suffix              = substr(sha1("${var.subscription_id}${var.instance}"), 0, 6)
  ca_certificate_name = "e2e-ca"
  tags = {
    purpose  = "e2e"
    instance = var.instance
  }
}
