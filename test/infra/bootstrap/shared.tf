resource "azurerm_resource_group" "e2e" {
  name     = "rg-akv-e2e-testing-pr-runs"
  location = var.location
}
