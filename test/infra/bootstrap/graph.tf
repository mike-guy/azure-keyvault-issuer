data "azuread_application_published_app_ids" "well_known" {}

resource "azuread_service_principal" "msgraph" {
  client_id    = data.azuread_application_published_app_ids.well_known.result["MicrosoftGraph"]
  use_existing = true
}

resource "azuread_app_role_assignment" "github_applications" {
  app_role_id         = azuread_service_principal.msgraph.app_role_ids["Application.ReadWrite.OwnedBy"]
  principal_object_id = azurerm_user_assigned_identity.this.principal_id
  resource_object_id  = azuread_service_principal.msgraph.object_id
}
