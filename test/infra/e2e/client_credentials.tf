####################################################
# Application
####################################################
resource "azuread_application" "client" {
  count        = var.enable_client_credentials ? 1 : 0
  display_name = "akv-e2e-client-${var.instance}"
  owners       = [data.azurerm_client_config.current.object_id]
}

resource "azuread_service_principal" "client" {
  count     = var.enable_client_credentials ? 1 : 0
  client_id = azuread_application.client[0].client_id
  owners    = [data.azurerm_client_config.current.object_id]
}

####################################################
# Client secret
####################################################
resource "time_offset" "client_expiry" {
  count       = var.enable_client_credentials ? 1 : 0
  offset_days = 30
}

resource "azuread_application_password" "client" {
  count          = var.enable_client_credentials ? 1 : 0
  application_id = azuread_application.client[0].id
  display_name   = "e2e"
  end_date       = time_offset.client_expiry[0].rfc3339
}

####################################################
# Client certificate
####################################################
resource "tls_private_key" "client" {
  count     = var.enable_client_credentials ? 1 : 0
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "tls_self_signed_cert" "client" {
  count                 = var.enable_client_credentials ? 1 : 0
  private_key_pem       = tls_private_key.client[0].private_key_pem
  validity_period_hours = 24 * 30
  allowed_uses          = ["digital_signature"]
  subject {
    common_name = "akv-e2e-client-${var.instance}"
  }
}

resource "azuread_application_certificate" "client" {
  count          = var.enable_client_credentials ? 1 : 0
  application_id = azuread_application.client[0].id
  type           = "AsymmetricX509Cert"
  encoding       = "pem"
  value          = tls_self_signed_cert.client[0].cert_pem
  end_date       = tls_self_signed_cert.client[0].validity_end_time
}

####################################################
# Limited application
####################################################
# An application with a client secret that may read certificates and sign, and
# may not read secrets (see vault.tf), so that a spec can see what an issuer says when
# chainInSecret needs a secret that its identity cannot read.
resource "azuread_application" "limited" {
  count        = var.enable_client_credentials ? 1 : 0
  display_name = "akv-e2e-limited-${var.instance}"
  owners       = [data.azurerm_client_config.current.object_id]
}

resource "azuread_service_principal" "limited" {
  count     = var.enable_client_credentials ? 1 : 0
  client_id = azuread_application.limited[0].client_id
  owners    = [data.azurerm_client_config.current.object_id]
}

resource "azuread_application_password" "limited" {
  count          = var.enable_client_credentials ? 1 : 0
  application_id = azuread_application.limited[0].id
  display_name   = "e2e"
  end_date       = time_offset.client_expiry[0].rfc3339
}
