data "azurerm_client_config" "current" {}

data "azurerm_resource_group" "ci" {
  name = var.resource_group_name
}

data "azurerm_role_definition" "issuer" {
  name  = var.issuer_role_name
  scope = data.azurerm_resource_group.ci.id
}

# The OIDC storage account is deliberately not read with a data source: the
# azurerm one exports the account's access keys and connection strings, which
# would then sit in this stack's durable state. Its website URL arrives as a
# variable and its ID is built from names.

resource "random_string" "suffix" {
  length  = 6
  upper   = false
  special = false
}

# When the run was created (RFC 3339, UTC), fixed in state, so a later apply or
# destroy needs no timestamp passed in.
resource "time_static" "created" {}

locals {
  name_suffix = random_string.suffix.result

  tags = {
    project    = "azure-keyvault-issuer"
    purpose    = "e2e"
    run_id     = var.run_id
    created_at = time_static.created.rfc3339
  }

  # The OIDC issuer the federated credentials trust. For kind, it is the
  # per-run prefix on the static website, which must match the API server's
  # --service-account-issuer exactly (no trailing slash). AKS publishes its own.
  oidc_issuer_url = var.cluster == "aks" ? azurerm_kubernetes_cluster.aks[0].oidc_issuer_url : "${trimsuffix(var.oidc_site_url, "/")}/${var.run_id}"

  # The static website's container, which Azure creates when the website is
  # enabled, so it is addressed by ID rather than managed here.
  oidc_web_container_id = "${data.azurerm_resource_group.ci.id}/providers/Microsoft.Storage/storageAccounts/${var.oidc_storage_account_name}/blobServices/default/containers/$web"
}

# A Standard (software-key) vault with public access. This is test-only
# infrastructure that CI and kind clusters reach from the internet.
#trivy:ignore:AVD-AZU-0013 Public access is deliberate: GitHub-hosted runners have no fixed addresses.
resource "azurerm_key_vault" "ca" {
  name                = "kv-akvi-${local.name_suffix}"
  location            = data.azurerm_resource_group.ci.location
  resource_group_name = data.azurerm_resource_group.ci.name
  tenant_id           = data.azurerm_client_config.current.tenant_id
  sku_name            = "standard"

  rbac_authorization_enabled = true

  # The shortest retention, and no purge protection, so a destroyed vault
  # expires on its own and its name is reusable.
  soft_delete_retention_days = 7
  purge_protection_enabled   = false

  tags = local.tags
}

# The CAs. Key Vault can't create a certificate with the CA basic constraint
# itself (a self-signed one comes back CA:FALSE), so every CA is created
# pending: Key Vault generates the key, which is not exportable, and a CSR. The
# Go tests sign each CSR with a throwaway root and merge the result back,
# which is the production flow and the one thing Terraform can't do.
#
#   ca-ec, ca-rsa  two-tier CAs for the happy path (chainSource: Certificate)
#   sub-ca         signed by a throwaway root, then an intermediate, for the
#                  three-tier test; it gets the secret role below
#   sub-ca-norole  the same, without the role, to test the failure
locals {
  cas = {
    "ca-ec"         = { key_type = "EC", curve = "P-256", key_size = null }
    "ca-rsa"        = { key_type = "RSA", curve = null, key_size = 2048 }
    "sub-ca"        = { key_type = "RSA", curve = null, key_size = 2048 }
    "sub-ca-norole" = { key_type = "RSA", curve = null, key_size = 2048 }
  }
}

resource "azurerm_key_vault_certificate" "ca" {
  for_each = local.cas

  name         = each.key
  key_vault_id = azurerm_key_vault.ca.id

  certificate_policy {
    issuer_parameters {
      name = "Unknown"
    }

    key_properties {
      exportable = false
      key_type   = each.value.key_type
      curve      = each.value.curve
      key_size   = each.value.key_size
      reuse_key  = false
    }

    secret_properties {
      content_type = "application/x-pem-file"
    }

    x509_certificate_properties {
      subject            = "CN=akvi e2e ${each.key}"
      validity_in_months = 12
      key_usage          = ["cRLSign", "digitalSignature", "keyCertSign"]
    }
  }

  tags = local.tags
}

# Two workload identities, so the tests can check they are isolated: the
# ambient one belongs to the controller's ServiceAccount, the other to the
# test tenant's.
resource "azurerm_user_assigned_identity" "ambient" {
  name                = "id-akvi-${local.name_suffix}-ambient"
  resource_group_name = data.azurerm_resource_group.ci.name
  location            = data.azurerm_resource_group.ci.location
  tags                = local.tags
}

resource "azurerm_user_assigned_identity" "tenant" {
  name                = "id-akvi-${local.name_suffix}-tenant"
  resource_group_name = data.azurerm_resource_group.ci.name
  location            = data.azurerm_resource_group.ci.location
  tags                = local.tags
}

# Entra rejects concurrent writes to one identity's federated credentials, and
# also throttles them across identities, so the two are chained.
resource "azurerm_federated_identity_credential" "ambient" {
  name      = "ambient"
  parent_id = azurerm_user_assigned_identity.ambient.id
  issuer    = local.oidc_issuer_url
  subject   = "system:serviceaccount:${var.controller_namespace}:${var.controller_service_account}"
  audience  = ["api://AzureADTokenExchange"]

  depends_on = [azurerm_storage_blob.discovery, azurerm_storage_blob.jwks]
}

resource "azurerm_federated_identity_credential" "tenant" {
  name      = "tenant"
  parent_id = azurerm_user_assigned_identity.tenant.id
  issuer    = local.oidc_issuer_url
  subject   = "system:serviceaccount:${var.tenant_namespace}:${var.tenant_service_account}"
  audience  = ["api://AzureADTokenExchange"]

  depends_on = [azurerm_federated_identity_credential.ambient]
}

# The Entra application the client certificate and client secret scenarios
# sign in as. It is created with no credentials, so none ever reaches this
# state: the Go tests add a short-lived certificate and client secret through
# Microsoft Graph, and destroying the application removes them. One per run, so
# concurrent runs never edit each other's credentials.
data "azuread_client_config" "current" {}

resource "azuread_application" "fallback" {
  display_name = "akvi-e2e-${var.run_id}"
  owners       = [data.azuread_client_config.current.object_id]
}

resource "azuread_service_principal" "fallback" {
  client_id = azuread_application.fallback.client_id
  owners    = [data.azuread_client_config.current.object_id]
}

# The issuer's least-privilege role, on this run's vault only. principal_type
# lets Azure accept the new service principal before Entra has replicated it.
resource "azurerm_role_assignment" "issuer" {
  for_each = {
    ambient  = azurerm_user_assigned_identity.ambient.principal_id
    tenant   = azurerm_user_assigned_identity.tenant.principal_id
    fallback = azuread_service_principal.fallback.object_id
  }

  scope              = azurerm_key_vault.ca.id
  role_definition_id = data.azurerm_role_definition.issuer.id
  principal_id       = each.value
  principal_type     = "ServicePrincipal"
}

# chainSource: Secret needs Key Vault Secrets User on that one secret, never
# the whole vault.
resource "azurerm_role_assignment" "subordinate_secret" {
  for_each = {
    ambient = azurerm_user_assigned_identity.ambient.principal_id
    tenant  = azurerm_user_assigned_identity.tenant.principal_id
  }

  scope                = "${azurerm_key_vault.ca.id}/secrets/${azurerm_key_vault_certificate.ca["sub-ca"].name}"
  role_definition_name = "Key Vault Secrets User"
  principal_id         = each.value
  principal_type       = "ServicePrincipal"
}

# The kind cluster's OIDC documents, so Entra can verify its tokens. They hold
# public keys only.
resource "azurerm_storage_blob" "discovery" {
  count = var.cluster == "kind" ? 1 : 0

  name                 = "${var.run_id}/.well-known/openid-configuration"
  storage_container_id = local.oidc_web_container_id
  type                 = "Block"
  content_type         = "application/json"
  source_content = jsonencode({
    issuer                                = local.oidc_issuer_url
    jwks_uri                              = "${local.oidc_issuer_url}/openid/v1/jwks"
    response_types_supported              = ["id_token"]
    subject_types_supported               = ["public"]
    id_token_signing_alg_values_supported = ["RS256"]
  })
}

resource "azurerm_storage_blob" "jwks" {
  count = var.cluster == "kind" ? 1 : 0

  name                 = "${var.run_id}/openid/v1/jwks"
  storage_container_id = local.oidc_web_container_id
  type                 = "Block"
  content_type         = "application/json"
  source               = var.oidc_jwks_file

  lifecycle {
    precondition {
      condition     = fileexists(var.oidc_jwks_file)
      error_message = "${var.oidc_jwks_file} is missing: create the kind cluster first ('make cluster-up')."
    }
  }
}

# The AKS cluster and the registry that holds the run's controller image. Both
# exist only when cluster is aks; kind loads the image from a tarball instead.
resource "azurerm_container_registry" "image" {
  count = var.cluster == "aks" ? 1 : 0

  name                = "acrakvi${local.name_suffix}"
  resource_group_name = data.azurerm_resource_group.ci.name
  location            = data.azurerm_resource_group.ci.location
  sku                 = "Basic"
  admin_enabled       = false

  tags = local.tags
}

# Free tier, one small node, no add-ons. Local accounts are off and Azure RBAC
# governs the Kubernetes API, so no cluster credential is ever written to state:
# the CI identity and the administrator hold the cluster admin role through the
# bootstrap stack, and kubelogin signs in with their Azure CLI session.
#trivy:ignore:AVD-AZU-0040 Test-only cluster: no monitoring add-on, to keep cost down.
#trivy:ignore:AVD-AZU-0041 The API server is public: GitHub-hosted runners have no fixed addresses.
#trivy:ignore:AVD-AZU-0043 Test-only cluster: no network policy.
resource "azurerm_kubernetes_cluster" "aks" {
  count = var.cluster == "aks" ? 1 : 0

  name                = "aks-akvi-${local.name_suffix}"
  resource_group_name = data.azurerm_resource_group.ci.name
  location            = data.azurerm_resource_group.ci.location
  dns_prefix          = "akvi-${local.name_suffix}"
  sku_tier            = "Free"

  oidc_issuer_enabled       = true
  workload_identity_enabled = true
  local_account_disabled    = true

  azure_active_directory_role_based_access_control {
    azure_rbac_enabled = true
    tenant_id          = data.azurerm_client_config.current.tenant_id
  }

  default_node_pool {
    name       = "default"
    node_count = 1
    vm_size    = var.aks_vm_size
  }

  identity {
    type = "SystemAssigned"
  }

  tags = local.tags
}

# Lets the nodes pull the run's image.
resource "azurerm_role_assignment" "kubelet_acr_pull" {
  count = var.cluster == "aks" ? 1 : 0

  scope                = azurerm_container_registry.image[0].id
  role_definition_name = "AcrPull"
  principal_id         = azurerm_kubernetes_cluster.aks[0].kubelet_identity[0].object_id
  principal_type       = "ServicePrincipal"
}
