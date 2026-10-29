data "azurerm_client_config" "current" {}

data "azurerm_storage_account" "state" {
  name                = var.state_storage_account_name
  resource_group_name = var.state_resource_group_name
}

locals {
  tags = {
    project = "azure-keyvault-issuer"
    purpose = "e2e"
  }

  # var.github_repository is "owner/name". The OIDC subject GitHub issues also
  # carries the numeric owner and repository IDs, so Azure keeps trusting the
  # same repository if its name is later reused.
  github_owner = split("/", var.github_repository)[0]
  github_name  = split("/", var.github_repository)[1]

  # Built-in role: Key Vault Secrets User (a public Azure role definition GUID, not a secret).
  key_vault_secrets_user_role_id = "4633458b-17de-408a-b874-0445c86b69e6" # gitleaks:allow

  # Built-in role: AcrPull, which lets an AKS cluster's kubelet identity pull the run's image.
  acr_pull_role_id = "7f951dda-4ed3-4680-a7ca-43fe172d538d" # gitleaks:allow

  # Role assignments the CI identity may create and delete.
  delegable_role_ids = join(", ", [
    azurerm_role_definition.issuer.role_definition_id,
    local.key_vault_secrets_user_role_id,
    local.acr_pull_role_id,
  ])

  # ABAC condition: the CI identity can only create or delete assignments of
  # the roles above, and only to service principals (the per-run workload
  # identities and AKS kubelet identity).
  rbac_condition = <<-EOT
    (
     (
      !(ActionMatches{'Microsoft.Authorization/roleAssignments/write'})
     )
     OR
     (
      @Request[Microsoft.Authorization/roleAssignments:RoleDefinitionId] ForAnyOfAnyValues:GuidEquals {${local.delegable_role_ids}}
      AND
      @Request[Microsoft.Authorization/roleAssignments:PrincipalType] StringEqualsIgnoreCase 'ServicePrincipal'
     )
    )
    AND
    (
     (
      !(ActionMatches{'Microsoft.Authorization/roleAssignments/delete'})
     )
     OR
     (
      @Resource[Microsoft.Authorization/roleAssignments:RoleDefinitionId] ForAnyOfAnyValues:GuidEquals {${local.delegable_role_ids}}
      AND
      @Resource[Microsoft.Authorization/roleAssignments:PrincipalType] StringEqualsIgnoreCase 'ServicePrincipal'
     )
    )
  EOT
}

# Every per-run resource lives in this group, so CI never needs
# subscription-wide rights.
resource "azurerm_resource_group" "ci" {
  name     = "rg-akvi-ci"
  location = var.location
  tags     = local.tags
}

# The least-privilege role the issuer itself needs (docs/azure-setup.md). The
# per-run stack assigns it to the two test workload identities.
resource "azurerm_role_definition" "issuer" {
  name        = "akvi-e2e-issuer"
  scope       = azurerm_resource_group.ci.id
  description = "Read certificates and sign with keys: what azure-keyvault-issuer needs."

  permissions {
    actions = []
    data_actions = [
      "Microsoft.KeyVault/vaults/certificates/read",
      "Microsoft.KeyVault/vaults/keys/sign/action",
    ]
  }

  assignable_scopes = [azurerm_resource_group.ci.id]
}

# The identity GitHub Actions signs in as. A federated credential means no
# app registration and no client secret.
resource "azurerm_user_assigned_identity" "ci" {
  name                = "id-akvi-ci"
  resource_group_name = azurerm_resource_group.ci.name
  location            = azurerm_resource_group.ci.location
  tags                = local.tags
}

resource "azurerm_federated_identity_credential" "github" {
  name      = "github-${var.github_environment}"
  parent_id = azurerm_user_assigned_identity.ci.id
  issuer    = "https://token.actions.githubusercontent.com"
  subject   = "repo:${local.github_owner}@${var.github_repository_owner_id}/${local.github_name}@${var.github_repository_id}:environment:${var.github_environment}"
  audience  = ["api://AzureADTokenExchange"]
}

# The client certificate and client secret scenarios need an Entra
# application, which each run creates and destroys. Application.ReadWrite.OwnedBy
# lets CI create applications and manage only those it owns: it cannot read or
# change any other application in the tenant. Assigning it is an admin consent.
data "azuread_application_published_app_ids" "well_known" {}

data "azuread_service_principal" "msgraph" {
  client_id = data.azuread_application_published_app_ids.well_known.result["MicrosoftGraph"]
}

resource "azuread_app_role_assignment" "ci_graph_applications" {
  app_role_id         = data.azuread_service_principal.msgraph.app_role_ids["Application.ReadWrite.OwnedBy"]
  principal_object_id = azurerm_user_assigned_identity.ci.principal_id
  resource_object_id  = data.azuread_service_principal.msgraph.object_id
}

resource "azurerm_role_assignment" "ci_contributor" {
  scope                = azurerm_resource_group.ci.id
  role_definition_name = "Contributor"
  principal_id         = azurerm_user_assigned_identity.ci.principal_id
  principal_type       = "ServicePrincipal"
}

# Contributor has no data-plane rights, so CI needs this to create the CA
# certificates in each per-run vault.
resource "azurerm_role_assignment" "ci_certificates_officer" {
  scope                = azurerm_resource_group.ci.id
  role_definition_name = "Key Vault Certificates Officer"
  principal_id         = azurerm_user_assigned_identity.ci.principal_id
  principal_type       = "ServicePrincipal"
}

resource "azurerm_role_assignment" "ci_rbac_administrator" {
  scope                = azurerm_resource_group.ci.id
  role_definition_name = "Role Based Access Control Administrator"
  principal_id         = azurerm_user_assigned_identity.ci.principal_id
  principal_type       = "ServicePrincipal"
  condition_version    = "2.0"
  condition            = local.rbac_condition
}

# The AKS e2e job reaches the cluster's API with Azure RBAC rather than an
# admin kubeconfig, so no cluster credential ever lands in Terraform state. The
# role is scoped to this group, so it covers each run's cluster and nothing else.
resource "azurerm_role_assignment" "ci_aks_cluster_admin" {
  scope                = azurerm_resource_group.ci.id
  role_definition_name = "Azure Kubernetes Service RBAC Cluster Admin"
  principal_id         = azurerm_user_assigned_identity.ci.principal_id
  principal_type       = "ServicePrincipal"
}

# Contributor cannot push images, so CI needs this to push to each run's registry.
resource "azurerm_role_assignment" "ci_acr_push" {
  scope                = azurerm_resource_group.ci.id
  role_definition_name = "AcrPush"
  principal_id         = azurerm_user_assigned_identity.ci.principal_id
  principal_type       = "ServicePrincipal"
}

# The same two rights for the administrator, so 'make e2e CLUSTER=aks' works locally.
resource "azurerm_role_assignment" "admin_aks_cluster_admin" {
  scope                = azurerm_resource_group.ci.id
  role_definition_name = "Azure Kubernetes Service RBAC Cluster Admin"
  principal_id         = data.azurerm_client_config.current.object_id
}

resource "azurerm_role_assignment" "admin_acr_push" {
  scope                = azurerm_resource_group.ci.id
  role_definition_name = "AcrPush"
  principal_id         = data.azurerm_client_config.current.object_id
}

# CI keeps per-run state in the same container as this stack's state, under
# run/. Scoped to the container, not the account.
resource "azurerm_role_assignment" "ci_state" {
  scope                = "${data.azurerm_storage_account.state.id}/blobServices/default/containers/${var.state_container_name}"
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = azurerm_user_assigned_identity.ci.principal_id
  principal_type       = "ServicePrincipal"
}

# Hosts the OIDC discovery documents that kind clusters publish, so Entra can
# verify their projected tokens. The documents hold public keys only.
#trivy:ignore:AVD-AZU-0012 Entra must reach the static website anonymously over the internet.
resource "azurerm_storage_account" "oidc" {
  name                = "stakvioidc${substr(md5(azurerm_resource_group.ci.id), 0, 8)}"
  resource_group_name = azurerm_resource_group.ci.name
  location            = azurerm_resource_group.ci.location

  account_kind             = "StorageV2"
  account_tier             = "Standard"
  account_replication_type = "LRS"
  min_tls_version          = "TLS1_2"

  # The static website endpoint is public regardless of this setting, which
  # only governs blob containers.
  allow_nested_items_to_be_public = false
  shared_access_key_enabled       = false
  default_to_oauth_authentication = true

  tags = local.tags
}

# The administrator needs data-plane rights to turn the static website on.
resource "azurerm_role_assignment" "admin_oidc" {
  scope                = azurerm_storage_account.oidc.id
  role_definition_name = "Storage Blob Data Owner"
  principal_id         = data.azurerm_client_config.current.object_id
}

# Azure reports a role assignment as created before it is enforced, and the
# static website setting is a data-plane call that needs the role above. Without
# this pause the first apply fails with an authorisation error. It runs only
# when the role assignment is created, so later applies and destroys don't wait.
resource "time_sleep" "admin_oidc_propagation" {
  create_duration = "30s"

  depends_on = [azurerm_role_assignment.admin_oidc]
}

resource "azurerm_storage_account_static_website" "oidc" {
  storage_account_id = azurerm_storage_account.oidc.id
  index_document     = "index.html"

  depends_on = [time_sleep.admin_oidc_propagation]
}

resource "azurerm_role_assignment" "ci_oidc" {
  scope                = azurerm_storage_account.oidc.id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = azurerm_user_assigned_identity.ci.principal_id
  principal_type       = "ServicePrincipal"
}
