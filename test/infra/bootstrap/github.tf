resource "azurerm_user_assigned_identity" "this" {
  name                = "id-akve2e-github"
  resource_group_name = azurerm_resource_group.bootstrap.name
  location            = azurerm_resource_group.bootstrap.location
}

resource "azurerm_federated_identity_credential" "this" {
  for_each                  = var.github_environments
  name                      = "github-environment-${each.key}"
  issuer                    = "https://token.actions.githubusercontent.com"
  audience                  = ["api://AzureADTokenExchange"]
  user_assigned_identity_id = azurerm_user_assigned_identity.this.id
  subject                   = "repo:${var.github_owner}@${var.github_owner_id}/${var.github_repository}@${var.github_repository_id}:environment:${each.key}"
}

resource "azurerm_role_assignment" "github_state" {
  scope                = azurerm_storage_container.this.id
  principal_id         = azurerm_user_assigned_identity.this.principal_id
  role_definition_name = "Storage Blob Data Contributor"
  principal_type       = "ServicePrincipal"
}

resource "azurerm_role_assignment" "github_runs" {
  scope                = azurerm_resource_group.e2e.id
  role_definition_name = "Contributor"
  principal_type       = "ServicePrincipal"
  principal_id         = azurerm_user_assigned_identity.this.principal_id
}

resource "azurerm_role_definition" "vault_purger" {
  name        = "akvi-e2e-vault-purger"
  scope       = data.azurerm_subscription.current.id
  description = "Purges deleted Key Vaults, for the e2e runs to clear up after themselves."
  permissions {
    actions = [
      "Microsoft.KeyVault/deletedVaults/read",
      "Microsoft.KeyVault/locations/deletedVaults/read",
      "Microsoft.KeyVault/locations/deletedVaults/purge/action",
      "Microsoft.KeyVault/locations/operationResults/read",
    ]
  }
  assignable_scopes = [data.azurerm_subscription.current.id]
}

resource "azurerm_role_assignment" "github_vault_purge" {
  scope              = data.azurerm_subscription.current.id
  role_definition_id = azurerm_role_definition.vault_purger.role_definition_resource_id
  principal_id       = azurerm_user_assigned_identity.this.principal_id
  principal_type     = "ServicePrincipal"
}

locals {
  grantable_roles = toset([
    "Key Vault Certificates Officer",
    "Key Vault Certificate User",
    "Key Vault Crypto User",
    "Key Vault Reader",
    "Key Vault Secrets User",
    "Storage Blob Data Contributor",
    "AcrPull",
    "AcrPush",
  ])
  grantable_role_ids = join(", ", [for role in data.azurerm_role_definition.grantable : regex("[^/]+$", role.role_definition_id)])
}

data "azurerm_role_definition" "grantable" {
  for_each = local.grantable_roles
  name     = each.key
}

resource "azurerm_role_assignment" "github_rbac" {
  scope                = azurerm_resource_group.e2e.id
  role_definition_name = "Role Based Access Control Administrator"
  principal_id         = azurerm_user_assigned_identity.this.principal_id
  principal_type       = "ServicePrincipal"
  condition_version    = "2.0"
  condition            = <<-EOT
    (
      (
        !(ActionMatches{'Microsoft.Authorization/roleAssignments/write'})
      )
      OR
      (
        @Request[Microsoft.Authorization/roleAssignments:RoleDefinitionId] ForAnyOfAnyValues:GuidEquals {${local.grantable_role_ids}}
      )
    )
    AND
    (
      (
        !(ActionMatches{'Microsoft.Authorization/roleAssignments/delete'})
      )
      OR
      (
        @Resource[Microsoft.Authorization/roleAssignments:RoleDefinitionId] ForAnyOfAnyValues:GuidEquals {${local.grantable_role_ids}}
      )
    )
  EOT
}
