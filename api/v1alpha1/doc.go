// Package v1alpha1 defines the azure-keyvault-issuer v1alpha1 API: the
// AzureKeyVaultIssuer and AzureKeyVaultClusterIssuer kinds, which sign
// cert-manager CertificateRequests with a certificate authority held in Azure
// Key Vault.
//
// The two kinds share BaseIssuerSpec. They differ in scope and in
// authentication: only the cluster issuer may use the controller's own Azure
// identity, and only it can restrict the namespaces that may use it.
//
// The CRDs in charts/azure-keyvault-issuer/files/crds are generated from these
// types by "mise run manifests", so a change to a field comment changes the
// CRD's description.
//
// +kubebuilder:object:generate=true
// +groupName=azure-keyvault-issuer.mike-guy.github.io
package v1alpha1
