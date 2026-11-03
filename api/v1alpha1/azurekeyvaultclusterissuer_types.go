package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	issuerlib "github.com/cert-manager/issuer-lib/api/v1alpha1"
)

// AzureKeyVaultClusterIssuerTypeIdentifier identifies the cluster-scoped
// issuer kind to issuer-lib, in the form "<plural resource>.<group>".
const AzureKeyVaultClusterIssuerTypeIdentifier = "azurekeyvaultclusterissuers." + GroupName

// AzureKeyVaultClusterIssuer signs CertificateRequests in any namespace with a
// CA key held in Azure Key Vault.
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,shortName=akvci
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Reason",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].reason`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
type AzureKeyVaultClusterIssuer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   AzureKeyVaultIssuerSpec `json:"spec"`
	Status issuerlib.IssuerStatus  `json:"status,omitempty"`
}

// GetConditions returns the issuer's status conditions.
func (i *AzureKeyVaultClusterIssuer) GetConditions() []metav1.Condition {
	return i.Status.Conditions
}

// GetIssuerTypeIdentifier returns the identifier issuer-lib uses to match
// this kind.
func (*AzureKeyVaultClusterIssuer) GetIssuerTypeIdentifier() string {
	return AzureKeyVaultClusterIssuerTypeIdentifier
}

// AzureKeyVaultClusterIssuerList is a list of AzureKeyVaultClusterIssuer.
// +kubebuilder:object:root=true
type AzureKeyVaultClusterIssuerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []AzureKeyVaultClusterIssuer `json:"items"`
}
