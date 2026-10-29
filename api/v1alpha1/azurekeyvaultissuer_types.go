package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	issuerlib "github.com/cert-manager/issuer-lib/api/v1alpha1"
)

// AzureKeyVaultIssuerTypeIdentifier identifies the namespaced issuer kind to
// issuer-lib, in the form "<plural resource>.<group>".
const AzureKeyVaultIssuerTypeIdentifier = "azurekeyvaultissuers." + GroupName

// AzureKeyVaultIssuer signs CertificateRequests in its own namespace with a CA
// key held in Azure Key Vault.
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=akvi
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Reason",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].reason`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
type AzureKeyVaultIssuer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   AzureKeyVaultIssuerSpec `json:"spec"`
	Status issuerlib.IssuerStatus  `json:"status,omitempty"`
}

// GetConditions returns the issuer's status conditions.
func (i *AzureKeyVaultIssuer) GetConditions() []metav1.Condition {
	return i.Status.Conditions
}

// GetIssuerTypeIdentifier returns the identifier issuer-lib uses to match
// this kind.
func (*AzureKeyVaultIssuer) GetIssuerTypeIdentifier() string {
	return AzureKeyVaultIssuerTypeIdentifier
}

// AzureKeyVaultIssuerList is a list of AzureKeyVaultIssuer.
// +kubebuilder:object:root=true
type AzureKeyVaultIssuerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []AzureKeyVaultIssuer `json:"items"`
}
