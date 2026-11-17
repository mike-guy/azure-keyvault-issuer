/*
Copyright 2023 The cert-manager Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// This code has been modified from the cert-manager provided example
// by github.com/mike-guy

package v1alpha1

import (
	"github.com/cert-manager/issuer-lib/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// AzureKeyVaultClusterIssuerTypeIdentifier identifies the cluster-scoped
// issuer kind to issuer-lib, in the form "<plural resource>.<group>".
const AzureKeyVaultClusterIssuerTypeIdentifier = "azurekeyvaultclusterissuers." + GroupName

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,shortName=akvci;akvcis
// +kubebuilder:printcolumn:name="Ready",type="string",JSONPath=".status.conditions[?(@.type==\"Ready\")].status"
// +kubebuilder:printcolumn:name="Reason",type="string",JSONPath=".status.conditions[?(@.type==\"Ready\")].reason"
// +kubebuilder:printcolumn:name="Message",type="string",JSONPath=".status.conditions[?(@.type==\"Ready\")].message"
// +kubebuilder:printcolumn:name="LastTransition",type="date",JSONPath=".status.conditions[?(@.type==\"Ready\")].lastTransitionTime"
// +kubebuilder:printcolumn:name="ObservedGeneration",type="integer",JSONPath=".status.conditions[?(@.type==\"Ready\")].observedGeneration"
// +kubebuilder:printcolumn:name="Generation",type="integer",JSONPath=".metadata.generation"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// AzureKeyVaultClusterIssuer is the Schema for the AzureKeyVaultClusterIssuers API.
type AzureKeyVaultClusterIssuer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ClusterIssuerSpec     `json:"spec,omitempty"`
	Status v1alpha1.IssuerStatus `json:"status,omitempty"`
}

// ClusterIssuerSpec defines the desired state of AzureKeyVaultClusterIssuer
type ClusterIssuerSpec struct {
	BaseIssuerSpec `json:",inline"`

	// Auth configures how the issuer authenticates to Azure. When omitted, the
	// controller pod's own ambient Azure identity is used. This is not
	// available to namespaced issuers for security reasons.
	// +optional
	Auth *Auth `json:"auth,omitempty"`

	// AllowedNamespaces limits which namespaces may use this issuer. A request
	// from a namespace that is not listed is failed.
	// When omitted or empty, every namespace is allowed, as with cert-manager's
	// own ClusterIssuers. That suits clusters where every namespace may use the
	// CA, or where an approver such as approver-policy decides which requests
	// are approved.
	// Each entry is an exact namespace name, such as "prod". Wildcards are not
	// supported.
	// +optional
	// +listType=set
	// +kubebuilder:validation:items:MaxLength=63
	// +kubebuilder:validation:items:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	AllowedNamespaces []string `json:"allowedNamespaces,omitempty"`
}

// GetConditions returns the issuer's status conditions.
func (vi *AzureKeyVaultClusterIssuer) GetConditions() []metav1.Condition {
	return vi.Status.Conditions
}

// GetIssuerTypeIdentifier returns the identifier that issuer-lib uses for this
// kind, which is the same for every instance.
func (vi *AzureKeyVaultClusterIssuer) GetIssuerTypeIdentifier() string {
	return AzureKeyVaultClusterIssuerTypeIdentifier
}

// Checks that the type implements issuer-lib's Issuer interface.
var _ v1alpha1.Issuer = &AzureKeyVaultClusterIssuer{}

// +kubebuilder:object:root=true

// AzureKeyVaultClusterIssuerList contains a list of AzureKeyVaultClusterIssuer.
type AzureKeyVaultClusterIssuerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AzureKeyVaultClusterIssuer `json:"items"`
}
