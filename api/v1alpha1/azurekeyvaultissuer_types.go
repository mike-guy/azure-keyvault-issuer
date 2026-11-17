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

// AzureKeyVaultIssuerTypeIdentifier identifies the namespaced issuer kind to
// issuer-lib, in the form "<plural resource>.<group>".
const AzureKeyVaultIssuerTypeIdentifier = "azurekeyvaultissuers." + GroupName

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=akvi;akvis
// +kubebuilder:printcolumn:name="Ready",type="string",JSONPath=".status.conditions[?(@.type==\"Ready\")].status"
// +kubebuilder:printcolumn:name="Reason",type="string",JSONPath=".status.conditions[?(@.type==\"Ready\")].reason"
// +kubebuilder:printcolumn:name="Message",type="string",JSONPath=".status.conditions[?(@.type==\"Ready\")].message"
// +kubebuilder:printcolumn:name="LastTransition",type="date",JSONPath=".status.conditions[?(@.type==\"Ready\")].lastTransitionTime"
// +kubebuilder:printcolumn:name="ObservedGeneration",type="integer",JSONPath=".status.conditions[?(@.type==\"Ready\")].observedGeneration"
// +kubebuilder:printcolumn:name="Generation",type="integer",JSONPath=".metadata.generation"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// AzureKeyVaultIssuer is the Schema for the AzureKeyVaultIssuers API.
type AzureKeyVaultIssuer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   IssuerSpec            `json:"spec,omitempty"`
	Status v1alpha1.IssuerStatus `json:"status,omitempty"`
}

// IssuerSpec defines the desired state of AzureKeyVaultIssuer
type IssuerSpec struct {
	BaseIssuerSpec `json:",inline"`

	// Auth configures how the issuer authenticates to Azure. Unlike an
	// AzureKeyVaultClusterIssuer, a namespaced issuer cannot use the controller's
	// own identity, as anyone able to create one would gain its Azure permissions.
	// +required
	Auth Auth `json:"auth"`
}

// GetConditions returns the issuer's status conditions.
func (vi *AzureKeyVaultIssuer) GetConditions() []metav1.Condition {
	return vi.Status.Conditions
}

// GetIssuerTypeIdentifier returns the identifier that issuer-lib uses for this
// kind, which is the same for every instance.
func (vi *AzureKeyVaultIssuer) GetIssuerTypeIdentifier() string {
	return AzureKeyVaultIssuerTypeIdentifier
}

// Checks that the type implements issuer-lib's Issuer interface.
var _ v1alpha1.Issuer = &AzureKeyVaultIssuer{}

// +kubebuilder:object:root=true

// AzureKeyVaultIssuerList contains a list of AzureKeyVaultIssuer.
type AzureKeyVaultIssuerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AzureKeyVaultIssuer `json:"items"`
}
