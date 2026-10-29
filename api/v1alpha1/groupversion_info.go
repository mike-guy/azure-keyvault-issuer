package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// GroupName is the API group of every type in this package. It is compiled
// into the binary and forms part of the CRD names, signer names and every
// issuerRef, so it cannot be configured at deploy time.
const GroupName = "azure-keyvault-issuer.mike-guy.github.io"

var (
	// GroupVersion is the group and version used to register these types.
	GroupVersion = schema.GroupVersion{Group: GroupName, Version: "v1alpha1"}

	// SchemeBuilder collects the functions that add these types to a scheme.
	SchemeBuilder = runtime.NewSchemeBuilder(addKnownTypes)

	// AddToScheme adds these types to a runtime scheme.
	AddToScheme = SchemeBuilder.AddToScheme
)

func addKnownTypes(s *runtime.Scheme) error {
	s.AddKnownTypes(GroupVersion,
		&AzureKeyVaultIssuer{}, &AzureKeyVaultIssuerList{},
		&AzureKeyVaultClusterIssuer{}, &AzureKeyVaultClusterIssuerList{},
	)
	metav1.AddToGroupVersion(s, GroupVersion)

	return nil
}
