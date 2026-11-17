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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

const (
	// GroupName is the Kubernetes API group of every type in this package.
	GroupName = "azure-keyvault-issuer.mike-guy.github.io"

	// Version is the API version of every type in this package.
	Version = "v1alpha1"
)

var (
	// SchemeGroupVersion is the group version these objects are registered under.
	SchemeGroupVersion = schema.GroupVersion{Group: GroupName, Version: Version}

	// SchemeBuilder adds the Go types to a scheme.
	SchemeBuilder = runtime.NewSchemeBuilder(addKnownTypes)

	// AddToScheme adds the types in this group version to a scheme.
	AddToScheme = SchemeBuilder.AddToScheme
)

func addKnownTypes(scheme *runtime.Scheme) error {
	scheme.AddKnownTypes(SchemeGroupVersion,
		&AzureKeyVaultClusterIssuer{}, &AzureKeyVaultClusterIssuerList{},
		&AzureKeyVaultIssuer{}, &AzureKeyVaultIssuerList{},
	)

	metav1.AddToGroupVersion(scheme, SchemeGroupVersion)
	return nil
}
