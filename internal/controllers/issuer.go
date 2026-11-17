package controllers

import (
	"fmt"

	issuerapi "github.com/cert-manager/issuer-lib/api/v1alpha1"

	api "github.com/mike-guy/azure-keyvault-issuer/api/v1alpha1"
)

// resolvedIssuer is the issuer-kind-agnostic view of an issuer, so the rest of
// the package never type-switches on the two kinds.
type resolvedIssuer struct {
	// name is the issuer's name, for logging.
	name string

	// namespace is the issuer's namespace. It is empty for a ClusterIssuer.
	namespace string

	// ambientAllowed says whether the issuer may omit auth and use the
	// controller's ambient identity. Only a ClusterIssuer may, as with
	// cert-manager's CanUseAmbientCredentials.
	ambientAllowed bool

	// secretNamespace is the namespace of the Secrets and ServiceAccount that
	// auth refers to: the issuer's own, or the cluster resource namespace.
	secretNamespace string

	// spec is the part of the spec common to both kinds.
	spec api.BaseIssuerSpec

	// auth is nil only for a ClusterIssuer that uses the ambient identity.
	auth *api.Auth

	// allowedNamespaces limits which namespaces may use a ClusterIssuer, as
	// exact names. An Issuer has no such field, so it is nil, and nil or
	// empty both mean that any namespace is permitted.
	allowedNamespaces []string
}

// resolveIssuer fills in a resolvedIssuer from either issuer kind. Any other
// type is a programmer error, so it is a plain error with no sentinel.
func (s *KeyVaultSigner) resolveIssuer(issuer issuerapi.Issuer) (resolvedIssuer, error) {
	switch i := issuer.(type) {
	case *api.AzureKeyVaultIssuer:
		return resolvedIssuer{
			name:              i.GetName(),
			namespace:         i.GetNamespace(),
			ambientAllowed:    false,
			secretNamespace:   i.GetNamespace(),
			spec:              i.Spec.BaseIssuerSpec,
			auth:              &i.Spec.Auth,
			allowedNamespaces: nil,
		}, nil
	case *api.AzureKeyVaultClusterIssuer:
		return resolvedIssuer{
			name:              i.GetName(),
			namespace:         "",
			ambientAllowed:    true,
			secretNamespace:   s.clusterResourceNamespace,
			spec:              i.Spec.BaseIssuerSpec,
			auth:              i.Spec.Auth,
			allowedNamespaces: i.Spec.AllowedNamespaces,
		}, nil
	default:
		return resolvedIssuer{}, fmt.Errorf("resolving issuer: unsupported type %T", issuer)
	}
}
