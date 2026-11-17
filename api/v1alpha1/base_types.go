package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// BaseIssuerSpec is the part of the spec common to both issuer kinds.
type BaseIssuerSpec struct {
	// VaultURL is the URL of the Key Vault that holds the CA certificate, such as
	// https://my-ca.vault.azure.net/. Only the Azure public cloud is supported,
	// and the URL must have no path, query or user information.
	// +required
	// +kubebuilder:validation:MaxLength=50
	// +kubebuilder:validation:Pattern=`^https://[a-z][a-z0-9-]{1,22}[a-z0-9]\.vault\.azure\.net/?$`
	// +kubebuilder:validation:XValidation:rule="!self.contains('--')",message="vaultURL must not contain consecutive hyphens"
	VaultURL string `json:"vaultURL"`

	// CertificateName is the name of the Key Vault certificate, a CA
	// certificate with a non-exportable key, that signs requests.
	// +required
	// +kubebuilder:validation:Pattern=`^[0-9a-zA-Z-]{1,127}$`
	CertificateName string `json:"certificateName"`

	// CertificateVersion optionally pins the certificate to a version. When
	// empty, Key Vault's current version is used, and the issuer fails if that
	// is disabled or not yet issued, rather than falling back to an older one.
	// +optional
	// +kubebuilder:validation:Pattern=`^[0-9a-f]{32}$`
	CertificateVersion string `json:"certificateVersion,omitempty"`

	// ChainInSecret says that the certificate's backing secret holds the
	// intermediate CAs above the Key Vault CA. When false (the default), the
	// Key Vault CA is assumed to be issued directly by a root and the secret is
	// never read.
	// When true, the issuer fails unless the secret holds at least one
	// certificate above the Key Vault CA. The chain is built upwards from the CA,
	// enforcing each link's path length constraint, and anything else in the
	// secret is ignored with a warning. The root may be omitted.
	// +optional
	// +kubebuilder:default=false
	ChainInSecret bool `json:"chainInSecret,omitempty"`

	// Policy limits what the issuer will sign.
	// +optional
	// +kubebuilder:default={}
	Policy Policy `json:"policy,omitempty"`
}

// Policy limits what the issuer will sign.
type Policy struct {
	// AllowCA permits requests for CA certificates (isCA: true). It is false
	// by default, so such requests are refused.
	// When true, the Key Vault CA's path length constraint still applies: a CA
	// with path length N issues CAs with at most N - 1, and one with a path
	// length of 0 can issue none. If nothing in the chain sets a limit, the new CA
	// may only issue end certificates. A CA is limited to allowedExtKeyUsages like
	// any request, and its subject must differ from that of the Key Vault CA
	// and its chain.
	// It cannot be combined with allowedDomains, as a new CA could not be
	// restricted to those domains. The issuer is not Ready while both are set.
	// +optional
	// +kubebuilder:default=false
	AllowCA bool `json:"allowCA,omitempty"`

	// AllowedExtKeyUsages limits the extended key usages that a request may ask
	// for, using the names of a Certificate's usages. A request for any other
	// usage is failed, for an end certificate or a CA.
	// The default is "server auth" and "client auth", so other usages such as
	// "code signing" must be listed. "any" permits every usage.
	// A Certificate that sets no usages gets "server auth", so that must be
	// listed for it to be signed. A request that names key usages but no
	// extended key usage is failed, as such a certificate is valid for any
	// usage.
	// +optional
	// +listType=set
	// +kubebuilder:default={"server auth","client auth"}
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:items:Enum="any";"server auth";"client auth";"code signing";"email protection";"s/mime";"ipsec end system";"ipsec tunnel";"ipsec user";"timestamping";"ocsp signing";"microsoft sgc";"netscape sgc"
	AllowedExtKeyUsages []string `json:"allowedExtKeyUsages,omitempty"`

	// MaxDuration is the longest lifetime the issuer will use for a certificate.
	// Longer requests are clamped rather than refused. Lifetimes are also always
	// clamped to the expiry of the CA chain. Short lifetimes matter, as the
	// issuer offers no revocation.
	// +optional
	// +kubebuilder:default="2160h"
	// +kubebuilder:validation:XValidation:rule="duration(self) >= duration('1h')",message="maxDuration must be a valid duration of at least 1h"
	MaxDuration *metav1.Duration `json:"maxDuration,omitempty"`

	// AllowedDomains limits the DNS names that the issuer will sign. When
	// omitted or empty, any name is signed. A request for a name that no entry
	// permits will fail. Each entry is one of:
	//   - a name, such as "app.example.com", which permits exactly that name;
	//   - "*.example.com", which permits one label below the domain, such as
	//     "app.example.com" but not "example.com" or "a.b.example.com";
	//   - "**.example.com", which permits any number of labels below the domain,
	//     such as "app.example.com" and "a.b.example.com", but not "example.com".
	// The bare domain is never implied: list "example.com" as well to allow it.
	// A wildcard needs at least two labels after it, so "*.com" is not allowed.
	// A requested wildcard name counts as one label, so "*.example.com" is
	// permitted by "*.example.com" and "**.example.com". Matching ignores case.
	// When this is set, the request must have a DNS name or a common name, and
	// every one must be permitted. A request for an IP address, email address or
	// URI is failed, as is a subject with attributes other than a common name,
	// as a list of domains cannot restrict them.
	// This is a guardrail for clusters without approver-policy, which is the
	// better tool where installed as it can restrict names per requester. On an
	// AzureKeyVaultIssuer it only guards against mistakes, as whoever can edit
	// the Issuer can edit the list.
	// +optional
	// +listType=set
	// +kubebuilder:validation:MaxItems=100
	// +kubebuilder:validation:items:MaxLength=253
	// +kubebuilder:validation:items:Pattern=`^([a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?(\.[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?)*|\*{1,2}(\.[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?){2,})$`
	AllowedDomains []string `json:"allowedDomains,omitempty"`
}

// Auth selects how the issuer authenticates to Azure. Exactly one method must
// be set. Workload identity is preferred; the client certificate and client
// secret methods are fallbacks for clusters that cannot federate with
// Microsoft Entra.
// +kubebuilder:validation:XValidation:rule="[has(self.workloadIdentity), has(self.clientCertificate), has(self.clientSecret)].filter(m, m).size() == 1",message="exactly one authentication method must be set"
type Auth struct {
	// WorkloadIdentity authenticates by exchanging a token for a named
	// ServiceAccount through Microsoft Entra workload identity federation.
	// +optional
	WorkloadIdentity *WorkloadIdentity `json:"workloadIdentity,omitempty"`

	// ClientCertificate authenticates as an Entra application with a
	// certificate and RSA private key held in a Kubernetes Secret.
	// +optional
	ClientCertificate *ClientCertificate `json:"clientCertificate,omitempty"`

	// ClientSecret authenticates as an Entra application with a client secret
	// held in a Kubernetes Secret. It is a last resort: prefer workload
	// identity, then a client certificate.
	// +optional
	ClientSecret *ClientSecret `json:"clientSecret,omitempty"`
}

// WorkloadIdentity configures workload identity with a ServiceAccount
// reference.
type WorkloadIdentity struct {
	// ClientID is the client ID of the Entra application or user-assigned
	// managed identity that has the federated credential.
	// +required
	// +kubebuilder:validation:Pattern=`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`
	ClientID string `json:"clientID"`

	// TenantID is the Entra tenant ID.
	// +required
	// +kubebuilder:validation:Pattern=`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`
	TenantID string `json:"tenantID"`

	// ServiceAccountRef names the ServiceAccount the controller requests a
	// token for. For an AzureKeyVaultIssuer it is in the issuer's namespace; for
	// an AzureKeyVaultClusterIssuer, in the controller's cluster resource
	// namespace.
	// +required
	ServiceAccountRef ServiceAccountRef `json:"serviceAccountRef"`
}

// ServiceAccountRef names a ServiceAccount. Its namespace is implied by the
// kind of issuer that holds the reference.
type ServiceAccountRef struct {
	// Name is the name of the ServiceAccount.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name"`
}

// ClientCertificate configures authentication with an Entra application's
// certificate.
type ClientCertificate struct {
	// ClientID is the client ID of the Entra application the certificate is
	// registered with.
	// +required
	// +kubebuilder:validation:Pattern=`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`
	ClientID string `json:"clientID"`

	// TenantID is the Entra tenant ID.
	// +required
	// +kubebuilder:validation:Pattern=`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`
	TenantID string `json:"tenantID"`

	// SecretRef names a Secret holding the PEM-encoded certificate under tls.crt
	// and the unencrypted, PEM-encoded RSA private key under tls.key, such as a
	// kubernetes.io/tls Secret or one issued by cert-manager.
	// For an AzureKeyVaultIssuer the Secret is in the issuer's namespace; for an
	// AzureKeyVaultClusterIssuer, in the controller's cluster resource namespace.
	// It is read on every check and signing, so updating it in place rotates the
	// certificate.
	// +required
	SecretRef SecretSelector `json:"secretRef"`
}

// ClientSecret configures authentication with an Entra application's client
// secret.
type ClientSecret struct {
	// ClientID is the client ID of the Entra application the secret belongs
	// to.
	// +required
	// +kubebuilder:validation:Pattern=`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`
	ClientID string `json:"clientID"`

	// TenantID is the Entra tenant ID.
	// +required
	// +kubebuilder:validation:Pattern=`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`
	TenantID string `json:"tenantID"`

	// SecretRef selects the client secret. For an AzureKeyVaultIssuer the Secret
	// is in the issuer's namespace; for an AzureKeyVaultClusterIssuer, in the
	// controller's cluster resource namespace.
	// It is read on every check and signing, so updating it in place rotates the
	// client secret.
	// +required
	SecretRef SecretKeySelector `json:"secretRef"`
}

// SecretSelector selects a Secret. Its namespace is implied by the kind of
// issuer that holds the selector.
type SecretSelector struct {
	// Name is the name of the Secret.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name"`
}

// SecretKeySelector selects a key of a Secret. The Secret's namespace is
// implied by the kind of issuer that holds the selector.
type SecretKeySelector struct {
	// Name is the name of the Secret.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name"`

	// Key is the key in the Secret's data to use.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[-._a-zA-Z0-9]+$`
	Key string `json:"key"`
}
