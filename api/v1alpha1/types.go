package v1alpha1

import (
	issuerlib "github.com/cert-manager/issuer-lib/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// The issuer-lib controller only accepts types that implement its interface.
var (
	_ issuerlib.Issuer = (*AzureKeyVaultIssuer)(nil)
	_ issuerlib.Issuer = (*AzureKeyVaultClusterIssuer)(nil)
)

// ChainSource says where the issuer reads the CA certificate chain from.
// +kubebuilder:validation:Enum=Certificate;Secret
type ChainSource string

const (
	// ChainSourceCertificate uses only the Key Vault certificate itself. It is
	// enough for a two-tier PKI (offline root, then the Key Vault CA).
	ChainSourceCertificate ChainSource = "Certificate"

	// ChainSourceSecret reads the full merged chain from the certificate's
	// backing secret. It needs the extra secrets/getSecret permission.
	ChainSourceSecret ChainSource = "Secret"
)

// AzureKeyVaultIssuerSpec is the desired state shared by AzureKeyVaultIssuer
// and AzureKeyVaultClusterIssuer.
type AzureKeyVaultIssuerSpec struct {
	// VaultURL is the URL of the Key Vault that holds the CA certificate, for
	// example https://my-ca.vault.azure.net/. Only the Azure public cloud is
	// supported, and the URL must have no path, query or user information.
	// +required
	// +kubebuilder:validation:Pattern=`^https://[a-z][a-z0-9-]{1,22}[a-z0-9]\.vault\.azure\.net/?$`
	// +kubebuilder:validation:XValidation:rule="!self.contains('--')",message="vaultURL must not contain consecutive hyphens"
	VaultURL string `json:"vaultURL"`

	// CertificateName is the name of the Key Vault certificate whose
	// non-exportable key is the CA key.
	// +required
	// +kubebuilder:validation:Pattern=`^[0-9a-zA-Z-]{1,127}$`
	CertificateName string `json:"certificateName"`

	// CertificateVersion optionally pins the certificate to one version. When
	// empty, Key Vault's current version is used, and the issuer fails if that
	// version is disabled or not yet issued; it never falls back to an older
	// version.
	// +optional
	// +kubebuilder:validation:Pattern=`^[0-9a-f]{32}$`
	CertificateVersion string `json:"certificateVersion,omitempty"`

	// ChainSource says where the CA chain is read from.
	// +optional
	// +kubebuilder:default=Certificate
	ChainSource ChainSource `json:"chainSource,omitempty"`

	// Policy limits what the issuer will sign.
	// +optional
	// +kubebuilder:default={}
	Policy Policy `json:"policy,omitempty"`

	// Auth says how the issuer authenticates to Azure. When omitted, the
	// controller's own (ambient) workload identity is used, if the controller
	// permits it for this kind of issuer.
	// +optional
	Auth *Auth `json:"auth,omitempty"`
}

// Policy is the issuance policy.
type Policy struct {
	// AllowCA permits requests for CA certificates (isCA: true). It is false
	// by default, so such requests are refused. Even when it is true, the Key
	// Vault CA's path length constraint applies: a CA with path length N
	// issues CAs with at most N - 1, and one with path length 0 issues none.
	// +optional
	// +kubebuilder:default=false
	AllowCA bool `json:"allowCA,omitempty"`

	// MaxDuration is the longest lifetime the issuer will give a certificate.
	// Longer requests are clamped rather than refused. Lifetimes are also
	// always clamped to the expiry of the CA chain. Short lifetimes
	// matter because the issuer offers no revocation. It is a pointer so that a
	// client that leaves it unset gets the CRD default (2160h) instead of
	// sending a zero value; after defaulting it is never nil.
	// +optional
	// +kubebuilder:default="2160h"
	// +kubebuilder:validation:XValidation:rule="duration(self) >= duration('1h')",message="maxDuration must be a valid duration of at least 1h"
	MaxDuration *metav1.Duration `json:"maxDuration,omitempty"`
}

// Auth selects how the issuer authenticates to Azure. At most one method may
// be set. Workload identity is preferred; the client certificate and client
// secret methods are fallbacks for clusters that cannot federate with
// Microsoft Entra.
// +kubebuilder:validation:XValidation:rule="[has(self.workloadIdentity), has(self.clientCertificate), has(self.clientSecret)].filter(m, m).size() <= 1",message="at most one authentication method may be set"
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

	// TenantID is the Entra tenant ID. When empty, the controller's
	// configured default is used.
	// +optional
	// +kubebuilder:validation:Pattern=`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`
	TenantID string `json:"tenantID,omitempty"`

	// ServiceAccountRef names the ServiceAccount the controller requests a
	// token for. For an AzureKeyVaultIssuer it is in the issuer's namespace.
	// For an AzureKeyVaultClusterIssuer it is in the controller's cluster
	// resource namespace.
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

	// TenantID is the Entra tenant ID. When empty, the controller's
	// configured default is used.
	// +optional
	// +kubebuilder:validation:Pattern=`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`
	TenantID string `json:"tenantID,omitempty"`

	// SecretRef names a Secret holding the certificate in tls.crt and its
	// unencrypted RSA private key in tls.key, both PEM-encoded, as in a
	// kubernetes.io/tls Secret. For an AzureKeyVaultIssuer it is in the
	// issuer's namespace. For an AzureKeyVaultClusterIssuer it is in the
	// controller's cluster resource namespace. The Secret is read whenever a
	// token is needed, so updating it in place rotates the certificate.
	// +required
	SecretRef SecretRef `json:"secretRef"`
}

// ClientSecret configures authentication with an Entra application's client
// secret.
type ClientSecret struct {
	// ClientID is the client ID of the Entra application the secret belongs
	// to.
	// +required
	// +kubebuilder:validation:Pattern=`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`
	ClientID string `json:"clientID"`

	// TenantID is the Entra tenant ID. When empty, the controller's
	// configured default is used.
	// +optional
	// +kubebuilder:validation:Pattern=`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`
	TenantID string `json:"tenantID,omitempty"`

	// SecretRef names the Secret and key holding the client secret. For an
	// AzureKeyVaultIssuer it is in the issuer's namespace. For an
	// AzureKeyVaultClusterIssuer it is in the controller's cluster resource
	// namespace. The Secret is read whenever a token is needed, so updating it
	// in place rotates the client secret.
	// +required
	SecretRef SecretKeyRef `json:"secretRef"`
}

// SecretRef names a Secret. Its namespace is implied by the kind of issuer
// that holds the reference.
type SecretRef struct {
	// Name is the name of the Secret.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name"`
}

// SecretKeyRef names one key in a Secret. Its namespace is implied by the
// kind of issuer that holds the reference.
type SecretKeyRef struct {
	// Name is the name of the Secret.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name"`

	// Key is the key within the Secret's data.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[-._a-zA-Z0-9]+$`
	Key string `json:"key"`
}
