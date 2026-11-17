package controllers

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	azpolicy "github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	issuerapi "github.com/cert-manager/issuer-lib/api/v1alpha1"
	"github.com/cert-manager/issuer-lib/controllers/signer"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"

	api "github.com/mike-guy/azure-keyvault-issuer/api/v1alpha1"
	"github.com/mike-guy/azure-keyvault-issuer/internal/azure/credential"
	"github.com/mike-guy/azure-keyvault-issuer/internal/azure/vault"
	"github.com/mike-guy/azure-keyvault-issuer/internal/pki"
)

// errUnclassified is an error that no sentinel names, such as throttling or a
// network failure.
var errUnclassified = errors.New("429 too many requests")

// unsupportedIssuer satisfies issuerapi.Issuer without being one of the two
// kinds this package knows. Its embedded interface is nil, so only the type
// matters.
type unsupportedIssuer struct {
	issuerapi.Issuer
}

// testCert is a certificate with its key and PEM encoding, so a test can sign
// the next certificate down a chain.
type testCert struct {
	cert *x509.Certificate
	key  crypto.Signer
	pem  []byte
}

// newTestCert returns a certificate for name, signed by parent. A nil parent
// makes it self-signed.
func newTestCert(t *testing.T, name string, isCA bool, parent *testCert) testCert {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatalf("generating serial number: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  isCA,
	}

	if isCA {
		template.KeyUsage |= x509.KeyUsageCertSign
	}

	signerCert, signerKey := template, crypto.Signer(key)
	if parent != nil {
		signerCert, signerKey = parent.cert, parent.key
	}

	der, err := x509.CreateCertificate(rand.Reader, template, signerCert, key.Public(), signerKey)
	if err != nil {
		t.Fatalf("creating certificate %q: %v", name, err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing certificate %q: %v", name, err)
	}

	return testCert{
		cert: cert,
		key:  key,
		pem:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
	}
}

// stubTokenCredential is the credential that fakeCredentials hands out.
type stubTokenCredential struct{}

func (stubTokenCredential) GetToken(context.Context, azpolicy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{Token: "", ExpiresOn: time.Time{}, RefreshOn: time.Time{}}, nil
}

// fakeCredentials is a credentialBuilder that records its arguments and fails
// with err when it is set.
type fakeCredentials struct {
	err error

	calls      int
	issuerType credential.IssuerType
	auth       *api.Auth
	namespace  string
}

func (f *fakeCredentials) BuildTokenFetcher(_ context.Context, issType credential.IssuerType, auth *api.Auth, ns string) (azcore.TokenCredential, error) {
	f.calls++
	f.issuerType = issType
	f.auth = auth
	f.namespace = ns

	if f.err != nil {
		return nil, f.err
	}

	return stubTokenCredential{}, nil
}

// fakeFactory is an authorityFactory that records its arguments and returns
// authority, or err when it is set.
type fakeFactory struct {
	authority pki.Authority
	err       error

	calls int
	cfg   vault.Config
	cred  azcore.TokenCredential
}

func (f *fakeFactory) build(_ context.Context, cfg vault.Config, cred azcore.TokenCredential) (pki.Authority, error) {
	f.calls++
	f.cfg = cfg
	f.cred = cred

	if f.err != nil {
		return nil, f.err
	}

	return f.authority, nil
}

// fakeAuthority is a pki.Authority whose key is in memory.
type fakeAuthority struct {
	crypto.Signer

	cert  *x509.Certificate
	chain []*x509.Certificate
}

func (f *fakeAuthority) Certificate() *x509.Certificate { return f.cert }

func (f *fakeAuthority) Chain() []*x509.Certificate { return f.chain }

// exportableAuthority is a fakeAuthority that also says whether its key is
// exportable, as the vault's authority does.
type exportableAuthority struct {
	*fakeAuthority

	exportable bool
}

func (e *exportableAuthority) KeyExportable() bool { return e.exportable }

// newFakeAuthority returns an authority that is an intermediate beneath a
// self-signed root, and the root.
func newFakeAuthority(t *testing.T) (*fakeAuthority, testCert) {
	t.Helper()

	root := newTestCert(t, "root", true, nil)
	inter := newTestCert(t, "inter", true, &root)

	return &fakeAuthority{Signer: inter.key, cert: inter.cert, chain: []*x509.Certificate{root.cert}}, root
}

// recordedEvent is an event that fakeEvents was given, with its note formatted.
type recordedEvent struct {
	regarding runtime.Object
	eventType string
	reason    string
	action    string
	note      string
}

// fakeEvents is an eventRecorder that keeps what it is given.
type fakeEvents struct {
	events []recordedEvent
}

func (f *fakeEvents) Eventf(regarding, _ runtime.Object, eventType, reason, action, note string, args ...any) {
	f.events = append(f.events, recordedEvent{
		regarding: regarding,
		eventType: eventType,
		reason:    reason,
		action:    action,
		note:      fmt.Sprintf(note, args...),
	})
}

// defaultSignerOptions returns the options that the command's flags default to,
// for a test to change the one field it is about.
func defaultSignerOptions() SignerOptions {
	return SignerOptions{
		ReconcileTimeout:      DefaultReconcileTimeout,
		CAExpiryWarnThreshold: DefaultCAExpiryWarningThreshold,
		WarnOnExportableCAKey: DefaultWarnOnExportableCAKey,
	}
}

// newSignerWithEvents returns a KeyVaultSigner with the given dependencies, and
// "cert-manager" as its cluster resource namespace, with the events recorder it
// holds so a test can check what was recorded.
func newSignerWithEvents(t *testing.T, creds credentialBuilder, factory authorityFactory) (*KeyVaultSigner, *fakeEvents) {
	t.Helper()

	events := &fakeEvents{events: nil}

	s, err := NewKeyVaultSigner(creds, factory, events, "cert-manager", defaultSignerOptions())
	if err != nil {
		t.Fatalf("NewKeyVaultSigner() error = %v, want nil", err)
	}

	return s, events
}

// newSignerUnderTest returns a KeyVaultSigner as newSignerWithEvents does, for
// tests that do not look at its events.
func newSignerUnderTest(t *testing.T, creds credentialBuilder, factory authorityFactory) *KeyVaultSigner {
	t.Helper()

	s, _ := newSignerWithEvents(t, creds, factory)

	return s
}

// newIdleSigner returns a KeyVaultSigner for tests that never reach Key Vault,
// with the credential builder it holds so a test can check it was not used.
func newIdleSigner(t *testing.T) (*KeyVaultSigner, *fakeCredentials) {
	t.Helper()

	creds := &fakeCredentials{err: nil, calls: 0, issuerType: "", auth: nil, namespace: ""}
	factory := &fakeFactory{authority: nil, err: nil, calls: 0, cfg: vault.Config{}, cred: nil}

	return newSignerUnderTest(t, creds, factory.build), creds
}

// fakeRequest is a signer.CertificateRequestObject.
type fakeRequest struct {
	metav1.ObjectMeta

	details    signer.CertificateDetails
	detailsErr error
}

func (f *fakeRequest) GetCertificateDetails() (signer.CertificateDetails, error) {
	return f.details, f.detailsErr
}

func (f *fakeRequest) GetConditions() []metav1.Condition { return nil }

// GetObjectKind and DeepCopyObject make fakeRequest a runtime.Object, as the
// real request implementations are, so that an event can be recorded on it.
func (f *fakeRequest) GetObjectKind() schema.ObjectKind { return schema.EmptyObjectKind }

func (f *fakeRequest) DeepCopyObject() runtime.Object {
	c := *f

	return &c
}

// newCSRPEM returns a PEM encoded request for a certificate for dnsName.
func newCSRPEM(t *testing.T, dnsName string) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: dnsName},
		DNSNames: []string{dnsName},
	}, key)
	if err != nil {
		t.Fatalf("creating certificate request: %v", err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

// newTestRequest returns a request from namespace for a leaf certificate.
func newTestRequest(t *testing.T, namespace string, duration time.Duration) *fakeRequest {
	t.Helper()

	return &fakeRequest{
		ObjectMeta: metav1.ObjectMeta{Name: "my-request", Namespace: namespace},
		details: signer.CertificateDetails{
			CSR:         newCSRPEM(t, "app.example.com"),
			Duration:    duration,
			IsCA:        false,
			MaxPathLen:  nil,
			KeyUsage:    x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		},
		detailsErr: nil,
	}
}

// baseSpec returns a valid spec common to both issuer kinds.
func baseSpec() api.BaseIssuerSpec {
	return api.BaseIssuerSpec{
		VaultURL:           "https://my-ca.vault.azure.net/",
		CertificateName:    "ca",
		CertificateVersion: "v1",
		ChainInSecret:      true,
		Policy:             api.Policy{AllowCA: false, AllowedExtKeyUsages: nil, MaxDuration: nil, AllowedDomains: nil},
	}
}

func namespacedIssuer(namespace string) *api.AzureKeyVaultIssuer {
	return &api.AzureKeyVaultIssuer{
		TypeMeta:   metav1.TypeMeta{Kind: "", APIVersion: ""},
		ObjectMeta: metav1.ObjectMeta{Name: "my-issuer", Namespace: namespace},
		Spec: api.IssuerSpec{
			BaseIssuerSpec: baseSpec(),
			Auth:           api.Auth{WorkloadIdentity: nil, ClientCertificate: nil, ClientSecret: nil},
		},
		Status: issuerapi.IssuerStatus{},
	}
}

func clusterIssuer(auth *api.Auth, allowedNamespaces []string) *api.AzureKeyVaultClusterIssuer {
	return &api.AzureKeyVaultClusterIssuer{
		TypeMeta:   metav1.TypeMeta{Kind: "", APIVersion: ""},
		ObjectMeta: metav1.ObjectMeta{Name: "my-cluster-issuer", Namespace: ""},
		Spec: api.ClusterIssuerSpec{
			BaseIssuerSpec:    baseSpec(),
			Auth:              auth,
			AllowedNamespaces: allowedNamespaces,
		},
		Status: issuerapi.IssuerStatus{},
	}
}
