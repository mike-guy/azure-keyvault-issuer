package vault

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azcertificates"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
)

// Compile-time checks that the fakes used across this package's tests satisfy
// the interfaces they stand in for.
var (
	_ certFetcher   = (*fakeCertFetcher)(nil)
	_ secretFetcher = (*fakeSecretFetcher)(nil)
	_ keySigner     = (*fakeKeySigner)(nil)
)

const testVaultURL = "https://test.vault.azure.net/"

// certCall is one call recorded by fakeCertFetcher.
type certCall struct {
	name    string
	version string
}

// fakeCertFetcher stands in for the Key Vault certificates client. It returns
// err if it is set, otherwise resp, and records every call, in order. The
// policy has its own response and error, so a test can fail one and not the other.
type fakeCertFetcher struct {
	resp        azcertificates.GetCertificateResponse
	err         error
	calls       []certCall
	policyResp  azcertificates.GetCertificatePolicyResponse
	policyErr   error
	policyCalls []string
}

func (f *fakeCertFetcher) GetCertificatePolicy(_ context.Context, name string, _ *azcertificates.GetCertificatePolicyOptions) (azcertificates.GetCertificatePolicyResponse, error) {
	f.policyCalls = append(f.policyCalls, name)

	if f.policyErr != nil {
		return azcertificates.GetCertificatePolicyResponse{}, f.policyErr
	}

	return f.policyResp, nil
}

// exportablePolicy returns a policy response whose key is, or is not, exportable.
func exportablePolicy(exportable bool) azcertificates.GetCertificatePolicyResponse {
	return azcertificates.GetCertificatePolicyResponse{
		CertificatePolicy: azcertificates.CertificatePolicy{
			KeyProperties: &azcertificates.KeyProperties{Exportable: to.Ptr(exportable)},
		},
	}
}

func (f *fakeCertFetcher) GetCertificate(_ context.Context, name string, version string, _ *azcertificates.GetCertificateOptions) (azcertificates.GetCertificateResponse, error) {
	f.calls = append(f.calls, certCall{name: name, version: version})

	if f.err != nil {
		return azcertificates.GetCertificateResponse{}, f.err
	}

	return f.resp, nil
}

// secretCall is one call recorded by fakeSecretFetcher. outContentType is the
// format the call asked Key Vault to convert the secret to, empty for none.
type secretCall struct {
	name           string
	version        string
	outContentType string
}

// fakeSecretFetcher stands in for the Key Vault secrets client. It returns
// err if it is set, otherwise resp, and records every call, in order.
type fakeSecretFetcher struct {
	resp  azsecrets.GetSecretResponse
	err   error
	calls []secretCall
}

func (f *fakeSecretFetcher) GetSecret(_ context.Context, name string, version string, options *azsecrets.GetSecretOptions) (azsecrets.GetSecretResponse, error) {
	outContentType := ""
	if options != nil && options.OutContentType != nil {
		outContentType = string(*options.OutContentType)
	}

	f.calls = append(f.calls, secretCall{name: name, version: version, outContentType: outContentType})

	if f.err != nil {
		return azsecrets.GetSecretResponse{}, f.err
	}

	return f.resp, nil
}

// liveSpec is newCertSpec valid around now. newCertificateAuthority checks
// validity against the real clock, not chainTestNow.
func liveSpec(commonName string, now time.Time) certSpec {
	spec := newCertSpec(commonName)
	spec.notBefore = now.Add(-time.Hour)
	spec.notAfter = now.Add(time.Hour)

	return spec
}

// pemOf returns certs as PEM, in the order given.
func pemOf(certs ...*x509.Certificate) string {
	var b strings.Builder

	for _, c := range certs {
		b.WriteString(encodePEM("CERTIFICATE", c.Raw))
	}

	return b.String()
}

// secretResponse returns a secret response with only the fields
// secretInfoFrom relies on set.
func secretResponse(value, contentType *string) azsecrets.GetSecretResponse {
	return azsecrets.GetSecretResponse{
		Secret: azsecrets.Secret{
			Attributes:  nil,
			ContentType: contentType,
			ID:          nil,
			KID:         nil,
			Managed:     nil,
			Tags:        nil,
			Value:       value,
		},
	}
}

// checkAuthority asserts the outcome of loading a CertificateAuthority. With
// wantErr nil and wantMsg empty it expects success. Otherwise it expects an
// error that wraps wantErr (when set), contains wantMsg and does not wrap any
// sentinel (ErrInvalidConfig, ErrNotFound, ErrAccessDenied,
// ErrCertificateUnusable) unless it is wantErr, so an unclassified error can't
// be misclassified.
func checkAuthority(t *testing.T, fn string, ca *CertificateAuthority, err, wantErr error, wantMsg string) {
	t.Helper()

	if wantErr == nil && wantMsg == "" {
		if err != nil {
			t.Fatalf("%s() error = %v, want nil", fn, err)
		}

		if ca == nil {
			t.Fatalf("%s() authority = nil, want non-nil", fn)
		}

		return
	}

	if err == nil {
		t.Fatalf("%s() error = nil, want error containing %q", fn, wantMsg)
	}

	if ca != nil {
		t.Errorf("%s() authority = non-nil, want nil on error", fn)
	}

	if wantErr != nil && !errors.Is(err, wantErr) {
		t.Errorf("%s() error = %v, want it to wrap %v", fn, err, wantErr)
	}

	for _, sentinel := range []error{ErrInvalidConfig, ErrNotFound, ErrAccessDenied, ErrCertificateUnusable} {
		if !errors.Is(wantErr, sentinel) && errors.Is(err, sentinel) {
			t.Errorf("%s() error = %v, want it not to wrap %v", fn, err, sentinel)
		}
	}

	if !strings.Contains(err.Error(), wantMsg) {
		t.Errorf("%s() error = %q, want it to contain %q", fn, err, wantMsg)
	}
}

func TestNewCertificateAuthority(t *testing.T) {
	t.Parallel()

	// Every case fails before a client is built, so no network is involved.
	tests := []struct {
		name    string
		cfg     Config
		wantErr error
		wantMsg string // substring expected in the error message
	}{
		{
			name:    "invalid vault url fails validation",
			cfg:     Config{VaultURL: "http://test.vault.azure.net/", CertificateName: testCertName, CertificateVersion: "", ChainInSecret: false},
			wantErr: ErrInvalidConfig,
			wantMsg: "vaultURL",
		},
		{
			name:    "empty certificate name fails validation",
			cfg:     Config{VaultURL: testVaultURL, CertificateName: "", CertificateVersion: "", ChainInSecret: false},
			wantErr: ErrInvalidConfig,
			wantMsg: "certificateName must not be empty",
		},
		{
			name:    "nil credential fails",
			cfg:     Config{VaultURL: testVaultURL, CertificateName: testCertName, CertificateVersion: "", ChainInSecret: false},
			wantErr: nil,
			wantMsg: "credential must not be nil",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ca, err := NewCertificateAuthority(context.Background(), tt.cfg, nil, nil)

			checkAuthority(t, "NewCertificateAuthority", ca, err, tt.wantErr, tt.wantMsg)
		})
	}
}

func TestLoadCertificateAuthority(t *testing.T) {
	t.Parallel()

	now := time.Now()

	// root > intermediate > ca is the chain the vault issuing CA normally sits in.
	root := issue(t, liveSpec("root", now), nil)
	intermediate := issue(t, liveSpec("intermediate", now), root)
	ca := issue(t, liveSpec("ca", now), intermediate)
	unrelated := issue(t, liveSpec("unrelated", now), nil)

	// A CA whose intermediate expired a minute ago.
	expiredIntermediateSpec := liveSpec("expired-intermediate", now)
	expiredIntermediateSpec.notBefore = now.Add(-2 * time.Hour)
	expiredIntermediateSpec.notAfter = now.Add(-time.Minute)
	expiredIntermediate := issue(t, expiredIntermediateSpec, root)
	caUnderExpired := issue(t, liveSpec("ca-under-expired", now), expiredIntermediate)

	expiredCASpec := liveSpec("expired-ca", now)
	expiredCASpec.notBefore = now.Add(-2 * time.Hour)
	expiredCASpec.notAfter = now.Add(-time.Minute)
	expiredCA := issue(t, expiredCASpec, nil)

	notCASpec := liveSpec("not-ca", now)
	notCASpec.isCA = false
	notCASpec.basicConstraintsValid = false
	notCA := issue(t, notCASpec, nil)

	caKeyDER, err := x509.MarshalPKCS8PrivateKey(ca.key)
	if err != nil {
		t.Fatalf("marshalling private key: %v", err)
	}

	errFetch := errors.New("connection reset")

	cfgNoChain := Config{VaultURL: testVaultURL, CertificateName: testCertName, CertificateVersion: "", ChainInSecret: false}
	cfgPinned := Config{VaultURL: testVaultURL, CertificateName: testCertName, CertificateVersion: testCertVersion, ChainInSecret: false}
	cfgChain := Config{VaultURL: testVaultURL, CertificateName: testCertName, CertificateVersion: "", ChainInSecret: true}

	enabled := certAttributes(to.Ptr(true))
	disabled := certAttributes(to.Ptr(false))

	caResp := certResponse(to.Ptr(testCertID), ca.cert.Raw, enabled)

	newCerts := func(resp azcertificates.GetCertificateResponse, err error) *fakeCertFetcher {
		return &fakeCertFetcher{resp: resp, err: err, calls: nil, policyResp: exportablePolicy(false), policyErr: nil, policyCalls: nil}
	}

	newSecrets := func(resp azsecrets.GetSecretResponse, err error) *fakeSecretFetcher {
		return &fakeSecretFetcher{resp: resp, err: err, calls: nil}
	}

	pemSecret := func(value string) azsecrets.GetSecretResponse {
		return secretResponse(to.Ptr(value), to.Ptr(contentTypePEM))
	}

	unusedSecrets := newSecrets(azsecrets.GetSecretResponse{}, nil)

	wantCertCalls := []certCall{{name: testCertName, version: ""}}
	wantPinnedCertCalls := []certCall{{name: testCertName, version: testCertVersion}}
	// The secret is always requested as PEM, whatever format it is stored in.
	wantSecretCalls := []secretCall{{name: testCertName, version: testCertVersion, outContentType: contentTypePEM}}

	tests := []struct {
		name            string
		cfg             Config
		certs           *fakeCertFetcher
		secrets         *fakeSecretFetcher
		wantCert        *x509.Certificate
		wantChain       []*x509.Certificate
		wantErr         error
		wantMsg         string // substring expected in the error message, empty means success
		wantCertCalls   []certCall
		wantSecretCalls []secretCall
	}{
		{
			name:            "no chain requested resolves the current version and leaves the secret unread",
			cfg:             cfgNoChain,
			certs:           newCerts(caResp, nil),
			secrets:         newSecrets(pemSecret(pemOf(ca.cert, intermediate.cert, root.cert)), nil),
			wantCert:        ca.cert,
			wantChain:       nil,
			wantErr:         nil,
			wantMsg:         "",
			wantCertCalls:   wantCertCalls,
			wantSecretCalls: nil,
		},
		{
			name:            "pinned version is requested from the vault",
			cfg:             cfgPinned,
			certs:           newCerts(caResp, nil),
			secrets:         unusedSecrets,
			wantCert:        ca.cert,
			wantChain:       nil,
			wantErr:         nil,
			wantMsg:         "",
			wantCertCalls:   wantPinnedCertCalls,
			wantSecretCalls: nil,
		},
		{
			name:            "chain is read from the secret at the resolved version",
			cfg:             cfgChain,
			certs:           newCerts(caResp, nil),
			secrets:         newSecrets(pemSecret(pemOf(ca.cert, intermediate.cert, root.cert)), nil),
			wantCert:        ca.cert,
			wantChain:       []*x509.Certificate{intermediate.cert, root.cert},
			wantErr:         nil,
			wantMsg:         "",
			wantCertCalls:   wantCertCalls,
			wantSecretCalls: wantSecretCalls,
		},
		{
			name:            "chain is ordered whatever order the secret holds it in",
			cfg:             cfgChain,
			certs:           newCerts(caResp, nil),
			secrets:         newSecrets(pemSecret(pemOf(root.cert, ca.cert, intermediate.cert)), nil),
			wantCert:        ca.cert,
			wantChain:       []*x509.Certificate{intermediate.cert, root.cert},
			wantErr:         nil,
			wantMsg:         "",
			wantCertCalls:   wantCertCalls,
			wantSecretCalls: wantSecretCalls,
		},
		{
			name:            "secret without the CA's own certificate still chains",
			cfg:             cfgChain,
			certs:           newCerts(caResp, nil),
			secrets:         newSecrets(pemSecret(pemOf(intermediate.cert, root.cert)), nil),
			wantCert:        ca.cert,
			wantChain:       []*x509.Certificate{intermediate.cert, root.cert},
			wantErr:         nil,
			wantMsg:         "",
			wantCertCalls:   wantCertCalls,
			wantSecretCalls: wantSecretCalls,
		},
		{
			name:  "private key in the secret is ignored",
			cfg:   cfgChain,
			certs: newCerts(caResp, nil),
			secrets: newSecrets(pemSecret(
				pemOf(ca.cert)+encodePEM("PRIVATE KEY", caKeyDER)+pemOf(intermediate.cert, root.cert)), nil),
			wantCert:        ca.cert,
			wantChain:       []*x509.Certificate{intermediate.cert, root.cert},
			wantErr:         nil,
			wantMsg:         "",
			wantCertCalls:   wantCertCalls,
			wantSecretCalls: wantSecretCalls,
		},
		{
			name:            "unrelated certificate in the secret is ignored",
			cfg:             cfgChain,
			certs:           newCerts(caResp, nil),
			secrets:         newSecrets(pemSecret(pemOf(ca.cert, unrelated.cert, intermediate.cert, root.cert)), nil),
			wantCert:        ca.cert,
			wantChain:       []*x509.Certificate{intermediate.cert, root.cert},
			wantErr:         nil,
			wantMsg:         "",
			wantCertCalls:   wantCertCalls,
			wantSecretCalls: wantSecretCalls,
		},
		{
			// As happens when the API version in use ignores outContentType.
			name:            "a secret that Key Vault did not convert to PEM is refused",
			cfg:             cfgChain,
			certs:           newCerts(caResp, nil),
			secrets:         newSecrets(secretResponse(to.Ptr("MIIK"), to.Ptr("application/x-pkcs12")), nil),
			wantCert:        nil,
			wantChain:       nil,
			wantErr:         ErrCertificateUnusable,
			wantMsg:         "Key Vault did not convert it",
			wantCertCalls:   wantCertCalls,
			wantSecretCalls: wantSecretCalls,
		},
		{
			name:            "certificate fetch error is wrapped and treated as transient",
			cfg:             cfgNoChain,
			certs:           newCerts(azcertificates.GetCertificateResponse{}, errFetch),
			secrets:         unusedSecrets,
			wantCert:        nil,
			wantChain:       nil,
			wantErr:         errFetch,
			wantMsg:         "getting ca certificate",
			wantCertCalls:   wantCertCalls,
			wantSecretCalls: nil,
		},
		{
			name:            "certificate not found is classified",
			cfg:             cfgNoChain,
			certs:           newCerts(azcertificates.GetCertificateResponse{}, newResponseError(t, http.StatusNotFound)),
			secrets:         unusedSecrets,
			wantCert:        nil,
			wantChain:       nil,
			wantErr:         ErrNotFound,
			wantMsg:         "getting ca certificate",
			wantCertCalls:   wantCertCalls,
			wantSecretCalls: nil,
		},
		{
			name:            "certificate access denied is classified",
			cfg:             cfgNoChain,
			certs:           newCerts(azcertificates.GetCertificateResponse{}, newResponseError(t, http.StatusForbidden)),
			secrets:         unusedSecrets,
			wantCert:        nil,
			wantChain:       nil,
			wantErr:         ErrAccessDenied,
			wantMsg:         "getting ca certificate",
			wantCertCalls:   wantCertCalls,
			wantSecretCalls: nil,
		},
		{
			name:            "entra rejecting the credential on the certificate fetch is classified",
			cfg:             cfgNoChain,
			certs:           newCerts(azcertificates.GetCertificateResponse{}, newAuthenticationFailedError(t, http.StatusUnauthorized)),
			secrets:         unusedSecrets,
			wantCert:        nil,
			wantChain:       nil,
			wantErr:         ErrAccessDenied,
			wantMsg:         "getting ca certificate",
			wantCertCalls:   wantCertCalls,
			wantSecretCalls: nil,
		},
		{
			name:            "entra rejecting the credential on the secret fetch is classified",
			cfg:             cfgChain,
			certs:           newCerts(caResp, nil),
			secrets:         newSecrets(azsecrets.GetSecretResponse{}, newAuthenticationFailedError(t, http.StatusBadRequest)),
			wantCert:        nil,
			wantChain:       nil,
			wantErr:         ErrAccessDenied,
			wantMsg:         "getting chain from backing secret",
			wantCertCalls:   wantCertCalls,
			wantSecretCalls: wantSecretCalls,
		},
		{
			name:            "certificate response without an id is malformed",
			cfg:             cfgNoChain,
			certs:           newCerts(certResponse(nil, ca.cert.Raw, enabled), nil),
			secrets:         unusedSecrets,
			wantCert:        nil,
			wantChain:       nil,
			wantErr:         nil,
			wantMsg:         "nil id",
			wantCertCalls:   wantCertCalls,
			wantSecretCalls: nil,
		},
		{
			name:            "unparseable certificate data is unusable",
			cfg:             cfgNoChain,
			certs:           newCerts(certResponse(to.Ptr(testCertID), []byte("not der"), enabled), nil),
			secrets:         unusedSecrets,
			wantCert:        nil,
			wantChain:       nil,
			wantErr:         ErrCertificateUnusable,
			wantMsg:         "parsing certificate",
			wantCertCalls:   wantCertCalls,
			wantSecretCalls: nil,
		},
		{
			name:            "disabled certificate is unusable and the secret is left unread",
			cfg:             cfgChain,
			certs:           newCerts(certResponse(to.Ptr(testCertID), ca.cert.Raw, disabled), nil),
			secrets:         newSecrets(pemSecret(pemOf(ca.cert, intermediate.cert, root.cert)), nil),
			wantCert:        nil,
			wantChain:       nil,
			wantErr:         ErrCertificateUnusable,
			wantMsg:         "disabled",
			wantCertCalls:   wantCertCalls,
			wantSecretCalls: nil,
		},
		{
			name:            "expired certificate is unusable",
			cfg:             cfgNoChain,
			certs:           newCerts(certResponse(to.Ptr(testCertID), expiredCA.cert.Raw, enabled), nil),
			secrets:         unusedSecrets,
			wantCert:        nil,
			wantChain:       nil,
			wantErr:         ErrCertificateUnusable,
			wantMsg:         "expired",
			wantCertCalls:   wantCertCalls,
			wantSecretCalls: nil,
		},
		{
			name:            "certificate that is not a CA is unusable",
			cfg:             cfgNoChain,
			certs:           newCerts(certResponse(to.Ptr(testCertID), notCA.cert.Raw, enabled), nil),
			secrets:         unusedSecrets,
			wantCert:        nil,
			wantChain:       nil,
			wantErr:         ErrCertificateUnusable,
			wantMsg:         "not a CA",
			wantCertCalls:   wantCertCalls,
			wantSecretCalls: nil,
		},
		{
			name:            "secret fetch error is wrapped and treated as transient",
			cfg:             cfgChain,
			certs:           newCerts(caResp, nil),
			secrets:         newSecrets(azsecrets.GetSecretResponse{}, errFetch),
			wantCert:        nil,
			wantChain:       nil,
			wantErr:         errFetch,
			wantMsg:         "getting chain from backing secret",
			wantCertCalls:   wantCertCalls,
			wantSecretCalls: wantSecretCalls,
		},
		{
			name:            "secret not found is classified",
			cfg:             cfgChain,
			certs:           newCerts(caResp, nil),
			secrets:         newSecrets(azsecrets.GetSecretResponse{}, newResponseError(t, http.StatusNotFound)),
			wantCert:        nil,
			wantChain:       nil,
			wantErr:         ErrNotFound,
			wantMsg:         "getting chain from backing secret",
			wantCertCalls:   wantCertCalls,
			wantSecretCalls: wantSecretCalls,
		},
		{
			name:            "secret access denied is classified",
			cfg:             cfgChain,
			certs:           newCerts(caResp, nil),
			secrets:         newSecrets(azsecrets.GetSecretResponse{}, newResponseError(t, http.StatusUnauthorized)),
			wantCert:        nil,
			wantChain:       nil,
			wantErr:         ErrAccessDenied,
			wantMsg:         "getting chain from backing secret",
			wantCertCalls:   wantCertCalls,
			wantSecretCalls: wantSecretCalls,
		},
		{
			name:            "secret response without a value is malformed",
			cfg:             cfgChain,
			certs:           newCerts(caResp, nil),
			secrets:         newSecrets(secretResponse(nil, to.Ptr(contentTypePEM)), nil),
			wantCert:        nil,
			wantChain:       nil,
			wantErr:         nil,
			wantMsg:         "no value",
			wantCertCalls:   wantCertCalls,
			wantSecretCalls: wantSecretCalls,
		},
		{
			name:            "secret with an unsupported content type is unusable",
			cfg:             cfgChain,
			certs:           newCerts(caResp, nil),
			secrets:         newSecrets(secretResponse(to.Ptr(pemOf(ca.cert, intermediate.cert)), to.Ptr("text/plain")), nil),
			wantCert:        nil,
			wantChain:       nil,
			wantErr:         ErrCertificateUnusable,
			wantMsg:         "content type",
			wantCertCalls:   wantCertCalls,
			wantSecretCalls: wantSecretCalls,
		},
		{
			name:            "secret without certificates is unusable",
			cfg:             cfgChain,
			certs:           newCerts(caResp, nil),
			secrets:         newSecrets(pemSecret(""), nil),
			wantCert:        nil,
			wantChain:       nil,
			wantErr:         ErrCertificateUnusable,
			wantMsg:         "no certificates found",
			wantCertCalls:   wantCertCalls,
			wantSecretCalls: wantSecretCalls,
		},
		{
			name:            "secret holding only the CA has no chain and is unusable",
			cfg:             cfgChain,
			certs:           newCerts(caResp, nil),
			secrets:         newSecrets(pemSecret(pemOf(ca.cert)), nil),
			wantCert:        nil,
			wantChain:       nil,
			wantErr:         ErrCertificateUnusable,
			wantMsg:         "no certificates that chain above",
			wantCertCalls:   wantCertCalls,
			wantSecretCalls: wantSecretCalls,
		},
		{
			name:            "secret holding only unrelated certificates is unusable",
			cfg:             cfgChain,
			certs:           newCerts(caResp, nil),
			secrets:         newSecrets(pemSecret(pemOf(ca.cert, unrelated.cert)), nil),
			wantCert:        nil,
			wantChain:       nil,
			wantErr:         ErrCertificateUnusable,
			wantMsg:         "no certificates that chain above",
			wantCertCalls:   wantCertCalls,
			wantSecretCalls: wantSecretCalls,
		},
		{
			name:            "expired certificate in the chain is unusable",
			cfg:             cfgChain,
			certs:           newCerts(certResponse(to.Ptr(testCertID), caUnderExpired.cert.Raw, enabled), nil),
			secrets:         newSecrets(pemSecret(pemOf(caUnderExpired.cert, expiredIntermediate.cert, root.cert)), nil),
			wantCert:        nil,
			wantChain:       nil,
			wantErr:         ErrCertificateUnusable,
			wantMsg:         "expired",
			wantCertCalls:   wantCertCalls,
			wantSecretCalls: wantSecretCalls,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()
			signer := &fakeKeySigner{key: nil, result: nil, err: nil, calls: nil}

			got, err := newCertificateAuthority(ctx, signer, tt.certs, tt.secrets, tt.cfg)

			if !slices.Equal(tt.certs.calls, tt.wantCertCalls) {
				t.Errorf("newCertificateAuthority() GetCertificate calls = %+v, want %+v", tt.certs.calls, tt.wantCertCalls)
			}

			if !slices.Equal(tt.secrets.calls, tt.wantSecretCalls) {
				t.Errorf("newCertificateAuthority() GetSecret calls = %+v, want %+v", tt.secrets.calls, tt.wantSecretCalls)
			}

			checkAuthority(t, "newCertificateAuthority", got, err, tt.wantErr, tt.wantMsg)

			if err != nil {
				return
			}

			if !got.certificate.Equal(tt.wantCert) {
				t.Errorf("newCertificateAuthority() certificate = %q, want %q", got.certificate.Subject, tt.wantCert.Subject)
			}

			if !sameCerts(got.chain, tt.wantChain) {
				t.Errorf("newCertificateAuthority() chain = %s, want %s", subjects(got.chain), subjects(tt.wantChain))
			}

			if got.certAndKeyVersion != testCertVersion {
				t.Errorf("newCertificateAuthority() version = %q, want %q", got.certAndKeyVersion, testCertVersion)
			}

			if got.certAndKeyName != tt.cfg.CertificateName {
				t.Errorf("newCertificateAuthority() name = %q, want %q", got.certAndKeyName, tt.cfg.CertificateName)
			}

			if got.keysigner != signer {
				t.Errorf("newCertificateAuthority() keysigner = %v, want the injected signer", got.keysigner)
			}

			if got.ctx != ctx {
				t.Errorf("newCertificateAuthority() ctx = %v, want the context it was built with", got.ctx)
			}

			pub, ok := tt.wantCert.PublicKey.(interface{ Equal(crypto.PublicKey) bool })
			if !ok || !pub.Equal(got.publicKey) {
				t.Errorf("newCertificateAuthority() publicKey = %v, want the certificate's public key", got.publicKey)
			}

			if len(signer.calls) != 0 {
				t.Errorf("newCertificateAuthority() signed %d time(s), want 0: loading must not use the key", len(signer.calls))
			}
		})
	}
}

// TestCertificateAuthorityKeyExportable checks that the key is reported as
// exportable when the certificate's policy says so or the backing secret that
// was read held it, and that a policy that cannot be read does not fail the
// load.
func TestCertificateAuthorityKeyExportable(t *testing.T) {
	t.Parallel()

	now := time.Now()

	root := issue(t, liveSpec("root", now), nil)
	ca := issue(t, liveSpec("ca", now), root)

	caKeyDER, err := x509.MarshalPKCS8PrivateKey(ca.key)
	if err != nil {
		t.Fatalf("marshalling private key: %v", err)
	}

	cfgNoChain := Config{VaultURL: testVaultURL, CertificateName: testCertName, CertificateVersion: "", ChainInSecret: false}
	cfgChain := Config{VaultURL: testVaultURL, CertificateName: testCertName, CertificateVersion: "", ChainInSecret: true}

	withKey := pemOf(ca.cert) + encodePEM("PRIVATE KEY", caKeyDER) + pemOf(root.cert)
	withoutKey := pemOf(ca.cert, root.cert)

	noKeyProperties := azcertificates.GetCertificatePolicyResponse{CertificatePolicy: azcertificates.CertificatePolicy{KeyProperties: nil}}
	noExportable := azcertificates.GetCertificatePolicyResponse{CertificatePolicy: azcertificates.CertificatePolicy{KeyProperties: &azcertificates.KeyProperties{Exportable: nil}}}

	tests := []struct {
		name      string
		cfg       Config
		secret    string
		policy    azcertificates.GetCertificatePolicyResponse
		policyErr error
		want      bool
	}{
		{name: "the secret holds the key", cfg: cfgChain, secret: withKey, policy: exportablePolicy(false), policyErr: nil, want: true},
		{name: "the secret holds no key", cfg: cfgChain, secret: withoutKey, policy: exportablePolicy(false), policyErr: nil, want: false},
		{name: "the secret is not read and the policy is not exportable", cfg: cfgNoChain, secret: withKey, policy: exportablePolicy(false), policyErr: nil, want: false},
		{name: "the policy is exportable and the secret is not read", cfg: cfgNoChain, secret: withKey, policy: exportablePolicy(true), policyErr: nil, want: true},
		{name: "the policy is exportable and the secret holds no key", cfg: cfgChain, secret: withoutKey, policy: exportablePolicy(true), policyErr: nil, want: true},
		{name: "the policy is not exportable but the secret holds the key", cfg: cfgChain, secret: withKey, policy: exportablePolicy(false), policyErr: nil, want: true},
		{name: "the policy has no key properties", cfg: cfgNoChain, secret: withKey, policy: noKeyProperties, policyErr: nil, want: false},
		{name: "the policy does not say whether the key is exportable", cfg: cfgNoChain, secret: withKey, policy: noExportable, policyErr: nil, want: false},
		{name: "the policy cannot be read", cfg: cfgNoChain, secret: withKey, policy: exportablePolicy(true), policyErr: newResponseError(t, http.StatusForbidden), want: false},
		{name: "the policy cannot be read but the secret holds the key", cfg: cfgChain, secret: withKey, policy: exportablePolicy(false), policyErr: newResponseError(t, http.StatusForbidden), want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			certs := &fakeCertFetcher{
				resp:        certResponse(to.Ptr(testCertID), ca.cert.Raw, certAttributes(to.Ptr(true))),
				err:         nil,
				calls:       nil,
				policyResp:  tt.policy,
				policyErr:   tt.policyErr,
				policyCalls: nil,
			}
			secrets := &fakeSecretFetcher{resp: secretResponse(to.Ptr(tt.secret), to.Ptr(contentTypePEM)), err: nil, calls: nil}
			signer := &fakeKeySigner{key: nil, result: nil, err: nil, calls: nil}

			got, err := newCertificateAuthority(context.Background(), signer, certs, secrets, tt.cfg)
			if err != nil {
				t.Fatalf("newCertificateAuthority() error = %v, want nil", err)
			}

			if got.KeyExportable() != tt.want {
				t.Errorf("KeyExportable() = %t, want %t", got.KeyExportable(), tt.want)
			}
		})
	}
}

func TestCertificateAuthorityCertificate(t *testing.T) {
	t.Parallel()

	root := issue(t, newCertSpec("root"), nil)

	got := (&CertificateAuthority{
		keysigner:         nil,
		ctx:               context.Background(),
		publicKey:         root.key.Public(),
		certificate:       root.cert,
		certAndKeyVersion: testCertVersion,
		certAndKeyName:    testCertName,
		chain:             nil,
	}).Certificate()

	if got != root.cert {
		t.Errorf("Certificate() = %v, want the loaded certificate", got.Subject)
	}
}

func TestCertificateAuthorityChain(t *testing.T) {
	t.Parallel()

	root := issue(t, newCertSpec("root"), nil)
	intermediate := issue(t, newCertSpec("intermediate"), root)

	tests := []struct {
		name  string
		chain []*x509.Certificate
		want  []*x509.Certificate
	}{
		{
			name:  "chain is returned in the order held",
			chain: []*x509.Certificate{intermediate.cert, root.cert},
			want:  []*x509.Certificate{intermediate.cert, root.cert},
		},
		{
			name:  "nil chain is empty",
			chain: nil,
			want:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			a := &CertificateAuthority{
				keysigner:         nil,
				ctx:               context.Background(),
				publicKey:         nil,
				certificate:       nil,
				certAndKeyVersion: testCertVersion,
				certAndKeyName:    testCertName,
				chain:             tt.chain,
			}

			if got := a.Chain(); !sameCerts(got, tt.want) {
				t.Errorf("Chain() = %s, want %s", subjects(got), subjects(tt.want))
			}
		})
	}
}

func TestCertificateAuthorityChainReturnsCopy(t *testing.T) {
	t.Parallel()

	root := issue(t, newCertSpec("root"), nil)
	intermediate := issue(t, newCertSpec("intermediate"), root)

	a := &CertificateAuthority{
		keysigner:         nil,
		ctx:               context.Background(),
		publicKey:         nil,
		certificate:       nil,
		certAndKeyVersion: testCertVersion,
		certAndKeyName:    testCertName,
		chain:             []*x509.Certificate{intermediate.cert, root.cert},
	}

	got := a.Chain()
	got[0] = root.cert

	want := []*x509.Certificate{intermediate.cert, root.cert}
	if again := a.Chain(); !sameCerts(again, want) {
		t.Errorf("Chain() = %s after the caller changed a previous result, want %s", subjects(again), subjects(want))
	}
}
