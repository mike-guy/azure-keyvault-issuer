package vault

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azcertificates"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
)

// The name and version a CertificateAuthority built by newTestAuthority asks
// the vault to sign with.
const (
	testCertName    = "ca-cert"
	testCertVersion = "0123456789abcdef0123456789abcdef"
)

// Certificate ids as the vault returns them, built from the name and version
// above.
const (
	testCertID        = azcertificates.ID("https://test.vault.azure.net/certificates/" + testCertName + "/" + testCertVersion)
	testCertIDNoVer   = azcertificates.ID("https://test.vault.azure.net/certificates/" + testCertName)
	testCertIDInvalid = azcertificates.ID("")
)

// certAttributes returns certificate attributes with only enabled set.
func certAttributes(enabled *bool) *azcertificates.CertificateAttributes {
	return &azcertificates.CertificateAttributes{
		Enabled:         enabled,
		Expires:         nil,
		NotBefore:       nil,
		Created:         nil,
		RecoverableDays: nil,
		RecoveryLevel:   nil,
		Updated:         nil,
	}
}

// certResponse returns a certificate response with only the fields
// certInfoFrom relies on set.
func certResponse(id *azcertificates.ID, cer []byte, attrs *azcertificates.CertificateAttributes) azcertificates.GetCertificateResponse {
	return azcertificates.GetCertificateResponse{
		Certificate: azcertificates.Certificate{
			Attributes:        attrs,
			CER:               cer,
			ContentType:       nil,
			PreserveCertOrder: nil,
			Tags:              nil,
			ID:                id,
			KID:               nil,
			Policy:            nil,
			SID:               nil,
			X509Thumbprint:    nil,
		},
	}
}

// signCall is one call recorded by fakeKeySigner.
type signCall struct {
	name      string
	version   string
	algorithm azkeys.SignatureAlgorithm
	value     []byte
}

// fakeKeySigner stands in for the Key Vault keys client. Sign returns err if
// it is set, then result if it is non-nil (an empty non-nil slice is returned
// as is), and otherwise signs the digest with key the way Key Vault does, so a
// test only sets what it wants to break. It records every call, in order.
type fakeKeySigner struct {
	key    crypto.Signer
	result []byte
	err    error
	calls  []signCall
}

func (f *fakeKeySigner) Sign(_ context.Context, name string, version string, parameters azkeys.SignParameters, _ *azkeys.SignOptions) (azkeys.SignResponse, error) {
	f.calls = append(f.calls, signCall{
		name:      name,
		version:   version,
		algorithm: *parameters.Algorithm,
		value:     parameters.Value,
	})

	if f.err != nil {
		return azkeys.SignResponse{}, f.err
	}

	result := f.result
	if result == nil {
		var err error

		result, err = vaultSign(f.key, *parameters.Algorithm, parameters.Value)
		if err != nil {
			return azkeys.SignResponse{}, err
		}
	}

	return azkeys.SignResponse{KeyOperationResult: azkeys.KeyOperationResult{Result: result}}, nil
}

// newResponseError returns the *azcore.ResponseError the SDK produces for a
// vault response with the given HTTP status, as classify sees it.
func newResponseError(t *testing.T, status int) *azcore.ResponseError {
	t.Helper()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "https://vault.example.net/keys/"+testCertName+"/sign", http.NoBody)
	if err != nil {
		t.Fatalf("creating request: %v", err)
	}

	resp := &http.Response{
		StatusCode: status,
		Status:     http.StatusText(status),
		Header:     http.Header{},
		Body:       http.NoBody,
		Request:    req,
	}

	var respErr *azcore.ResponseError
	if !errors.As(runtime.NewResponseError(resp), &respErr) {
		t.Fatalf("runtime.NewResponseError() did not return an *azcore.ResponseError")
	}

	return respErr
}

// newAuthenticationFailedError returns the *azidentity.AuthenticationFailedError
// the SDK produces when Entra ID answers a token request with the given HTTP
// status, as classify sees it.
func newAuthenticationFailedError(t *testing.T, status int) *azidentity.AuthenticationFailedError {
	t.Helper()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "https://login.microsoftonline.com/tenant/oauth2/v2.0/token", http.NoBody)
	if err != nil {
		t.Fatalf("creating request: %v", err)
	}

	return &azidentity.AuthenticationFailedError{
		RawResponse: &http.Response{
			StatusCode: status,
			Status:     http.StatusText(status),
			Header:     http.Header{},
			Body:       http.NoBody,
			Request:    req,
		},
	}
}

// newJSONResponse returns a response with the given status and JSON body, to a
// request with the given method and URL.
func newJSONResponse(t *testing.T, method, url string, status int, body string) *http.Response {
	t.Helper()

	req, err := http.NewRequestWithContext(context.Background(), method, url, http.NoBody)
	if err != nil {
		t.Fatalf("creating request: %v", err)
	}

	return &http.Response{
		StatusCode: status,
		Status:     http.StatusText(status),
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    req,
	}
}

// newResponseErrorWithBody is newResponseError for a vault response that has a
// JSON body, as a real error response does.
func newResponseErrorWithBody(t *testing.T, status int, body string) *azcore.ResponseError {
	t.Helper()

	resp := newJSONResponse(t, http.MethodPost, "https://vault.example.net/keys/"+testCertName+"/sign", status, body)

	var respErr *azcore.ResponseError
	if !errors.As(runtime.NewResponseError(resp), &respErr) {
		t.Fatalf("runtime.NewResponseError() did not return an *azcore.ResponseError")
	}

	return respErr
}

// newAuthenticationFailedErrorWithBody is newAuthenticationFailedError for a
// token response that has a JSON body, as a real error response does.
func newAuthenticationFailedErrorWithBody(t *testing.T, status int, body string) *azidentity.AuthenticationFailedError {
	t.Helper()

	return &azidentity.AuthenticationFailedError{
		RawResponse: newJSONResponse(t, http.MethodPost, "https://login.microsoftonline.com/tenant/oauth2/v2.0/token", status, body),
	}
}

// keyType is a kind of private key a test certificate can be created with.
type keyType struct {
	name     string
	generate func(t *testing.T) crypto.Signer
}

// The key types the package supports for a vault issuing CA, see checkKeySupported.
var (
	keyRSA2048 = keyType{
		name: "rsa-2048",
		generate: func(t *testing.T) crypto.Signer {
			t.Helper()

			key, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				t.Fatalf("generating rsa private key: %v", err)
			}

			return key
		},
	}
	keyECDSAP256 = newECDSAKeyType("ecdsa-p256", elliptic.P256())
	keyECDSAP384 = newECDSAKeyType("ecdsa-p384", elliptic.P384())
	keyECDSAP521 = newECDSAKeyType("ecdsa-p521", elliptic.P521())
)

func newECDSAKeyType(name string, curve elliptic.Curve) keyType {
	return keyType{
		name: name,
		generate: func(t *testing.T) crypto.Signer {
			t.Helper()

			key, err := ecdsa.GenerateKey(curve, rand.Reader)
			if err != nil {
				t.Fatalf("generating %s private key: %v", name, err)
			}

			return key
		},
	}
}

// chainTestNow is the time the chain tests validate at. Certificates are
// valid for an hour either side of it unless a test says otherwise.
var chainTestNow = time.Date(2026, time.January, 1, 12, 0, 0, 0, time.UTC)

// certSpec describes a test certificate. newCertSpec sets every field, so a
// test only changes what it cares about.
type certSpec struct {
	commonName            string
	key                   keyType
	isCA                  bool
	basicConstraintsValid bool
	maxPathLen            int // -1 leaves the path length unconstrained
	maxPathLenZero        bool
	keyUsage              x509.KeyUsage // 0 leaves the key usage extension absent
	notBefore             time.Time
	notAfter              time.Time
}

// newCertSpec returns a valid CA certificate spec with no path length
// constraint, valid around chainTestNow. The key is ECDSA P-256, as generating
// it is far faster than RSA and the logic under test does not depend on the
// key type. Tests that do depend on it set key explicitly.
func newCertSpec(commonName string) certSpec {
	return certSpec{
		commonName:            commonName,
		key:                   keyECDSAP256,
		isCA:                  true,
		basicConstraintsValid: true,
		maxPathLen:            -1,
		maxPathLenZero:        false,
		keyUsage:              0,
		notBefore:             chainTestNow.Add(-time.Hour),
		notAfter:              chainTestNow.Add(time.Hour),
	}
}

// testCert is a parsed certificate with the key that can sign for it.
type testCert struct {
	cert *x509.Certificate
	key  crypto.Signer
}

// createTestCert signs a certificate for key described by spec. With a nil
// parent it is self-signed, otherwise parent supplies the issuer name and
// parentKey signs. parent only needs its Subject and PublicKey set.
func createTestCert(t *testing.T, spec certSpec, key crypto.Signer, parent *x509.Certificate, parentKey crypto.Signer) *x509.Certificate {
	t.Helper()

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: spec.commonName},
		NotBefore:             spec.notBefore,
		NotAfter:              spec.notAfter,
		IsCA:                  spec.isCA,
		BasicConstraintsValid: spec.basicConstraintsValid,
		MaxPathLen:            spec.maxPathLen,
		MaxPathLenZero:        spec.maxPathLenZero,
		KeyUsage:              spec.keyUsage,
	}

	if parent == nil {
		parent = tmpl
		parentKey = key
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, key.Public(), parentKey)
	if err != nil {
		t.Fatalf("creating certificate %q: %v", spec.commonName, err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing certificate %q: %v", spec.commonName, err)
	}

	return cert
}

// issue creates a certificate with a new key of the spec's type, signed by
// issuer, or self-signed when issuer is nil.
func issue(t *testing.T, spec certSpec, issuer *testCert) *testCert {
	t.Helper()

	key := spec.key.generate(t)

	if issuer == nil {
		return &testCert{cert: createTestCert(t, spec, key, nil, nil), key: key}
	}

	return &testCert{cert: createTestCert(t, spec, key, issuer.cert, issuer.key), key: key}
}

// encodePEM returns a PEM block of the given type holding der.
func encodePEM(blockType string, der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: blockType, Headers: nil, Bytes: der}))
}

// sameCerts reports whether got and want hold the same certificates in the
// same order. A nil and an empty slice are the same.
func sameCerts(got, want []*x509.Certificate) bool {
	if len(got) != len(want) {
		return false
	}

	for i := range got {
		if !got[i].Equal(want[i]) {
			return false
		}
	}

	return true
}

// subjects renders the common names of certs for failure messages.
func subjects(certs []*x509.Certificate) string {
	names := make([]string, 0, len(certs))
	for _, c := range certs {
		names = append(names, c.Subject.CommonName)
	}

	return "[" + strings.Join(names, " ") + "]"
}
