package keyvault

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"

	azfake "github.com/Azure/azure-sdk-for-go/sdk/azcore/fake"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azcertificates"
	certfake "github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azcertificates/fake"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	keyfake "github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys/fake"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	secretfake "github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets/fake"
)

const (
	testVaultURL      = "https://test-ca.vault.azure.net/"
	testVaultHost     = "https://test-ca.vault.azure.net"
	testCertName      = "issuing-ca"
	testCertVersion   = "11111111111111111111111111111111"
	testKeyVersion    = "22222222222222222222222222222222"
	testSecretVersion = "33333333333333333333333333333333"
)

// ctxKey marks a context so a test can see that it reached Key Vault.
type ctxKey struct{}

// fakeVault is an in-memory Key Vault built on the SDK fake servers. Its
// certificate, policy and secret can be changed per test, and it signs with a
// local private key, returning signatures in Key Vault's format.
type fakeVault struct {
	mu sync.Mutex

	cert         azcertificates.Certificate
	certStatus   int // non-zero fails GetCertificate with this status
	policy       azcertificates.CertificatePolicy
	secret       azsecrets.Secret
	secretStatus int
	key          crypto.Signer
	signStatus   int
	signResult   func([]byte) []byte // optional tamper hook

	// Recorded calls. The fake servers parse names and versions out of the
	// path loosely, so the exact request paths are recorded instead.
	paths         []string
	policyCalls   int
	signCtxMarked bool
}

// newFakeVault returns a vault holding pki's CA with a non-exportable key,
// and a backing secret with the full PEM chain.
func newFakeVault(pki testPKI) *fakeVault {
	return &fakeVault{
		cert: azcertificates.Certificate{
			ID:         ptr(azcertificates.ID(testVaultHost + "/certificates/" + testCertName + "/" + testCertVersion)),
			KID:        ptr(azcertificates.ID(testVaultHost + "/keys/" + testCertName + "/" + testKeyVersion)),
			SID:        ptr(azcertificates.ID(testVaultHost + "/secrets/" + testCertName + "/" + testSecretVersion)),
			CER:        pki.ca.Raw,
			Attributes: &azcertificates.CertificateAttributes{Enabled: ptr(true)},
			Policy:     nonExportablePolicy(),
		},
		policy: *nonExportablePolicy(),
		secret: azsecrets.Secret{
			ID:          ptr(azsecrets.ID(testVaultHost + "/secrets/" + testCertName + "/" + testSecretVersion)),
			ContentType: ptr(pemContentType),
			Value:       ptr(pemEncode(pki.chain()...)),
		},
		key: pki.caKey,
	}
}

// transport returns one transport that serves all three Key Vault clients.
func (v *fakeVault) transport() policy.Transporter {
	certs := certfake.Server{
		GetCertificate: func(_ context.Context, _, _ string, _ *azcertificates.GetCertificateOptions) (
			resp azfake.Responder[azcertificates.GetCertificateResponse], errResp azfake.ErrorResponder,
		) {
			v.mu.Lock()
			defer v.mu.Unlock()

			if v.certStatus != 0 {
				errResp.SetResponseError(v.certStatus, http.StatusText(v.certStatus))

				return resp, errResp
			}

			resp.SetResponse(http.StatusOK, azcertificates.GetCertificateResponse{Certificate: v.cert}, nil)

			return resp, errResp
		},
		GetCertificatePolicy: func(_ context.Context, _ string, _ *azcertificates.GetCertificatePolicyOptions) (
			resp azfake.Responder[azcertificates.GetCertificatePolicyResponse], errResp azfake.ErrorResponder,
		) {
			v.mu.Lock()
			defer v.mu.Unlock()

			v.policyCalls++
			resp.SetResponse(http.StatusOK, azcertificates.GetCertificatePolicyResponse{CertificatePolicy: v.policy}, nil)

			return resp, errResp
		},
	}

	keys := keyfake.Server{
		Sign: func(ctx context.Context, _, _ string, params azkeys.SignParameters, _ *azkeys.SignOptions) (
			resp azfake.Responder[azkeys.SignResponse], errResp azfake.ErrorResponder,
		) {
			v.mu.Lock()
			defer v.mu.Unlock()

			v.signCtxMarked = ctx.Value(ctxKey{}) != nil

			if v.signStatus != 0 {
				errResp.SetResponseError(v.signStatus, http.StatusText(v.signStatus))

				return resp, errResp
			}

			sig, err := localSign(v.key, *params.Algorithm, params.Value)
			if err != nil {
				errResp.SetError(err)

				return resp, errResp
			}

			if v.signResult != nil {
				sig = v.signResult(sig)
			}

			resp.SetResponse(http.StatusOK, azkeys.SignResponse{KeyOperationResult: azkeys.KeyOperationResult{Result: sig}}, nil)

			return resp, errResp
		},
	}

	secrets := secretfake.Server{
		GetSecret: func(_ context.Context, _, _ string, _ *azsecrets.GetSecretOptions) (
			resp azfake.Responder[azsecrets.GetSecretResponse], errResp azfake.ErrorResponder,
		) {
			v.mu.Lock()
			defer v.mu.Unlock()

			if v.secretStatus != 0 {
				errResp.SetResponseError(v.secretStatus, http.StatusText(v.secretStatus))

				return resp, errResp
			}

			resp.SetResponse(http.StatusOK, azsecrets.GetSecretResponse{Secret: v.secret}, nil)

			return resp, errResp
		},
	}

	return routeTransport{
		certificates: certfake.NewServerTransport(&certs),
		keys:         keyfake.NewServerTransport(&keys),
		secrets:      secretfake.NewServerTransport(&secrets),
		record:       v.record,
	}
}

// record notes a request's path. The challenge round trip sends each request
// twice, first without a token, so only authorised requests are recorded.
func (v *fakeVault) record(req *http.Request) {
	if req.Header.Get("Authorization") == "" {
		return
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	v.paths = append(v.paths, req.Method+" "+req.URL.Path)
}

// requests returns the recorded requests whose path starts with prefix.
func (v *fakeVault) requests(prefix string) []string {
	v.mu.Lock()
	defer v.mu.Unlock()

	var out []string

	for _, p := range v.paths {
		if strings.HasPrefix(p, prefix) {
			out = append(out, p)
		}
	}

	return out
}

// fetcher returns a CAFetcher wired to v.
func (v *fakeVault) fetcher() *CAFetcher {
	return NewCAFetcher(Options{transport: v.transport()})
}

// fetch fetches the test certificate from v.
func (v *fakeVault) fetch(t *testing.T, chainFromSecret bool) (*CA, error) {
	t.Helper()

	src := testSource(t, "")
	src.ChainFromSecret = chainFromSecret

	return v.fetcher().Fetch(t.Context(), &azfake.TokenCredential{}, src)
}

// testSource returns the source of the test certificate at version, or the
// current version when version is empty.
func testSource(t *testing.T, version string) CASource {
	t.Helper()

	src, err := ParseCASource(testVaultURL, testCertName, version)
	if err != nil {
		t.Fatal(err)
	}

	return src
}

// localSign signs digest as Key Vault would: PKCS #1 v1.5 for RSA, and JOSE
// r||s for ECDSA.
func localSign(key crypto.Signer, alg azkeys.SignatureAlgorithm, digest []byte) ([]byte, error) {
	hashes := map[azkeys.SignatureAlgorithm]crypto.Hash{
		azkeys.SignatureAlgorithmRS256: crypto.SHA256, azkeys.SignatureAlgorithmRS384: crypto.SHA384, azkeys.SignatureAlgorithmRS512: crypto.SHA512,
		azkeys.SignatureAlgorithmES256: crypto.SHA256, azkeys.SignatureAlgorithmES384: crypto.SHA384, azkeys.SignatureAlgorithmES512: crypto.SHA512,
	}

	hash, ok := hashes[alg]
	if !ok {
		return nil, fmt.Errorf("fake vault: unsupported algorithm %s", alg)
	}

	switch k := key.(type) {
	case *rsa.PrivateKey:
		return rsa.SignPKCS1v15(nil, k, hash, digest)
	case *ecdsa.PrivateKey:
		r, s, err := ecdsa.Sign(rand.Reader, k, digest)
		if err != nil {
			return nil, err
		}

		size := curveByteSize(k.Curve)
		out := make([]byte, 2*size)
		r.FillBytes(out[:size])
		s.FillBytes(out[size:])

		return out, nil
	default:
		return nil, fmt.Errorf("fake vault: unsupported key %T", key)
	}
}
