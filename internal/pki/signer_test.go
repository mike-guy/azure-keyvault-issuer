package pki

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

// errTestSign is the error fakeAuthority returns when told to fail.
var errTestSign = errors.New("vault unavailable")

// signerTestPolicy is a policy that refuses CAs and allows a day.
var signerTestPolicy = Policy{AllowCA: false, AllowedExtKeyUsages: nil, MaxDuration: 24 * time.Hour, AllowedDomains: nil}

var _ Authority = (*fakeAuthority)(nil)

// fakeAuthority is an Authority backed by an in-memory key. Sign fails with
// signErr if it is set, and returns a signature over the wrong digest if
// badSig is set, so a test only sets what it wants to break. It counts calls
// to Sign.
type fakeAuthority struct {
	key       crypto.Signer
	cert      *x509.Certificate
	chain     []*x509.Certificate
	signErr   error
	badSig    bool
	signCalls int
}

func (f *fakeAuthority) Public() crypto.PublicKey { return f.key.Public() }

func (f *fakeAuthority) Certificate() *x509.Certificate { return f.cert }

func (f *fakeAuthority) Chain() []*x509.Certificate { return f.chain }

func (f *fakeAuthority) Sign(random io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	f.signCalls++

	if f.signErr != nil {
		return nil, f.signErr
	}

	if f.badSig {
		digest = make([]byte, len(digest))
	}

	return f.key.Sign(random, digest, opts)
}

// newTestCert creates a CA certificate for key, signed by parent with
// parentKey, or self-signed when parent is nil. maxPathLen -1 leaves the path
// length unconstrained.
func newTestCert(t *testing.T, commonName string, key crypto.Signer, maxPathLen int, parent *x509.Certificate, parentKey crypto.Signer) *x509.Certificate {
	t.Helper()

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             testNow.Add(-time.Hour),
		NotAfter:              testCAExpiry,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            maxPathLen,
	}

	if parent == nil {
		parent = tmpl
		parentKey = key
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, key.Public(), parentKey)
	if err != nil {
		t.Fatalf("creating certificate %q: %v", commonName, err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing certificate %q: %v", commonName, err)
	}

	return cert
}

// newTestAuthority returns an authority whose CA sits beneath chainLen
// certificates, the topmost of which is a self-signed root with path length
// rootMaxPathLen. The authority's chain is nearest issuer first.
func newTestAuthority(t *testing.T, chainLen int, rootMaxPathLen int) *fakeAuthority {
	t.Helper()

	var (
		chain     []*x509.Certificate
		parent    *x509.Certificate
		parentKey crypto.Signer
	)

	for i := 0; i < chainLen; i++ {
		maxPathLen := -1
		if i == 0 {
			maxPathLen = rootMaxPathLen
		}

		key := newTestKey(t)
		cert := newTestCert(t, fmt.Sprintf("chain-%d", i), key, maxPathLen, parent, parentKey)

		chain = append(chain, cert)
		parent, parentKey = cert, key
	}

	slices.Reverse(chain)

	caKey := newTestKey(t)

	return &fakeAuthority{
		key:       caKey,
		cert:      newTestCert(t, "ca", caKey, -1, parent, parentKey),
		chain:     chain,
		signErr:   nil,
		badSig:    false,
		signCalls: 0,
	}
}

// newTestSigner returns a signer for authority and policy that signs at
// testNow.
func newTestSigner(t *testing.T, authority Authority, policy Policy) *Signer {
	t.Helper()

	s, err := NewSigner(authority, policy)
	if err != nil {
		t.Fatalf("NewSigner() error = %v, want nil", err)
	}

	s.now = func() time.Time { return testNow }

	return s
}

// newTestRequest returns a request for a leaf certificate lasting an hour,
// signed by key.
func newTestRequest(t *testing.T, key crypto.Signer) CertSigningRequest {
	t.Helper()

	req := newRequest(pemBlock(pemTypeCSR, newCSRDER(t, key)))
	req.Duration = time.Hour

	return req
}

// parseCertPEM parses data, which must hold exactly one certificate.
func parseCertPEM(t *testing.T, data []byte) *x509.Certificate {
	t.Helper()

	block, rest := pem.Decode(data)
	if block == nil || block.Type != pemTypeCert || len(rest) != 0 {
		t.Fatalf("PEM = %q, want exactly one %s block", data, pemTypeCert)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parsing certificate: %v", err)
	}

	return cert
}

func TestNewSigner(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		authority func(t *testing.T) Authority
		policy    Policy
		wantFail  bool
		wantErr   error // sentinel the error must wrap, if any
		wantMsg   string
	}{
		{
			name:      "a valid authority and policy",
			authority: func(t *testing.T) Authority { return newTestAuthority(t, 1, -1) },
			policy:    signerTestPolicy,
			wantFail:  false,
			wantErr:   nil,
			wantMsg:   "",
		},
		{
			name:      "a nil authority fails",
			authority: func(t *testing.T) Authority { return nil },
			policy:    signerTestPolicy,
			wantFail:  true,
			wantErr:   nil,
			wantMsg:   "authority must not be nil",
		},
		{
			name: "an authority without a certificate fails",
			authority: func(t *testing.T) Authority {
				return &fakeAuthority{key: nil, cert: nil, chain: nil, signErr: nil, badSig: false, signCalls: 0}
			},
			policy:   signerTestPolicy,
			wantFail: true,
			wantErr:  nil,
			wantMsg:  "authority must have a certificate",
		},
		{
			name:      "a zero max duration fails",
			authority: func(t *testing.T) Authority { return newTestAuthority(t, 1, -1) },
			policy:    Policy{AllowCA: false, AllowedExtKeyUsages: nil, MaxDuration: 0, AllowedDomains: nil},
			wantFail:  true,
			wantErr:   ErrInvalidConfig,
			wantMsg:   "maxDuration must be positive",
		},
		{
			name:      "a negative max duration fails",
			authority: func(t *testing.T) Authority { return newTestAuthority(t, 1, -1) },
			policy:    Policy{AllowCA: false, AllowedExtKeyUsages: nil, MaxDuration: -time.Hour, AllowedDomains: nil},
			wantFail:  true,
			wantErr:   ErrInvalidConfig,
			wantMsg:   "maxDuration must be positive",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			authority := tt.authority(t)

			got, err := NewSigner(authority, tt.policy)

			if (err != nil) != tt.wantFail {
				t.Fatalf("NewSigner() error = %v, want failure = %t", err, tt.wantFail)
			}

			if tt.wantFail {
				if got != nil {
					t.Errorf("NewSigner() = %v alongside an error, want nil", got)
				}

				if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
					t.Errorf("NewSigner() error = %v, want it to wrap %v", err, tt.wantErr)
				}

				if !strings.Contains(err.Error(), tt.wantMsg) {
					t.Errorf("NewSigner() error = %q, want it to contain %q", err, tt.wantMsg)
				}

				return
			}

			if got.authority != authority {
				t.Errorf("NewSigner() authority = %v, want the one passed in", got.authority)
			}

			if !reflect.DeepEqual(got.policy, tt.policy) {
				t.Errorf("NewSigner() policy = %+v, want %+v", got.policy, tt.policy)
			}

			if got.now == nil {
				t.Errorf("NewSigner() now = nil, want a clock")
			}
		})
	}
}

func TestSign(t *testing.T) {
	t.Parallel()

	authority := newTestAuthority(t, 2, -1)
	signer := newTestSigner(t, authority, signerTestPolicy)
	csrKey := newTestKey(t)

	got, err := signer.Sign(t.Context(), newTestRequest(t, csrKey))
	if err != nil {
		t.Fatalf("Sign() error = %v, want nil", err)
	}

	if authority.signCalls != 1 {
		t.Errorf("authority was asked to sign %d times, want 1", authority.signCalls)
	}

	leaf := parseCertPEM(t, got.LeafPEM)

	if err := leaf.CheckSignatureFrom(authority.cert); err != nil {
		t.Errorf("leaf is not signed by the authority's certificate: %v", err)
	}

	if leaf.Issuer.CommonName != authority.cert.Subject.CommonName {
		t.Errorf("leaf issuer = %q, want %q", leaf.Issuer.CommonName, authority.cert.Subject.CommonName)
	}

	if leaf.Subject.CommonName != testCommonName {
		t.Errorf("leaf common name = %q, want %q", leaf.Subject.CommonName, testCommonName)
	}

	csrPublic, ok := csrKey.Public().(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("csr public key is %T, want *ecdsa.PublicKey", csrKey.Public())
	}

	if !csrPublic.Equal(leaf.PublicKey) {
		t.Errorf("leaf public key is not the requester's key")
	}

	if leaf.IsCA {
		t.Errorf("leaf IsCA = true, want false")
	}

	if want := testNow.Add(-backdate); !leaf.NotBefore.Equal(want) {
		t.Errorf("leaf NotBefore = %v, want %v", leaf.NotBefore, want)
	}

	if want := testNow.Add(time.Hour); !leaf.NotAfter.Equal(want) {
		t.Errorf("leaf NotAfter = %v, want %v", leaf.NotAfter, want)
	}

	if !got.NotAfter.Equal(leaf.NotAfter) {
		t.Errorf("NotAfter = %v, want the leaf's %v", got.NotAfter, leaf.NotAfter)
	}

	if !got.CAExpiry.Equal(testCAExpiry) {
		t.Errorf("CAExpiry = %v, want %v", got.CAExpiry, testCAExpiry)
	}

	if got.Clamped {
		t.Errorf("Clamped = true, want false for a lifetime within the chain")
	}

	if issuer := parseCertPEM(t, got.IssuerPEM); !issuer.Equal(authority.cert) {
		t.Errorf("IssuerPEM holds %q, want the authority's certificate", issuer.Subject.CommonName)
	}

	if len(got.ChainPEM) != len(authority.chain) {
		t.Fatalf("ChainPEM has %d certificates, want %d", len(got.ChainPEM), len(authority.chain))
	}

	for i, want := range authority.chain {
		if chained := parseCertPEM(t, got.ChainPEM[i]); !chained.Equal(want) {
			t.Errorf("ChainPEM[%d] = %q, want %q", i, chained.Subject.CommonName, want.Subject.CommonName)
		}
	}
}

// TestSignReportsClamp checks that Sign reports a certificate cut back to the
// expiry of the CA chain, with the expiry that cut it.
func TestSignReportsClamp(t *testing.T) {
	t.Parallel()

	authority := newTestAuthority(t, 2, -1)
	caExpiry := testNow.Add(30 * time.Minute)
	authority.chain[0].NotAfter = caExpiry

	signer := newTestSigner(t, authority, signerTestPolicy)

	got, err := signer.Sign(t.Context(), newTestRequest(t, newTestKey(t)))
	if err != nil {
		t.Fatalf("Sign() error = %v, want nil", err)
	}

	if !got.Clamped {
		t.Errorf("Clamped = false, want true for an hour's lifetime past the chain's expiry")
	}

	if !got.CAExpiry.Equal(caExpiry) {
		t.Errorf("CAExpiry = %v, want %v", got.CAExpiry, caExpiry)
	}

	if !got.NotAfter.Equal(caExpiry) {
		t.Errorf("NotAfter = %v, want %v", got.NotAfter, caExpiry)
	}

	if leaf := parseCertPEM(t, got.LeafPEM); !leaf.NotAfter.Equal(caExpiry) {
		t.Errorf("leaf NotAfter = %v, want %v", leaf.NotAfter, caExpiry)
	}
}

// TestSignReportsDurationClamp checks that Sign reports a lifetime cut back to
// the policy's maximum, and not one within it, nor a default that no request
// asked for.
func TestSignReportsDurationClamp(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		duration    time.Duration
		maxDuration time.Duration
		want        bool
	}{
		{name: "a maximum below the request", duration: time.Hour, maxDuration: 30 * time.Minute, want: true},
		{name: "a maximum at the request", duration: time.Hour, maxDuration: time.Hour, want: false},
		{name: "a maximum above the request", duration: time.Hour, maxDuration: 2 * time.Hour, want: false},
		{name: "a maximum below the default with no request", duration: 0, maxDuration: 30 * time.Minute, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			policy := signerTestPolicy
			policy.MaxDuration = tt.maxDuration

			signer := newTestSigner(t, newTestAuthority(t, 2, -1), policy)

			req := newTestRequest(t, newTestKey(t))
			req.Duration = tt.duration

			got, err := signer.Sign(t.Context(), req)
			if err != nil {
				t.Fatalf("Sign() error = %v, want nil", err)
			}

			if got.DurationClamped != tt.want {
				t.Errorf("DurationClamped = %t, want %t", got.DurationClamped, tt.want)
			}
		})
	}
}

func TestSignWithoutChain(t *testing.T) {
	t.Parallel()

	authority := newTestAuthority(t, 0, -1)
	signer := newTestSigner(t, authority, signerTestPolicy)

	got, err := signer.Sign(t.Context(), newTestRequest(t, newTestKey(t)))
	if err != nil {
		t.Fatalf("Sign() error = %v, want nil", err)
	}

	if len(got.ChainPEM) != 0 {
		t.Errorf("ChainPEM has %d certificates, want none", len(got.ChainPEM))
	}

	if issuer := parseCertPEM(t, got.IssuerPEM); !issuer.Equal(authority.cert) {
		t.Errorf("IssuerPEM holds %q, want the authority's certificate", issuer.Subject.CommonName)
	}
}

// TestSignCA checks the authority's chain is handed to the template, so a path
// length constraint above the authority limits the CAs it may issue.
func TestSignCA(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		rootMaxPathLen int
		wantErr        error
	}{
		{name: "a root with room for the new ca", rootMaxPathLen: 2, wantErr: nil},
		{name: "a root with no room for the new ca", rootMaxPathLen: 1, wantErr: ErrInvalidRequest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			authority := newTestAuthority(t, 1, tt.rootMaxPathLen)
			signer := newTestSigner(t, authority, Policy{AllowCA: true, AllowedExtKeyUsages: nil, MaxDuration: 24 * time.Hour, AllowedDomains: nil})

			req := newTestRequest(t, newTestKey(t))
			req.IsCA = true

			got, err := signer.Sign(t.Context(), req)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Sign() error = %v, want %v", err, tt.wantErr)
			}

			if err != nil {
				if got != nil {
					t.Errorf("Sign() = %v alongside an error, want nil", got)
				}

				if authority.signCalls != 0 {
					t.Errorf("authority was asked to sign %d times, want 0", authority.signCalls)
				}

				return
			}

			leaf := parseCertPEM(t, got.LeafPEM)

			if !leaf.IsCA || !leaf.MaxPathLenZero || leaf.MaxPathLen != 0 {
				t.Errorf("leaf IsCA = %t, MaxPathLen = %d, MaxPathLenZero = %t, want a CA that may only issue end certificates", leaf.IsCA, leaf.MaxPathLen, leaf.MaxPathLenZero)
			}

			// A CA that asked for no usages gets the default, as an end certificate does.
			if want := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}; !slices.Equal(leaf.ExtKeyUsage, want) {
				t.Errorf("leaf ExtKeyUsage = %v, want %v", leaf.ExtKeyUsage, want)
			}
		})
	}
}

func TestSignErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		policy           Policy
		now              time.Time
		signErr          error
		badSig           bool
		req              func(t *testing.T) CertSigningRequest
		wantErr          error // sentinel or cause the error must wrap, if any
		wantMsg          string
		wantSignCalls    int
		wantUnclassified bool // the error wraps none of the package's sentinels
	}{
		{
			name:    "an invalid request is refused before the authority is asked to sign",
			policy:  signerTestPolicy,
			now:     testNow,
			signErr: nil,
			badSig:  false,
			req: func(t *testing.T) CertSigningRequest {
				return newRequest([]byte("not pem"))
			},
			wantErr:          ErrInvalidRequest,
			wantMsg:          "no blocks",
			wantSignCalls:    0,
			wantUnclassified: false,
		},
		{
			name:    "a request the policy forbids is refused before the authority is asked to sign",
			policy:  signerTestPolicy,
			now:     testNow,
			signErr: nil,
			badSig:  false,
			req: func(t *testing.T) CertSigningRequest {
				req := newTestRequest(t, newTestKey(t))
				req.IsCA = true

				return req
			},
			wantErr:          ErrInvalidRequest,
			wantMsg:          "not allowed by policy",
			wantSignCalls:    0,
			wantUnclassified: false,
		},
		{
			name:    "an expired authority is refused before it is asked to sign",
			policy:  signerTestPolicy,
			now:     testNow.Add(20 * 365 * 24 * time.Hour),
			signErr: nil,
			badSig:  false,
			req: func(t *testing.T) CertSigningRequest {
				return newTestRequest(t, newTestKey(t))
			},
			wantErr:          ErrAuthorityUnusable,
			wantMsg:          "expired",
			wantSignCalls:    0,
			wantUnclassified: false,
		},
		{
			name:    "an authority that fails to sign is wrapped and left unclassified",
			policy:  signerTestPolicy,
			now:     testNow,
			signErr: errTestSign,
			badSig:  false,
			req: func(t *testing.T) CertSigningRequest {
				return newTestRequest(t, newTestKey(t))
			},
			wantErr:          errTestSign,
			wantMsg:          "signing certificate",
			wantSignCalls:    1,
			wantUnclassified: true,
		},
		{
			name:    "an authority that returns a bad signature is left unclassified",
			policy:  signerTestPolicy,
			now:     testNow,
			signErr: nil,
			badSig:  true,
			req: func(t *testing.T) CertSigningRequest {
				return newTestRequest(t, newTestKey(t))
			},
			wantErr:          nil,
			wantMsg:          "signing certificate",
			wantSignCalls:    1,
			wantUnclassified: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			authority := newTestAuthority(t, 1, -1)
			authority.signErr = tt.signErr
			authority.badSig = tt.badSig

			signer := newTestSigner(t, authority, tt.policy)
			signer.now = func() time.Time { return tt.now }

			got, err := signer.Sign(t.Context(), tt.req(t))
			if err == nil {
				t.Fatalf("Sign() error = nil, want one containing %q", tt.wantMsg)
			}

			if got != nil {
				t.Errorf("Sign() = %v alongside an error, want nil", got)
			}

			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Errorf("Sign() error = %v, want it to wrap %v", err, tt.wantErr)
			}

			if !strings.Contains(err.Error(), tt.wantMsg) {
				t.Errorf("Sign() error = %q, want it to contain %q", err, tt.wantMsg)
			}

			if authority.signCalls != tt.wantSignCalls {
				t.Errorf("authority was asked to sign %d times, want %d", authority.signCalls, tt.wantSignCalls)
			}

			if tt.wantUnclassified {
				for _, sentinel := range []error{ErrInvalidRequest, ErrInvalidConfig, ErrAuthorityUnusable} {
					if errors.Is(err, sentinel) {
						t.Errorf("Sign() error = %v, want it to wrap none of the package's sentinels but it wraps %v", err, sentinel)
					}
				}
			}
		})
	}
}

func TestEncodeCertificate(t *testing.T) {
	t.Parallel()

	der := []byte("certificate bytes")

	block, rest := pem.Decode(encodeCertificate(der))
	if block == nil {
		t.Fatalf("encodeCertificate() holds no PEM block")
	}

	if len(rest) != 0 {
		t.Errorf("encodeCertificate() has %d bytes after the block, want none", len(rest))
	}

	if block.Type != pemTypeCert {
		t.Errorf("encodeCertificate() type = %q, want %q", block.Type, pemTypeCert)
	}

	if !bytes.Equal(block.Bytes, der) {
		t.Errorf("encodeCertificate() bytes = %q, want %q", block.Bytes, der)
	}
}

func TestEncodeCertificates(t *testing.T) {
	t.Parallel()

	first := newTestCert(t, "first", newTestKey(t), -1, nil, nil)
	second := newTestCert(t, "second", newTestKey(t), -1, nil, nil)

	tests := []struct {
		name  string
		certs []*x509.Certificate
		want  []string // common names, in order
	}{
		{name: "nil", certs: nil, want: []string{}},
		{name: "one", certs: []*x509.Certificate{first}, want: []string{"first"}},
		{name: "two keep their order", certs: []*x509.Certificate{second, first}, want: []string{"second", "first"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := encodeCertificates(tt.certs)

			if got == nil {
				t.Fatalf("encodeCertificates() = nil, want a non-nil slice")
			}

			var names []string
			for _, encoded := range got {
				names = append(names, parseCertPEM(t, encoded).Subject.CommonName)
			}

			if !slices.Equal(names, tt.want) {
				t.Errorf("encodeCertificates() = %v, want %v", names, tt.want)
			}
		})
	}
}
