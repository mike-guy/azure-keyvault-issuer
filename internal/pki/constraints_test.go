package pki

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"
)

// The helpers below build a certificate with one kind of name constraint set
// and nothing else, which is all checkNameConstraints reads.

func permittedDNS(domains ...string) *x509.Certificate {
	return &x509.Certificate{PermittedDNSDomains: domains}
}

func excludedDNS(domains ...string) *x509.Certificate {
	return &x509.Certificate{ExcludedDNSDomains: domains}
}

func permittedEmail(domains ...string) *x509.Certificate {
	return &x509.Certificate{PermittedEmailAddresses: domains}
}

func excludedEmail(domains ...string) *x509.Certificate {
	return &x509.Certificate{ExcludedEmailAddresses: domains}
}

func permittedURI(domains ...string) *x509.Certificate {
	return &x509.Certificate{PermittedURIDomains: domains}
}

func excludedURI(domains ...string) *x509.Certificate {
	return &x509.Certificate{ExcludedURIDomains: domains}
}

func permittedIPRange(t *testing.T, cidr string) *x509.Certificate {
	t.Helper()

	return &x509.Certificate{PermittedIPRanges: []*net.IPNet{parseCIDR(t, cidr)}}
}

func excludedIPRange(t *testing.T, cidr string) *x509.Certificate {
	t.Helper()

	return &x509.Certificate{ExcludedIPRanges: []*net.IPNet{parseCIDR(t, cidr)}}
}

func parseCIDR(t *testing.T, cidr string) *net.IPNet {
	t.Helper()

	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatalf("parsing CIDR %q: %v", cidr, err)
	}

	return ipNet
}

func TestHasNameConstraints(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		cert *x509.Certificate
		want bool
	}{
		{name: "no constraints", cert: &x509.Certificate{}, want: false},
		{name: "permitted dns domains", cert: permittedDNS("example.com"), want: true},
		{name: "excluded dns domains", cert: excludedDNS("example.com"), want: true},
		{name: "permitted ip ranges", cert: permittedIPRange(t, "192.0.2.0/24"), want: true},
		{name: "excluded ip ranges", cert: excludedIPRange(t, "192.0.2.0/24"), want: true},
		{name: "permitted email addresses", cert: permittedEmail("example.com"), want: true},
		{name: "excluded email addresses", cert: excludedEmail("example.com"), want: true},
		{name: "permitted uri domains", cert: permittedURI("example.com"), want: true},
		{name: "excluded uri domains", cert: excludedURI("example.com"), want: true},
		{name: "only the criticality flag", cert: &x509.Certificate{PermittedDNSDomainsCritical: true}, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := hasNameConstraints(tt.cert); got != tt.want {
				t.Errorf("hasNameConstraints() = %t, want %t", got, tt.want)
			}
		})
	}
}

func TestCheckNameConstraints(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		csr     *x509.CertificateRequest
		ca      *x509.Certificate
		chain   []*x509.Certificate
		wantErr error
		wantMsg string
	}{
		{
			name:    "a CA without constraints permits any name",
			csr:     &x509.CertificateRequest{DNSNames: []string{"evil.com"}},
			ca:      &x509.Certificate{},
			chain:   nil,
			wantErr: nil,
			wantMsg: "",
		},
		{
			name:    "a request without names passes any constraints",
			csr:     &x509.CertificateRequest{Subject: pkix.Name{CommonName: "no-names"}},
			ca:      permittedDNS("example.com"),
			chain:   nil,
			wantErr: nil,
			wantMsg: "",
		},
		{
			name:    "a permitted dns domain allows the domain itself",
			csr:     &x509.CertificateRequest{DNSNames: []string{"example.com"}},
			ca:      permittedDNS("example.com"),
			chain:   nil,
			wantErr: nil,
			wantMsg: "",
		},
		{
			name:    "a permitted dns domain allows a subdomain",
			csr:     &x509.CertificateRequest{DNSNames: []string{"a.b.example.com"}},
			ca:      permittedDNS("example.com"),
			chain:   nil,
			wantErr: nil,
			wantMsg: "",
		},
		{
			name:    "a permitted dns domain refuses another domain",
			csr:     &x509.CertificateRequest{DNSNames: []string{"evil.com"}},
			ca:      permittedDNS("example.com"),
			chain:   nil,
			wantErr: ErrInvalidRequest,
			wantMsg: "evil.com",
		},
		{
			name:    "a permitted dns domain refuses a domain that only ends with the same text",
			csr:     &x509.CertificateRequest{DNSNames: []string{"notexample.com"}},
			ca:      permittedDNS("example.com"),
			chain:   nil,
			wantErr: ErrInvalidRequest,
			wantMsg: "notexample.com",
		},
		{
			name:    "one name outside the permitted domain refuses the request",
			csr:     &x509.CertificateRequest{DNSNames: []string{"a.example.com", "evil.com"}},
			ca:      permittedDNS("example.com"),
			chain:   nil,
			wantErr: ErrInvalidRequest,
			wantMsg: "evil.com",
		},
		{
			name:    "a wildcard under the permitted domain is allowed",
			csr:     &x509.CertificateRequest{DNSNames: []string{"*.example.com"}},
			ca:      permittedDNS("example.com"),
			chain:   nil,
			wantErr: nil,
			wantMsg: "",
		},
		{
			name:    "a wildcard under another domain is refused",
			csr:     &x509.CertificateRequest{DNSNames: []string{"*.evil.com"}},
			ca:      permittedDNS("example.com"),
			chain:   nil,
			wantErr: ErrInvalidRequest,
			wantMsg: "evil.com",
		},
		{
			name:    "a leading period permits subdomains only",
			csr:     &x509.CertificateRequest{DNSNames: []string{"a.example.com"}},
			ca:      permittedDNS(".example.com"),
			chain:   nil,
			wantErr: nil,
			wantMsg: "",
		},
		{
			name:    "a leading period refuses the bare domain",
			csr:     &x509.CertificateRequest{DNSNames: []string{"example.com"}},
			ca:      permittedDNS(".example.com"),
			chain:   nil,
			wantErr: ErrInvalidRequest,
			wantMsg: "example.com",
		},
		{
			name:    "an excluded dns domain refuses its subdomains",
			csr:     &x509.CertificateRequest{DNSNames: []string{"a.internal.example.com"}},
			ca:      excludedDNS("internal.example.com"),
			chain:   nil,
			wantErr: ErrInvalidRequest,
			wantMsg: "internal.example.com",
		},
		{
			name:    "an excluded dns domain allows other names",
			csr:     &x509.CertificateRequest{DNSNames: []string{"a.example.com"}},
			ca:      excludedDNS("internal.example.com"),
			chain:   nil,
			wantErr: nil,
			wantMsg: "",
		},
		{
			name:    "a permitted ip range allows an address inside it",
			csr:     &x509.CertificateRequest{IPAddresses: []net.IP{net.ParseIP("192.0.2.10")}},
			ca:      permittedIPRange(t, "192.0.2.0/24"),
			chain:   nil,
			wantErr: nil,
			wantMsg: "",
		},
		{
			name:    "a permitted ip range refuses an address outside it",
			csr:     &x509.CertificateRequest{IPAddresses: []net.IP{net.ParseIP("198.51.100.1")}},
			ca:      permittedIPRange(t, "192.0.2.0/24"),
			chain:   nil,
			wantErr: ErrInvalidRequest,
			wantMsg: "198.51.100.1",
		},
		{
			name:    "an excluded ip range refuses an address inside it",
			csr:     &x509.CertificateRequest{IPAddresses: []net.IP{net.ParseIP("192.0.2.10")}},
			ca:      excludedIPRange(t, "192.0.2.0/24"),
			chain:   nil,
			wantErr: ErrInvalidRequest,
			wantMsg: "192.0.2.10",
		},
		{
			name:    "a permitted email domain allows an address at it",
			csr:     &x509.CertificateRequest{EmailAddresses: []string{"a@example.com"}},
			ca:      permittedEmail("example.com"),
			chain:   nil,
			wantErr: nil,
			wantMsg: "",
		},
		{
			name:    "a permitted email domain refuses an address elsewhere",
			csr:     &x509.CertificateRequest{EmailAddresses: []string{"a@evil.com"}},
			ca:      permittedEmail("example.com"),
			chain:   nil,
			wantErr: ErrInvalidRequest,
			wantMsg: "a@evil.com",
		},
		{
			name:    "an excluded email domain refuses an address at it",
			csr:     &x509.CertificateRequest{EmailAddresses: []string{"a@example.com"}},
			ca:      excludedEmail("example.com"),
			chain:   nil,
			wantErr: ErrInvalidRequest,
			wantMsg: "a@example.com",
		},
		{
			name:    "a permitted uri domain allows a uri at it",
			csr:     &x509.CertificateRequest{URIs: []*url.URL{{Scheme: "https", Host: "app.example.com", Path: "/x"}}},
			ca:      permittedURI("example.com"),
			chain:   nil,
			wantErr: nil,
			wantMsg: "",
		},
		{
			name:    "a permitted uri domain refuses a uri elsewhere",
			csr:     &x509.CertificateRequest{URIs: []*url.URL{{Scheme: "https", Host: "evil.com", Path: "/x"}}},
			ca:      permittedURI("example.com"),
			chain:   nil,
			wantErr: ErrInvalidRequest,
			wantMsg: "evil.com",
		},
		{
			name:    "an excluded uri domain refuses a uri at it",
			csr:     &x509.CertificateRequest{URIs: []*url.URL{{Scheme: "https", Host: "app.example.com", Path: "/x"}}},
			ca:      excludedURI("example.com"),
			chain:   nil,
			wantErr: ErrInvalidRequest,
			wantMsg: "app.example.com",
		},
		{
			name:    "constraints on one kind of name do not restrict another",
			csr:     &x509.CertificateRequest{EmailAddresses: []string{"a@evil.com"}},
			ca:      permittedDNS("example.com"),
			chain:   nil,
			wantErr: nil,
			wantMsg: "",
		},
		{
			name:    "the common name is not checked",
			csr:     &x509.CertificateRequest{Subject: pkix.Name{CommonName: "evil.com"}, DNSNames: []string{"example.com"}},
			ca:      permittedDNS("example.com"),
			chain:   nil,
			wantErr: nil,
			wantMsg: "",
		},
		{
			name:    "a constraint on a certificate in the chain applies",
			csr:     &x509.CertificateRequest{DNSNames: []string{"evil.com"}},
			ca:      &x509.Certificate{},
			chain:   []*x509.Certificate{permittedDNS("example.com")},
			wantErr: ErrInvalidRequest,
			wantMsg: "evil.com",
		},
		{
			name:    "a name allowed by the CA but not by the chain is refused",
			csr:     &x509.CertificateRequest{DNSNames: []string{"a.example.com"}},
			ca:      permittedDNS("example.com"),
			chain:   []*x509.Certificate{permittedDNS("sub.example.com")},
			wantErr: ErrInvalidRequest,
			wantMsg: "a.example.com",
		},
		{
			name:    "a name allowed by the CA and the chain is accepted",
			csr:     &x509.CertificateRequest{DNSNames: []string{"x.sub.example.com"}},
			ca:      permittedDNS("example.com"),
			chain:   []*x509.Certificate{permittedDNS("sub.example.com")},
			wantErr: nil,
			wantMsg: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := checkNameConstraints(tt.csr, tt.ca, tt.chain, testNow)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("checkNameConstraints() error = %v, want %v", err, tt.wantErr)
			}

			if err != nil && !strings.Contains(err.Error(), tt.wantMsg) {
				t.Errorf("checkNameConstraints() error = %q, want it to contain %q", err, tt.wantMsg)
			}
		})
	}
}

// newConstrainedAuthority returns an authority whose self-signed CA permits
// only permittedDNS domains.
func newConstrainedAuthority(t *testing.T, permittedDNS ...string) *fakeAuthority {
	t.Helper()

	key := newTestKey(t)

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "constrained-ca"},
		NotBefore:             testNow.Add(-time.Hour),
		NotAfter:              testCAExpiry,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            -1,
		PermittedDNSDomains:   permittedDNS,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatalf("creating constrained CA: %v", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing constrained CA: %v", err)
	}

	return &fakeAuthority{
		key:       key,
		cert:      cert,
		chain:     nil,
		signErr:   nil,
		badSig:    false,
		signCalls: 0,
	}
}

// TestSignNameConstraints checks Sign applies the CA's name constraints, that a
// request it accepts really does validate against the CA as a client would
// check it, and that a refused request never reaches the authority.
func TestSignNameConstraints(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		permitted     []string
		wantErr       error
		wantSignCalls int
	}{
		// newTestRequest asks for testCommonName, test.example.com.
		{name: "a request inside the permitted domain", permitted: []string{"example.com"}, wantErr: nil, wantSignCalls: 1},
		{name: "a request outside the permitted domain", permitted: []string{"other.test"}, wantErr: ErrInvalidRequest, wantSignCalls: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			authority := newConstrainedAuthority(t, tt.permitted...)
			signer := newTestSigner(t, authority, signerTestPolicy)

			got, err := signer.Sign(t.Context(), newTestRequest(t, newTestKey(t)))
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Sign() error = %v, want %v", err, tt.wantErr)
			}

			if authority.signCalls != tt.wantSignCalls {
				t.Errorf("authority was asked to sign %d times, want %d", authority.signCalls, tt.wantSignCalls)
			}

			if err != nil {
				if got != nil {
					t.Errorf("Sign() = %v alongside an error, want nil", got)
				}

				return
			}

			roots := x509.NewCertPool()
			roots.AddCert(authority.cert)

			leaf := parseCertPEM(t, got.LeafPEM)

			_, verifyErr := leaf.Verify(x509.VerifyOptions{
				Roots:       roots,
				CurrentTime: testNow,
				KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			})
			if verifyErr != nil {
				t.Errorf("issued certificate does not verify against the constrained CA: %v", verifyErr)
			}
		})
	}
}
