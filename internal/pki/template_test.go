package pki

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"net"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"
)

// templateTestPolicy allows CAs and a year.
var templateTestPolicy = Policy{AllowCA: true, AllowedExtKeyUsages: nil, MaxDuration: 365 * 24 * time.Hour, AllowedDomains: nil}

// newTemplateCA returns an issuing CA with only the fields createTemplate
// reads set: it expires at notAfter and has no path length constraint.
func newTemplateCA(notAfter time.Time) *x509.Certificate {
	ca := pathLenCert(-1, false)
	ca.NotAfter = notAfter

	return ca
}

// newTemplateChainCert returns a certificate above the issuing CA with the given
// path length fields, expiring at testCAExpiry.
func newTemplateChainCert(maxPathLen int, maxPathLenZero bool) *x509.Certificate {
	c := pathLenCert(maxPathLen, maxPathLenZero)
	c.NotAfter = testCAExpiry

	return c
}

// newTemplateCAWithSubject returns an issuing CA, as newTemplateCA does, with
// the given common name as its subject.
func newTemplateCAWithSubject(notAfter time.Time, commonName string) *x509.Certificate {
	ca := newTemplateCA(notAfter)
	ca.Subject = pkix.Name{CommonName: commonName}

	return ca
}

// newTemplateCAWithIssuer returns an issuing CA, as newTemplateCA does, with
// the given common name as its issuer, as for a CA below a root that is not
// among the certificates the signer holds.
func newTemplateCAWithIssuer(notAfter time.Time, commonName string) *x509.Certificate {
	ca := newTemplateCAWithSubject(notAfter, "issuing")
	ca.Issuer = pkix.Name{CommonName: commonName}

	return ca
}

// newTemplateCAWithRawSubject returns an issuing CA, as newTemplateCA does,
// with name encoded as its raw subject, as in a certificate that was parsed.
func newTemplateCAWithRawSubject(t *testing.T, notAfter time.Time, name pkix.Name) *x509.Certificate {
	t.Helper()

	raw, err := asn1.Marshal(name.ToRDNSequence())
	if err != nil {
		t.Fatalf("encoding subject: %v", err)
	}

	ca := newTemplateCA(notAfter)
	ca.RawSubject = raw

	return ca
}

// newTemplateRequest returns a request with the given lifetime and nothing else.
func newTemplateRequest(lifetime time.Duration, isCA bool) CertSigningRequest {
	req := newRequest(nil)
	req.Duration = lifetime
	req.IsCA = isCA

	return req
}

func TestCreateTemplateErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		csr     *x509.CertificateRequest
		req     CertSigningRequest
		ca      *x509.Certificate
		chain   []*x509.Certificate
		policy  Policy
		wantErr error
		wantMsg string
	}{
		{
			name:    "a CA request the policy forbids",
			csr:     newTestCSR(),
			req:     newTemplateRequest(time.Hour, true),
			ca:      newTemplateCA(testCAExpiry),
			chain:   nil,
			policy:  Policy{AllowCA: false, AllowedExtKeyUsages: nil, MaxDuration: 24 * time.Hour, AllowedDomains: nil},
			wantErr: ErrInvalidRequest,
			wantMsg: "not allowed by policy",
		},
		{
			name:    "a name the policy's allowed domains do not permit",
			csr:     newTestCSR(),
			req:     newTemplateRequest(time.Hour, false),
			ca:      newTemplateCA(testCAExpiry),
			chain:   nil,
			policy:  Policy{AllowCA: false, AllowedExtKeyUsages: nil, MaxDuration: 24 * time.Hour, AllowedDomains: []string{"*.other.com"}},
			wantErr: ErrInvalidRequest,
			wantMsg: "not permitted by allowedDomains",
		},
		{
			name:    "a negative duration",
			csr:     newTestCSR(),
			req:     newTemplateRequest(-time.Hour, false),
			ca:      newTemplateCA(testCAExpiry),
			chain:   nil,
			policy:  templateTestPolicy,
			wantErr: ErrInvalidRequest,
			wantMsg: "must not be negative",
		},
		{
			name:    "a CSR with neither a subject nor a subject alternative name",
			csr:     &x509.CertificateRequest{},
			req:     newTemplateRequest(time.Hour, false),
			ca:      newTemplateCA(testCAExpiry),
			chain:   nil,
			policy:  templateTestPolicy,
			wantErr: ErrInvalidRequest,
			wantMsg: "subject or at least one",
		},
		{
			name:    "an authority that expired long ago",
			csr:     newTestCSR(),
			req:     newTemplateRequest(time.Hour, false),
			ca:      newTemplateCA(testNow.Add(-time.Hour)),
			chain:   nil,
			policy:  templateTestPolicy,
			wantErr: ErrAuthorityUnusable,
			wantMsg: "expired",
		},
		{
			name:    "a certificate above the authority that expired long ago",
			csr:     newTestCSR(),
			req:     newTemplateRequest(time.Hour, false),
			ca:      newTemplateCA(testCAExpiry),
			chain:   []*x509.Certificate{newTemplateCA(testNow.Add(-time.Hour))},
			policy:  templateTestPolicy,
			wantErr: ErrAuthorityUnusable,
			wantMsg: "expired",
		},
		{
			// The certificate would be valid from the moment the authority expires.
			name:    "an authority that expires exactly when the backdated certificate would start",
			csr:     newTestCSR(),
			req:     newTemplateRequest(time.Hour, false),
			ca:      newTemplateCA(testNow.Add(-backdate)),
			chain:   nil,
			policy:  templateTestPolicy,
			wantErr: ErrAuthorityUnusable,
			wantMsg: "expired",
		},
		{
			name: "cert sign usage on a non-CA certificate",
			csr:  newTestCSR(),
			req: CertSigningRequest{
				PEMData:     nil,
				Duration:    time.Hour,
				IsCA:        false,
				KeyUsage:    x509.KeyUsageCertSign,
				ExtKeyUsage: nil,
			},
			ca:      newTemplateCA(testCAExpiry),
			chain:   nil,
			policy:  templateTestPolicy,
			wantErr: ErrInvalidRequest,
			wantMsg: "require a CA certificate",
		},
		{
			name:    "a CA cannot be issued when allowedDomains is set",
			csr:     newTestCSR(),
			req:     newTemplateRequest(time.Hour, true),
			ca:      newTemplateCA(testCAExpiry),
			chain:   nil,
			policy:  Policy{AllowCA: true, AllowedExtKeyUsages: nil, MaxDuration: 24 * time.Hour, AllowedDomains: []string{"**.example.com"}},
			wantErr: ErrInvalidRequest,
			wantMsg: "cannot be issued when allowedDomains is set",
		},
		{
			name:    "a CA with the subject of the issuing CA",
			csr:     newTestCSR(),
			req:     newTemplateRequest(time.Hour, true),
			ca:      newTemplateCAWithSubject(testCAExpiry, testCommonName),
			chain:   nil,
			policy:  templateTestPolicy,
			wantErr: ErrInvalidRequest,
			wantMsg: "needs a distinct subject",
		},
		{
			name:    "a CA with the subject of a certificate above the issuing CA",
			csr:     newTestCSR(),
			req:     newTemplateRequest(time.Hour, true),
			ca:      newTemplateCAWithSubject(testCAExpiry, "issuing"),
			chain:   []*x509.Certificate{newTemplateCAWithSubject(testCAExpiry, "intermediate"), newTemplateCAWithSubject(testCAExpiry, testCommonName)},
			policy:  templateTestPolicy,
			wantErr: ErrInvalidRequest,
			wantMsg: "needs a distinct subject",
		},
		{
			name:    "a CA with the subject of the root that issued the issuing CA, which is not in the chain",
			csr:     newTestCSR(),
			req:     newTemplateRequest(time.Hour, true),
			ca:      newTemplateCAWithIssuer(testCAExpiry, testCommonName),
			chain:   nil,
			policy:  templateTestPolicy,
			wantErr: ErrInvalidRequest,
			wantMsg: "needs a distinct subject",
		},
		{
			name:    "a CA with the subject of the root that issued the top of the chain",
			csr:     newTestCSR(),
			req:     newTemplateRequest(time.Hour, true),
			ca:      newTemplateCAWithSubject(testCAExpiry, "issuing"),
			chain:   []*x509.Certificate{newTemplateCAWithIssuer(testCAExpiry, testCommonName)},
			policy:  templateTestPolicy,
			wantErr: ErrInvalidRequest,
			wantMsg: "needs a distinct subject",
		},
		{
			name:    "a CA with the subject of the issuing CA in other case and spacing",
			csr:     newTestCSR(),
			req:     newTemplateRequest(time.Hour, true),
			ca:      newTemplateCAWithSubject(testCAExpiry, "  "+strings.ToUpper(testCommonName)+" "),
			chain:   nil,
			policy:  templateTestPolicy,
			wantErr: ErrInvalidRequest,
			wantMsg: "needs a distinct subject",
		},
		{
			name:    "a CA with the encoded subject of the issuing CA in other case",
			csr:     newTestCSR(),
			req:     newTemplateRequest(time.Hour, true),
			ca:      newTemplateCAWithRawSubject(t, testCAExpiry, pkix.Name{CommonName: strings.ToUpper(testCommonName)}),
			chain:   nil,
			policy:  templateTestPolicy,
			wantErr: ErrInvalidRequest,
			wantMsg: "needs a distinct subject",
		},
		{
			name: "code signing is not in the default allowed usages",
			csr:  newTestCSR(),
			req: CertSigningRequest{
				PEMData:     nil,
				Duration:    time.Hour,
				IsCA:        false,
				KeyUsage:    0,
				ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
			},
			ca:      newTemplateCA(testCAExpiry),
			chain:   nil,
			policy:  templateTestPolicy,
			wantErr: ErrInvalidRequest,
			wantMsg: `extended key usage "code signing" is not permitted by policy`,
		},
		{
			name:    "a CA the path length constraints leave no room for",
			csr:     newTestCSR(),
			req:     newTemplateRequest(time.Hour, true),
			ca:      newTemplateCA(testCAExpiry),
			chain:   []*x509.Certificate{newTemplateChainCert(1, false)},
			policy:  templateTestPolicy,
			wantErr: ErrInvalidRequest,
			wantMsg: "path length",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, limits, err := createTemplate(t.Context(), tt.csr, tt.req, tt.ca, tt.chain, tt.policy, testNow)

			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("createTemplate() error = %v, want %v", err, tt.wantErr)
			}

			if !strings.Contains(err.Error(), tt.wantMsg) {
				t.Errorf("createTemplate() error = %q, want it to contain %q", err, tt.wantMsg)
			}

			if got != nil {
				t.Errorf("createTemplate() = %v alongside an error, want nil", got)
			}

			if limits.clampedToCA || limits.clampedToPolicy {
				t.Errorf("createTemplate() reported a clamp alongside an error, want none")
			}
		})
	}
}

// TestCreateTemplateClamped checks that only a lifetime cut back to the expiry of
// the CA chain is reported, since that is the one that only renewing the CA fixes.
func TestCreateTemplateClamped(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		lifetime     time.Duration
		maxDuration  time.Duration
		caNotAfter   time.Time
		chainNotAfts []time.Time
		wantClamped  bool
	}{
		{
			name:         "a lifetime within the chain is not clamped",
			lifetime:     time.Hour,
			maxDuration:  24 * time.Hour,
			caNotAfter:   testCAExpiry,
			chainNotAfts: []time.Time{testCAExpiry},
			wantClamped:  false,
		},
		{
			name:         "a lifetime cut to the policy maximum is not reported",
			lifetime:     48 * time.Hour,
			maxDuration:  24 * time.Hour,
			caNotAfter:   testCAExpiry,
			chainNotAfts: nil,
			wantClamped:  false,
		},
		{
			name:         "a lifetime ending exactly at the expiry of the CA is not clamped",
			lifetime:     time.Hour,
			maxDuration:  24 * time.Hour,
			caNotAfter:   testNow.Add(time.Hour),
			chainNotAfts: nil,
			wantClamped:  false,
		},
		{
			name:         "a lifetime past the expiry of the CA is clamped",
			lifetime:     24 * time.Hour,
			maxDuration:  24 * time.Hour,
			caNotAfter:   testNow.Add(time.Hour),
			chainNotAfts: nil,
			wantClamped:  true,
		},
		{
			name:         "a lifetime past the expiry of a certificate above the CA is clamped",
			lifetime:     24 * time.Hour,
			maxDuration:  24 * time.Hour,
			caNotAfter:   testCAExpiry,
			chainNotAfts: []time.Time{testNow.Add(time.Hour)},
			wantClamped:  true,
		},
		{
			name:         "the default lifetime past the expiry of the CA is clamped",
			lifetime:     0,
			maxDuration:  365 * 24 * time.Hour,
			caNotAfter:   testNow.Add(time.Hour),
			chainNotAfts: nil,
			wantClamped:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var chain []*x509.Certificate
			for _, notAfter := range tt.chainNotAfts {
				chain = append(chain, newTemplateCA(notAfter))
			}

			policy := Policy{AllowCA: false, AllowedExtKeyUsages: nil, MaxDuration: tt.maxDuration, AllowedDomains: nil}

			_, limits, err := createTemplate(t.Context(), newTestCSR(), newTemplateRequest(tt.lifetime, false), newTemplateCA(tt.caNotAfter), chain, policy, testNow)
			if err != nil {
				t.Fatalf("createTemplate() error = %v, want nil", err)
			}

			if limits.clampedToCA != tt.wantClamped {
				t.Errorf("createTemplate() clampedToCA = %t, want %t", limits.clampedToCA, tt.wantClamped)
			}

			wantCAExpiry := tt.caNotAfter
			for _, notAfter := range tt.chainNotAfts {
				if notAfter.Before(wantCAExpiry) {
					wantCAExpiry = notAfter
				}
			}

			if !limits.caExpiry.Equal(wantCAExpiry) {
				t.Errorf("createTemplate() caExpiry = %v, want %v", limits.caExpiry, wantCAExpiry)
			}
		})
	}
}

// TestCreateTemplateClampedToPolicy checks that a duration cut back to the
// policy's maximum is reported, and that the default lifetime being cut back is
// not, as the request never asked for it.
func TestCreateTemplateClampedToPolicy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		lifetime    time.Duration
		maxDuration time.Duration
		want        bool
	}{
		{name: "a duration past the maximum", lifetime: 48 * time.Hour, maxDuration: 24 * time.Hour, want: true},
		{name: "a duration at the maximum", lifetime: 24 * time.Hour, maxDuration: 24 * time.Hour, want: false},
		{name: "a duration within the maximum", lifetime: time.Hour, maxDuration: 24 * time.Hour, want: false},
		{name: "no duration with a maximum below the default", lifetime: 0, maxDuration: 24 * time.Hour, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			policy := Policy{AllowCA: false, AllowedExtKeyUsages: nil, MaxDuration: tt.maxDuration, AllowedDomains: nil}

			got, limits, err := createTemplate(t.Context(), newTestCSR(), newTemplateRequest(tt.lifetime, false), newTemplateCA(testCAExpiry), nil, policy, testNow)
			if err != nil {
				t.Fatalf("createTemplate() error = %v, want nil", err)
			}

			if limits.clampedToPolicy != tt.want {
				t.Errorf("createTemplate() clampedToPolicy = %t, want %t", limits.clampedToPolicy, tt.want)
			}

			// The lifetime is cut back either way, only the report differs.
			if want := testNow.Add(min(requestedLifetime(newTemplateRequest(tt.lifetime, false)), tt.maxDuration)); !got.NotAfter.Equal(want) {
				t.Errorf("createTemplate() NotAfter = %v, want %v", got.NotAfter, want)
			}
		})
	}
}

// TestCreateTemplateSubjectOfIssuer checks that only a CA is refused the subject
// of a certificate above it, and that a request with no subject cannot collide.
func TestCreateTemplateSubjectOfIssuer(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		csr  *x509.CertificateRequest
		isCA bool
	}{
		{name: "an end certificate may share the subject of the issuing CA", csr: newTestCSR(), isCA: false},
		{name: "a CA with no subject cannot collide", csr: &x509.CertificateRequest{DNSNames: []string{"ca.example.com"}}, isCA: true},
		{name: "a CA with a different subject", csr: &x509.CertificateRequest{Subject: pkix.Name{CommonName: "other"}, DNSNames: []string{"ca.example.com"}}, isCA: true},
		{
			name: "a CA with the same common name and another attribute",
			csr:  &x509.CertificateRequest{Subject: pkix.Name{CommonName: testCommonName, Organization: []string{"Acme"}}, DNSNames: []string{"ca.example.com"}},
			isCA: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ca := newTemplateCAWithSubject(testCAExpiry, testCommonName)

			if _, _, err := createTemplate(t.Context(), tt.csr, newTemplateRequest(time.Hour, tt.isCA), ca, nil, templateTestPolicy, testNow); err != nil {
				t.Errorf("createTemplate() error = %v, want nil", err)
			}
		})
	}
}

// TestCreateTemplateIdentity checks that a CSR needs only one of a subject or
// any kind of subject alternative name.
func TestCreateTemplateIdentity(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		csr  *x509.CertificateRequest
	}{
		{name: "subject only", csr: &x509.CertificateRequest{Subject: pkix.Name{CommonName: "subject-only"}}},
		{name: "dns name only", csr: &x509.CertificateRequest{DNSNames: []string{"a.example.com"}}},
		{name: "ip address only", csr: &x509.CertificateRequest{IPAddresses: []net.IP{net.ParseIP("192.0.2.1")}}},
		{name: "uri only", csr: &x509.CertificateRequest{URIs: []*url.URL{{Scheme: "spiffe", Host: "example.org", Path: "/workload"}}}},
		{name: "email address only", csr: &x509.CertificateRequest{EmailAddresses: []string{"a@example.com"}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, _, err := createTemplate(t.Context(), tt.csr, newTemplateRequest(time.Hour, false), newTemplateCA(testCAExpiry), nil, templateTestPolicy, testNow)
			if err != nil {
				t.Errorf("createTemplate() error = %v, want nil", err)
			}
		})
	}
}

func TestCreateTemplateLifetime(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		lifetime     time.Duration
		maxDuration  time.Duration
		caNotAfter   time.Time
		wantNotAfter time.Time
	}{
		{
			name:         "an explicit lifetime is honoured",
			lifetime:     time.Hour,
			maxDuration:  365 * 24 * time.Hour,
			caNotAfter:   testCAExpiry,
			wantNotAfter: testNow.Add(time.Hour),
		},
		{
			name:         "a zero lifetime gets the default",
			lifetime:     0,
			maxDuration:  365 * 24 * time.Hour,
			caNotAfter:   testCAExpiry,
			wantNotAfter: testNow.Add(defaultLifetime),
		},
		{
			name:         "a lifetime over the max duration is clamped",
			lifetime:     48 * time.Hour,
			maxDuration:  24 * time.Hour,
			caNotAfter:   testCAExpiry,
			wantNotAfter: testNow.Add(24 * time.Hour),
		},
		{
			name:         "a lifetime equal to the max duration is kept",
			lifetime:     24 * time.Hour,
			maxDuration:  24 * time.Hour,
			caNotAfter:   testCAExpiry,
			wantNotAfter: testNow.Add(24 * time.Hour),
		},
		{
			name:         "the default is clamped to a max duration below it",
			lifetime:     0,
			maxDuration:  24 * time.Hour,
			caNotAfter:   testCAExpiry,
			wantNotAfter: testNow.Add(24 * time.Hour),
		},
		{
			name:         "a lifetime past the authority's expiry is clamped to it",
			lifetime:     24 * time.Hour,
			maxDuration:  365 * 24 * time.Hour,
			caNotAfter:   testNow.Add(time.Hour),
			wantNotAfter: testNow.Add(time.Hour),
		},
		{
			name:         "a lifetime ending exactly at the authority's expiry is kept",
			lifetime:     time.Hour,
			maxDuration:  365 * 24 * time.Hour,
			caNotAfter:   testNow.Add(time.Hour),
			wantNotAfter: testNow.Add(time.Hour),
		},
		{
			name:         "an authority that expires soon after the backdated start still issues",
			lifetime:     time.Hour,
			maxDuration:  365 * 24 * time.Hour,
			caNotAfter:   testNow.Add(-backdate + time.Nanosecond),
			wantNotAfter: testNow.Add(-backdate + time.Nanosecond),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			policy := Policy{AllowCA: false, AllowedExtKeyUsages: nil, MaxDuration: tt.maxDuration, AllowedDomains: nil}

			got, _, err := createTemplate(t.Context(), newTestCSR(), newTemplateRequest(tt.lifetime, false), newTemplateCA(tt.caNotAfter), nil, policy, testNow)
			if err != nil {
				t.Fatalf("createTemplate() error = %v, want nil", err)
			}

			if want := testNow.Add(-backdate); !got.NotBefore.Equal(want) {
				t.Errorf("createTemplate() NotBefore = %v, want %v", got.NotBefore, want)
			}

			if !got.NotAfter.Equal(tt.wantNotAfter) {
				t.Errorf("createTemplate() NotAfter = %v, want %v", got.NotAfter, tt.wantNotAfter)
			}
		})
	}
}

// TestCreateTemplateLifetimeChain checks that NotAfter is clamped to the
// earliest expiry in the chain above the authority, not only to the authority's.
func TestCreateTemplateLifetimeChain(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		caNotAfter   time.Time
		chainNotAfts []time.Time
		wantNotAfter time.Time
	}{
		{
			name:         "an intermediate that expires before the authority limits the certificate",
			caNotAfter:   testCAExpiry,
			chainNotAfts: []time.Time{testNow.Add(2 * time.Hour)},
			wantNotAfter: testNow.Add(2 * time.Hour),
		},
		{
			name:         "the earliest of several certificates above the authority limits the certificate",
			caNotAfter:   testCAExpiry,
			chainNotAfts: []time.Time{testNow.Add(5 * time.Hour), testNow.Add(3 * time.Hour), testCAExpiry},
			wantNotAfter: testNow.Add(3 * time.Hour),
		},
		{
			name:         "an authority that expires before the chain still limits the certificate",
			caNotAfter:   testNow.Add(time.Hour),
			chainNotAfts: []time.Time{testCAExpiry},
			wantNotAfter: testNow.Add(time.Hour),
		},
		{
			name:         "a chain that outlasts the requested lifetime does not shorten it",
			caNotAfter:   testCAExpiry,
			chainNotAfts: []time.Time{testCAExpiry},
			wantNotAfter: testNow.Add(24 * time.Hour),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var chain []*x509.Certificate
			for _, notAfter := range tt.chainNotAfts {
				chain = append(chain, newTemplateCA(notAfter))
			}

			policy := Policy{AllowCA: false, AllowedExtKeyUsages: nil, MaxDuration: 365 * 24 * time.Hour, AllowedDomains: nil}

			got, _, err := createTemplate(t.Context(), newTestCSR(), newTemplateRequest(24*time.Hour, false), newTemplateCA(tt.caNotAfter), chain, policy, testNow)
			if err != nil {
				t.Fatalf("createTemplate() error = %v, want nil", err)
			}

			if !got.NotAfter.Equal(tt.wantNotAfter) {
				t.Errorf("createTemplate() NotAfter = %v, want %v", got.NotAfter, tt.wantNotAfter)
			}
		})
	}
}

// TestCreateTemplateFields checks what is taken from the CSR, and that
// nothing else the requester could influence is.
func TestCreateTemplateFields(t *testing.T) {
	t.Parallel()

	csr := &x509.CertificateRequest{
		Subject:        pkix.Name{CommonName: "cn.example.com", Organization: []string{"Example Org"}},
		DNSNames:       []string{"a.example.com", "b.example.com"},
		IPAddresses:    []net.IP{net.ParseIP("192.0.2.1")},
		URIs:           []*url.URL{{Scheme: "spiffe", Host: "example.org", Path: "/workload"}},
		EmailAddresses: []string{"a@example.com"},
		Extensions:     []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Critical: false, Value: []byte{0x05, 0x00}}},
		ExtraExtensions: []pkix.Extension{
			{Id: asn1.ObjectIdentifier{1, 2, 3, 5}, Critical: false, Value: []byte{0x05, 0x00}},
		},
	}

	got, _, err := createTemplate(t.Context(), csr, newTemplateRequest(time.Hour, false), newTemplateCA(testCAExpiry), nil, templateTestPolicy, testNow)
	if err != nil {
		t.Fatalf("createTemplate() error = %v, want nil", err)
	}

	if got.Subject.String() != csr.Subject.String() {
		t.Errorf("createTemplate() subject = %q, want %q", got.Subject, csr.Subject)
	}

	if !slices.Equal(got.DNSNames, csr.DNSNames) {
		t.Errorf("createTemplate() DNS names = %v, want %v", got.DNSNames, csr.DNSNames)
	}

	if !slices.EqualFunc(got.IPAddresses, csr.IPAddresses, net.IP.Equal) {
		t.Errorf("createTemplate() IP addresses = %v, want %v", got.IPAddresses, csr.IPAddresses)
	}

	if !slices.EqualFunc(got.URIs, csr.URIs, func(a, b *url.URL) bool { return a.String() == b.String() }) {
		t.Errorf("createTemplate() URIs = %v, want %v", got.URIs, csr.URIs)
	}

	if !slices.Equal(got.EmailAddresses, csr.EmailAddresses) {
		t.Errorf("createTemplate() email addresses = %v, want %v", got.EmailAddresses, csr.EmailAddresses)
	}

	if len(got.ExtraExtensions) != 0 || len(got.Extensions) != 0 {
		t.Errorf("createTemplate() carried over extensions from the CSR: extra = %v, extensions = %v", got.ExtraExtensions, got.Extensions)
	}

	if got.IsCA {
		t.Errorf("createTemplate() IsCA = true, want false")
	}

	if !got.BasicConstraintsValid {
		t.Errorf("createTemplate() BasicConstraintsValid = false, want true")
	}

	if got.MaxPathLen != 0 || got.MaxPathLenZero {
		t.Errorf("createTemplate() MaxPathLen = %d, MaxPathLenZero = %t, want a non-CA with no path length", got.MaxPathLen, got.MaxPathLenZero)
	}

	if want := x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment; got.KeyUsage != want {
		t.Errorf("createTemplate() KeyUsage = %v, want %v", got.KeyUsage, want)
	}

	if !slices.Equal(got.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}) {
		t.Errorf("createTemplate() ExtKeyUsage = %v, want [ServerAuth]", got.ExtKeyUsage)
	}

	if got.SerialNumber == nil || got.SerialNumber.Sign() <= 0 {
		t.Errorf("createTemplate() SerialNumber = %v, want a positive number", got.SerialNumber)
	}
}

func TestCreateTemplateCA(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name               string
		ca                 *x509.Certificate
		chain              []*x509.Certificate
		wantMaxPathLen     int
		wantMaxPathLenZero bool
	}{
		{
			name:               "an unconstrained authority issues a CA that may only issue end certificates",
			ca:                 pathLenCert(-1, false),
			chain:              nil,
			wantMaxPathLen:     0,
			wantMaxPathLenZero: true,
		},
		{
			name:               "an authority with room for more CAs below the new one",
			ca:                 pathLenCert(3, false),
			chain:              nil,
			wantMaxPathLen:     2,
			wantMaxPathLenZero: false,
		},
		{
			name:               "a constraint further up limits the new CA",
			ca:                 pathLenCert(-1, false),
			chain:              []*x509.Certificate{newTemplateChainCert(-1, false), newTemplateChainCert(4, false)},
			wantMaxPathLen:     1,
			wantMaxPathLenZero: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			tt.ca.NotAfter = testCAExpiry

			got, _, err := createTemplate(t.Context(), newTestCSR(), newTemplateRequest(time.Hour, true), tt.ca, tt.chain, templateTestPolicy, testNow)
			if err != nil {
				t.Fatalf("createTemplate() error = %v, want nil", err)
			}

			if !got.IsCA {
				t.Errorf("createTemplate() IsCA = false, want true")
			}

			if got.KeyUsage&x509.KeyUsageCertSign == 0 {
				t.Errorf("createTemplate() KeyUsage = %v, want cert sign set", got.KeyUsage)
			}

			if got.MaxPathLen != tt.wantMaxPathLen || got.MaxPathLenZero != tt.wantMaxPathLenZero {
				t.Errorf("createTemplate() MaxPathLen = %d, MaxPathLenZero = %t, want %d, %t", got.MaxPathLen, got.MaxPathLenZero, tt.wantMaxPathLen, tt.wantMaxPathLenZero)
			}
		})
	}
}

// usagesTestAllowed is the extended key usages a policy permits in the usagesFor
// tests, wider than the default so that email protection can be asked for.
var usagesTestAllowed = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageEmailProtection}

func TestUsagesFor(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		isCA     bool
		keyUsage x509.KeyUsage
		extUsage []x509.ExtKeyUsage
		wantKU   x509.KeyUsage
		wantEKU  []x509.ExtKeyUsage
	}{
		{
			name:     "a non-CA with no usages gets the defaults",
			isCA:     false,
			keyUsage: 0,
			extUsage: nil,
			wantKU:   x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			wantEKU:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		},
		{
			name:     "a non-CA with cert-manager's default key usages gets server auth",
			isCA:     false,
			keyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			extUsage: nil,
			wantKU:   x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			wantEKU:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		},
		{
			name:     "a CA with cert-manager's default key usages and cert sign gets server auth",
			isCA:     true,
			keyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
			extUsage: nil,
			wantKU:   x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
			wantEKU:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		},
		{
			name:     "a non-CA with only extended usages gets no defaults",
			isCA:     false,
			keyUsage: 0,
			extUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			wantKU:   0,
			wantEKU:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		},
		{
			name:     "a non-CA keeps the usages it asked for",
			isCA:     false,
			keyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment,
			extUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageEmailProtection},
			wantKU:   x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment,
			wantEKU:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageEmailProtection},
		},
		{
			name:     "a CA with no usages gets the defaults and cert sign",
			isCA:     true,
			keyUsage: 0,
			extUsage: nil,
			wantKU:   x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
			wantEKU:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		},
		{
			name:     "a CA keeps its key usages and gains cert sign",
			isCA:     true,
			keyUsage: x509.KeyUsageDigitalSignature,
			extUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			wantKU:   x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
			wantEKU:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		},
		{
			name:     "a CA may ask for crl sign",
			isCA:     true,
			keyUsage: x509.KeyUsageCRLSign,
			extUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			wantKU:   x509.KeyUsageCRLSign | x509.KeyUsageCertSign,
			wantEKU:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		},
		{
			name:     "a CA keeps its extended usages",
			isCA:     true,
			keyUsage: 0,
			extUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			wantKU:   x509.KeyUsageCertSign,
			wantEKU:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			req := CertSigningRequest{
				PEMData:     nil,
				Duration:    0,
				IsCA:        tt.isCA,
				KeyUsage:    tt.keyUsage,
				ExtKeyUsage: tt.extUsage,
			}

			gotKU, gotEKU, err := usagesFor(req, usagesTestAllowed)
			if err != nil {
				t.Fatalf("usagesFor() error = %v, want nil", err)
			}

			if gotKU != tt.wantKU {
				t.Errorf("usagesFor() key usage = %v, want %v", gotKU, tt.wantKU)
			}

			if !slices.Equal(gotEKU, tt.wantEKU) {
				t.Errorf("usagesFor() extended key usage = %v, want %v", gotEKU, tt.wantEKU)
			}
		})
	}
}

// TestUsagesForPolicy checks that every extended key usage, requested or
// defaulted, must be one the policy allows, for end certificates and CAs.
func TestUsagesForPolicy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		isCA     bool
		keyUsage x509.KeyUsage
		extUsage []x509.ExtKeyUsage
		allowed  []x509.ExtKeyUsage
		wantEKU  []x509.ExtKeyUsage
		wantErr  bool
		wantMsg  string
	}{
		{
			name:     "an allowed usage is accepted",
			isCA:     false,
			keyUsage: 0,
			extUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			allowed:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
			wantEKU:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			wantErr:  false,
			wantMsg:  "",
		},
		{
			name:     "code signing is refused",
			isCA:     false,
			keyUsage: 0,
			extUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
			allowed:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
			wantEKU:  nil,
			wantErr:  true,
			wantMsg:  `extended key usage "code signing" is not permitted by policy, which allows ["server auth" "client auth"]`,
		},
		{
			name:     "any is refused unless it is listed",
			isCA:     false,
			keyUsage: 0,
			extUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
			allowed:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
			wantEKU:  nil,
			wantErr:  true,
			wantMsg:  `extended key usage "any" is not permitted`,
		},
		{
			name:     "any is accepted when it is listed",
			isCA:     false,
			keyUsage: 0,
			extUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
			allowed:  []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
			wantEKU:  []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
			wantErr:  false,
			wantMsg:  "",
		},
		{
			name:     "one refused usage among allowed ones refuses the request",
			isCA:     false,
			keyUsage: 0,
			extUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageOCSPSigning},
			allowed:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
			wantEKU:  nil,
			wantErr:  true,
			wantMsg:  `extended key usage "ocsp signing" is not permitted`,
		},
		{
			name:     "a request with no usages gets server auth when the policy allows it",
			isCA:     false,
			keyUsage: 0,
			extUsage: nil,
			allowed:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			wantEKU:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			wantErr:  false,
			wantMsg:  "",
		},
		{
			name:     "a request with no usages is refused when the policy does not allow server auth",
			isCA:     false,
			keyUsage: 0,
			extUsage: nil,
			allowed:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			wantEKU:  nil,
			wantErr:  true,
			wantMsg:  "it is the default for a request with no usages",
		},
		{
			name:     "cert-manager's default key usages get server auth when the policy allows it",
			isCA:     false,
			keyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			extUsage: nil,
			allowed:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			wantEKU:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			wantErr:  false,
			wantMsg:  "",
		},
		{
			name:     "cert-manager's default key usages are refused when the policy does not allow server auth",
			isCA:     false,
			keyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			extUsage: nil,
			allowed:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			wantEKU:  nil,
			wantErr:  true,
			wantMsg:  "it is the default for a request with no usages",
		},
		{
			name:     "digital signature and key encipherment on a CA without cert sign are not the default and are refused",
			isCA:     true,
			keyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCRLSign,
			extUsage: nil,
			allowed:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
			wantEKU:  nil,
			wantErr:  true,
			wantMsg:  "must also name its extended key usages",
		},
		{
			name:     "a CA that asks for cert sign alone is not the default and is refused",
			isCA:     true,
			keyUsage: x509.KeyUsageCertSign,
			extUsage: nil,
			allowed:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
			wantEKU:  nil,
			wantErr:  true,
			wantMsg:  "must also name its extended key usages",
		},
		{
			name:     "digital signature, key encipherment and more is not the default and is refused",
			isCA:     false,
			keyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageContentCommitment,
			extUsage: nil,
			allowed:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
			wantEKU:  nil,
			wantErr:  true,
			wantMsg:  "must also name its extended key usages",
		},
		{
			name:     "a CA asking for a refused usage is refused",
			isCA:     true,
			keyUsage: 0,
			extUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
			allowed:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
			wantEKU:  nil,
			wantErr:  true,
			wantMsg:  `extended key usage "code signing" is not permitted`,
		},
		{
			name:     "a non-CA with key usages and no extended usages is refused",
			isCA:     false,
			keyUsage: x509.KeyUsageDigitalSignature,
			extUsage: nil,
			allowed:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageCodeSigning},
			wantEKU:  nil,
			wantErr:  true,
			wantMsg:  "must also name its extended key usages",
		},
		{
			name:     "a CA with key usages and no extended usages is refused",
			isCA:     true,
			keyUsage: x509.KeyUsageCRLSign,
			extUsage: nil,
			allowed:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
			wantEKU:  nil,
			wantErr:  true,
			wantMsg:  "must also name its extended key usages",
		},
		{
			name:     "any in the policy permits a specific usage",
			isCA:     false,
			keyUsage: 0,
			extUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageCodeSigning},
			allowed:  []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
			wantEKU:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageCodeSigning},
			wantErr:  false,
			wantMsg:  "",
		},
		{
			name:     "any among other usages in the policy permits a specific usage",
			isCA:     true,
			keyUsage: 0,
			extUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning},
			allowed:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageAny},
			wantEKU:  []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning},
			wantErr:  false,
			wantMsg:  "",
		},
		{
			name:     "any in the policy lets a request with no usages get server auth",
			isCA:     false,
			keyUsage: 0,
			extUsage: nil,
			allowed:  []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
			wantEKU:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			wantErr:  false,
			wantMsg:  "",
		},
		{
			name:     "a CA asking for an allowed usage is accepted",
			isCA:     true,
			keyUsage: 0,
			extUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			allowed:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
			wantEKU:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			wantErr:  false,
			wantMsg:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			req := CertSigningRequest{
				PEMData:     nil,
				Duration:    0,
				IsCA:        tt.isCA,
				KeyUsage:    tt.keyUsage,
				ExtKeyUsage: tt.extUsage,
			}

			_, gotEKU, err := usagesFor(req, tt.allowed)

			if tt.wantErr {
				if !errors.Is(err, ErrInvalidRequest) {
					t.Fatalf("usagesFor() error = %v, want %v", err, ErrInvalidRequest)
				}

				if !strings.Contains(err.Error(), tt.wantMsg) {
					t.Errorf("usagesFor() error = %q, want it to contain %q", err, tt.wantMsg)
				}

				return
			}

			if err != nil {
				t.Fatalf("usagesFor() error = %v, want nil", err)
			}

			if !slices.Equal(gotEKU, tt.wantEKU) {
				t.Errorf("usagesFor() extended key usage = %v, want %v", gotEKU, tt.wantEKU)
			}
		})
	}
}

// TestPolicyAllowedExtKeyUsagesDefault checks that a policy listing no usages
// allows server auth and client auth, and nothing else.
func TestPolicyAllowedExtKeyUsagesDefault(t *testing.T) {
	t.Parallel()

	policy := Policy{AllowCA: false, AllowedExtKeyUsages: nil, MaxDuration: time.Hour, AllowedDomains: nil}

	want := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	if got := policy.allowedExtKeyUsages(); !slices.Equal(got, want) {
		t.Errorf("allowedExtKeyUsages() = %v, want %v", got, want)
	}

	policy.AllowedExtKeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}
	if got := policy.allowedExtKeyUsages(); !slices.Equal(got, policy.AllowedExtKeyUsages) {
		t.Errorf("allowedExtKeyUsages() = %v, want the listed usages %v", got, policy.AllowedExtKeyUsages)
	}
}

func TestUsagesForRefused(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		keyUsage x509.KeyUsage
		extUsage []x509.ExtKeyUsage
	}{
		{name: "cert sign", keyUsage: x509.KeyUsageCertSign, extUsage: nil},
		{name: "crl sign", keyUsage: x509.KeyUsageCRLSign, extUsage: nil},
		{name: "cert sign among other usages", keyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, extUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			req := CertSigningRequest{
				PEMData:     nil,
				Duration:    0,
				IsCA:        false,
				KeyUsage:    tt.keyUsage,
				ExtKeyUsage: tt.extUsage,
			}

			gotKU, gotEKU, err := usagesFor(req, usagesTestAllowed)

			if !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("usagesFor() error = %v, want %v", err, ErrInvalidRequest)
			}

			if !strings.Contains(err.Error(), "require a CA certificate") {
				t.Errorf("usagesFor() error = %q, want it to contain %q", err, "require a CA certificate")
			}

			if gotKU != 0 || gotEKU != nil {
				t.Errorf("usagesFor() = (%v, %v) alongside an error, want no usages", gotKU, gotEKU)
			}
		})
	}
}

func TestNewSerialNumber(t *testing.T) {
	t.Parallel()

	const draws = 32

	seen := make(map[string]bool, draws)
	longest := 0

	for range draws {
		serial, err := newSerialNumber()
		if err != nil {
			t.Fatalf("newSerialNumber() error = %v, want nil", err)
		}

		if serial.Sign() < 0 {
			t.Errorf("newSerialNumber() = %v, want a non-negative number", serial)
		}

		if serial.BitLen() > 128 {
			t.Errorf("newSerialNumber() = %v has %d bits, want at most 128", serial, serial.BitLen())
		}

		longest = max(longest, serial.BitLen())

		if seen[serial.String()] {
			t.Errorf("newSerialNumber() returned %v twice", serial)
		}

		seen[serial.String()] = true
	}

	// 128 bit serials are almost always well over 64 bits, so a narrower
	// range shows up here.
	if longest <= 100 {
		t.Errorf("newSerialNumber() longest of %d draws has %d bits, want a 128 bit range", draws, longest)
	}
}
