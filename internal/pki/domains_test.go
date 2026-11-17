package pki

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestValidateDomainPattern(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		pattern string
		wantErr bool
		wantMsg string
	}{
		{name: "a name", pattern: "app.example.com", wantErr: false, wantMsg: ""},
		{name: "a name of one label", pattern: "localhost", wantErr: false, wantMsg: ""},
		{name: "a name with capitals", pattern: "App.Example.COM", wantErr: false, wantMsg: ""},
		{name: "a name with hyphens and digits", pattern: "a-1.b2.example.com", wantErr: false, wantMsg: ""},
		{name: "an internationalised name in its ASCII form", pattern: "xn--bcher-kva.example.com", wantErr: false, wantMsg: ""},
		{name: "one label of wildcard", pattern: "*.example.com", wantErr: false, wantMsg: ""},
		{name: "any depth of wildcard", pattern: "**.example.com", wantErr: false, wantMsg: ""},
		{name: "the least a wildcard may cover", pattern: "*.example.io", wantErr: false, wantMsg: ""},
		{name: "empty", pattern: "", wantErr: true, wantMsg: "must be a name"},
		{name: "a bare wildcard", pattern: "*", wantErr: true, wantMsg: "must be a name"},
		{name: "a bare double wildcard", pattern: "**", wantErr: true, wantMsg: "must be a name"},
		{name: "a wildcard with nothing after it", pattern: "*.", wantErr: true, wantMsg: "at least 2 labels"},
		{name: "a wildcard over a top level domain", pattern: "*.com", wantErr: true, wantMsg: "at least 2 labels"},
		{name: "a double wildcard over a top level domain", pattern: "**.com", wantErr: true, wantMsg: "at least 2 labels"},
		{name: "a wildcard that is not first", pattern: "a.*.example.com", wantErr: true, wantMsg: "must be a name"},
		{name: "a wildcard that is part of a label", pattern: "a*.example.com", wantErr: true, wantMsg: "must be a name"},
		{name: "a triple wildcard", pattern: "***.example.com", wantErr: true, wantMsg: "must be a name"},
		{name: "a trailing dot", pattern: "example.com.", wantErr: true, wantMsg: "must be a name"},
		{name: "a leading dot", pattern: ".example.com", wantErr: true, wantMsg: "must be a name"},
		{name: "an empty label", pattern: "a..example.com", wantErr: true, wantMsg: "must be a name"},
		{name: "a label starting with a hyphen", pattern: "-a.example.com", wantErr: true, wantMsg: "must be a name"},
		{name: "a label ending with a hyphen", pattern: "a-.example.com", wantErr: true, wantMsg: "must be a name"},
		{name: "an underscore", pattern: "a_b.example.com", wantErr: true, wantMsg: "must be a name"},
		{name: "a space", pattern: "a b.example.com", wantErr: true, wantMsg: "must be a name"},
		{name: "a non ASCII label", pattern: "bücher.example.com", wantErr: true, wantMsg: "must be a name"},
		{name: "a label that is too long", pattern: strings.Repeat("a", 64) + ".example.com", wantErr: true, wantMsg: "must be a name"},
		{name: "a name that is too long", pattern: strings.Repeat("a.", 127) + "com", wantErr: true, wantMsg: "at most 253 characters"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := validateDomainPattern(tt.pattern)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validateDomainPattern(%q) error = %v, wantErr %t", tt.pattern, err, tt.wantErr)
			}

			if err != nil && !strings.Contains(err.Error(), tt.wantMsg) {
				t.Errorf("validateDomainPattern(%q) error = %q, want it to contain %q", tt.pattern, err, tt.wantMsg)
			}
		})
	}
}

func TestPolicyValidateAllowedDomains(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		policy  Policy
		wantErr error
		wantMsg string
	}{
		{
			name:    "no domains",
			policy:  Policy{AllowCA: false, AllowedExtKeyUsages: nil, MaxDuration: time.Hour, AllowedDomains: nil},
			wantErr: nil,
			wantMsg: "",
		},
		{
			name:    "valid domains",
			policy:  Policy{AllowCA: false, AllowedExtKeyUsages: nil, MaxDuration: time.Hour, AllowedDomains: []string{"example.com", "*.example.org", "**.example.net"}},
			wantErr: nil,
			wantMsg: "",
		},
		{
			name:    "domains with allowCA",
			policy:  Policy{AllowCA: true, AllowedExtKeyUsages: nil, MaxDuration: time.Hour, AllowedDomains: []string{"example.com"}},
			wantErr: ErrInvalidConfig,
			wantMsg: "allowCA cannot be combined with allowedDomains",
		},
		{
			name:    "allowCA without domains",
			policy:  Policy{AllowCA: true, AllowedExtKeyUsages: nil, MaxDuration: time.Hour, AllowedDomains: nil},
			wantErr: nil,
			wantMsg: "",
		},
		{
			name:    "an invalid domain names its position and value",
			policy:  Policy{AllowCA: false, AllowedExtKeyUsages: nil, MaxDuration: time.Hour, AllowedDomains: []string{"example.com", "**.com"}},
			wantErr: ErrInvalidConfig,
			wantMsg: `allowedDomains[1] "**.com"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := tt.policy.validate()
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("validate() error = %v, want %v", err, tt.wantErr)
			}

			if err != nil && !strings.Contains(err.Error(), tt.wantMsg) {
				t.Errorf("validate() error = %q, want it to contain %q", err, tt.wantMsg)
			}
		})
	}
}

func TestCheckAllowedDomains(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		csr     *x509.CertificateRequest
		allowed []string
		wantErr error
		wantMsg string
	}{
		{
			name:    "no entries permit any name",
			csr:     &x509.CertificateRequest{DNSNames: []string{"anything.example"}},
			allowed: nil,
			wantErr: nil,
			wantMsg: "",
		},
		{
			name:    "no entries permit any other kind of name",
			csr:     &x509.CertificateRequest{IPAddresses: []net.IP{net.ParseIP("192.0.2.1")}, EmailAddresses: []string{"a@example.com"}},
			allowed: nil,
			wantErr: nil,
			wantMsg: "",
		},
		{
			name:    "a name permits itself",
			csr:     &x509.CertificateRequest{DNSNames: []string{"app.domain.com"}},
			allowed: []string{"app.domain.com"},
			wantErr: nil,
			wantMsg: "",
		},
		{
			name:    "a name is matched without regard to case",
			csr:     &x509.CertificateRequest{DNSNames: []string{"APP.Domain.COM"}},
			allowed: []string{"app.domain.com"},
			wantErr: nil,
			wantMsg: "",
		},
		{
			name:    "a pattern is matched without regard to case",
			csr:     &x509.CertificateRequest{DNSNames: []string{"a.domain.com"}},
			allowed: []string{"*.DOMAIN.com"},
			wantErr: nil,
			wantMsg: "",
		},
		{
			name:    "a name does not permit its subdomains",
			csr:     &x509.CertificateRequest{DNSNames: []string{"a.domain.com"}},
			allowed: []string{"domain.com"},
			wantErr: ErrInvalidRequest,
			wantMsg: `"a.domain.com"`,
		},
		{
			name:    "a name does not permit another name",
			csr:     &x509.CertificateRequest{DNSNames: []string{"other.com"}},
			allowed: []string{"domain.com"},
			wantErr: ErrInvalidRequest,
			wantMsg: `"other.com"`,
		},
		{
			name:    "one label of wildcard permits one label",
			csr:     &x509.CertificateRequest{DNSNames: []string{"test1.domain.com", "test2.domain.com"}},
			allowed: []string{"*.domain.com"},
			wantErr: nil,
			wantMsg: "",
		},
		{
			name:    "one label of wildcard refuses the bare domain",
			csr:     &x509.CertificateRequest{DNSNames: []string{"domain.com"}},
			allowed: []string{"*.domain.com"},
			wantErr: ErrInvalidRequest,
			wantMsg: `"domain.com"`,
		},
		{
			name:    "one label of wildcard refuses two labels",
			csr:     &x509.CertificateRequest{DNSNames: []string{"test1.something.domain.com"}},
			allowed: []string{"*.domain.com"},
			wantErr: ErrInvalidRequest,
			wantMsg: `"test1.something.domain.com"`,
		},
		{
			name:    "one label of wildcard refuses a domain that only ends with the same text",
			csr:     &x509.CertificateRequest{DNSNames: []string{"a.notdomain.com"}},
			allowed: []string{"*.domain.com"},
			wantErr: ErrInvalidRequest,
			wantMsg: `"a.notdomain.com"`,
		},
		{
			name:    "any depth permits one label",
			csr:     &x509.CertificateRequest{DNSNames: []string{"test1.domain.com"}},
			allowed: []string{"**.domain.com"},
			wantErr: nil,
			wantMsg: "",
		},
		{
			name:    "any depth permits many labels",
			csr:     &x509.CertificateRequest{DNSNames: []string{"a.b.c.domain.com"}},
			allowed: []string{"**.domain.com"},
			wantErr: nil,
			wantMsg: "",
		},
		{
			name:    "any depth refuses the bare domain",
			csr:     &x509.CertificateRequest{DNSNames: []string{"domain.com"}},
			allowed: []string{"**.domain.com"},
			wantErr: ErrInvalidRequest,
			wantMsg: `"domain.com"`,
		},
		{
			name:    "any depth refuses a domain that only ends with the same text",
			csr:     &x509.CertificateRequest{DNSNames: []string{"notdomain.com"}},
			allowed: []string{"**.domain.com"},
			wantErr: ErrInvalidRequest,
			wantMsg: `"notdomain.com"`,
		},
		{
			name:    "any depth refuses another domain",
			csr:     &x509.CertificateRequest{DNSNames: []string{"a.domain.org"}},
			allowed: []string{"**.domain.com"},
			wantErr: ErrInvalidRequest,
			wantMsg: `"a.domain.org"`,
		},
		{
			name:    "the bare domain can be listed beside a wildcard",
			csr:     &x509.CertificateRequest{DNSNames: []string{"domain.com", "a.domain.com"}},
			allowed: []string{"domain.com", "*.domain.com"},
			wantErr: nil,
			wantMsg: "",
		},
		{
			name:    "any entry that matches is enough",
			csr:     &x509.CertificateRequest{DNSNames: []string{"a.two.org"}},
			allowed: []string{"*.one.com", "*.two.org"},
			wantErr: nil,
			wantMsg: "",
		},
		{
			name:    "every name must be permitted",
			csr:     &x509.CertificateRequest{DNSNames: []string{"a.domain.com", "evil.com"}},
			allowed: []string{"*.domain.com"},
			wantErr: ErrInvalidRequest,
			wantMsg: `"evil.com"`,
		},
		{
			name:    "a wildcard request is permitted by the same wildcard",
			csr:     &x509.CertificateRequest{DNSNames: []string{"*.domain.com"}},
			allowed: []string{"*.domain.com"},
			wantErr: nil,
			wantMsg: "",
		},
		{
			name:    "a wildcard request is permitted by any depth",
			csr:     &x509.CertificateRequest{DNSNames: []string{"*.domain.com"}},
			allowed: []string{"**.domain.com"},
			wantErr: nil,
			wantMsg: "",
		},
		{
			name:    "a wildcard request is not permitted by a name",
			csr:     &x509.CertificateRequest{DNSNames: []string{"*.domain.com"}},
			allowed: []string{"domain.com"},
			wantErr: ErrInvalidRequest,
			wantMsg: `"*.domain.com"`,
		},
		{
			name:    "a wildcard request is not permitted for another domain",
			csr:     &x509.CertificateRequest{DNSNames: []string{"*.other.com"}},
			allowed: []string{"*.domain.com"},
			wantErr: ErrInvalidRequest,
			wantMsg: `"*.other.com"`,
		},
		{
			name:    "a wildcard request below the permitted level is refused by one label",
			csr:     &x509.CertificateRequest{DNSNames: []string{"*.a.domain.com"}},
			allowed: []string{"*.domain.com"},
			wantErr: ErrInvalidRequest,
			wantMsg: `"*.a.domain.com"`,
		},
		{
			name:    "a wildcard request below the permitted level is permitted by any depth",
			csr:     &x509.CertificateRequest{DNSNames: []string{"*.a.domain.com"}},
			allowed: []string{"**.domain.com"},
			wantErr: nil,
			wantMsg: "",
		},
		{
			name:    "a wildcard that is not the first label is refused",
			csr:     &x509.CertificateRequest{DNSNames: []string{"a.*.domain.com"}},
			allowed: []string{"**.domain.com"},
			wantErr: ErrInvalidRequest,
			wantMsg: `"a.*.domain.com"`,
		},
		{
			name:    "a wildcard that is part of a label is refused",
			csr:     &x509.CertificateRequest{DNSNames: []string{"a*.domain.com"}},
			allowed: []string{"*.domain.com"},
			wantErr: ErrInvalidRequest,
			wantMsg: `"a*.domain.com"`,
		},
		{
			name:    "a name with a trailing dot is refused",
			csr:     &x509.CertificateRequest{DNSNames: []string{"a.domain.com."}},
			allowed: []string{"**.domain.com"},
			wantErr: ErrInvalidRequest,
			wantMsg: `"a.domain.com."`,
		},
		{
			name:    "a name with an empty label is refused",
			csr:     &x509.CertificateRequest{DNSNames: []string{"a..domain.com"}},
			allowed: []string{"**.domain.com"},
			wantErr: ErrInvalidRequest,
			wantMsg: `"a..domain.com"`,
		},
		{
			name:    "a name with a space is refused",
			csr:     &x509.CertificateRequest{DNSNames: []string{"a b.domain.com"}},
			allowed: []string{"**.domain.com"},
			wantErr: ErrInvalidRequest,
			wantMsg: `"a b.domain.com"`,
		},
		{
			name:    "a name that is not ASCII is refused",
			csr:     &x509.CertificateRequest{DNSNames: []string{"bücher.domain.com"}},
			allowed: []string{"**.domain.com"},
			wantErr: ErrInvalidRequest,
			wantMsg: `"bücher.domain.com"`,
		},
		{
			name:    "an underscore in a requested name is accepted",
			csr:     &x509.CertificateRequest{DNSNames: []string{"_dmarc.domain.com"}},
			allowed: []string{"*.domain.com"},
			wantErr: nil,
			wantMsg: "",
		},
		{
			name:    "an IP address is refused when domains are listed",
			csr:     &x509.CertificateRequest{DNSNames: []string{"a.domain.com"}, IPAddresses: []net.IP{net.ParseIP("192.0.2.1")}},
			allowed: []string{"*.domain.com"},
			wantErr: ErrInvalidRequest,
			wantMsg: "IP addresses, email addresses and URIs",
		},
		{
			name:    "an email address is refused when domains are listed",
			csr:     &x509.CertificateRequest{DNSNames: []string{"a.domain.com"}, EmailAddresses: []string{"a@domain.com"}},
			allowed: []string{"*.domain.com"},
			wantErr: ErrInvalidRequest,
			wantMsg: "IP addresses, email addresses and URIs",
		},
		{
			name:    "a URI is refused when domains are listed",
			csr:     &x509.CertificateRequest{DNSNames: []string{"a.domain.com"}, URIs: []*url.URL{{Scheme: "https", Host: "a.domain.com", Path: "/x"}}},
			allowed: []string{"*.domain.com"},
			wantErr: ErrInvalidRequest,
			wantMsg: "IP addresses, email addresses and URIs",
		},
		{
			name:    "a common name that is not permitted is refused",
			csr:     &x509.CertificateRequest{Subject: pkix.Name{CommonName: "evil.com"}, DNSNames: []string{"a.domain.com"}},
			allowed: []string{"*.domain.com"},
			wantErr: ErrInvalidRequest,
			wantMsg: `common name "evil.com" is not permitted`,
		},
		{
			name:    "a common name that is permitted is accepted",
			csr:     &x509.CertificateRequest{Subject: pkix.Name{CommonName: "a.domain.com"}, DNSNames: []string{"a.domain.com"}},
			allowed: []string{"*.domain.com"},
			wantErr: nil,
			wantMsg: "",
		},
		{
			name:    "a common name alone is accepted when it is permitted",
			csr:     &x509.CertificateRequest{Subject: pkix.Name{CommonName: "a.domain.com"}},
			allowed: []string{"*.domain.com"},
			wantErr: nil,
			wantMsg: "",
		},
		{
			name:    "a common name alone is refused when it is not permitted",
			csr:     &x509.CertificateRequest{Subject: pkix.Name{CommonName: "no-names"}},
			allowed: []string{"*.domain.com"},
			wantErr: ErrInvalidRequest,
			wantMsg: `common name "no-names" is not permitted`,
		},
		{
			name:    "DNS names alone with an empty subject are accepted",
			csr:     &x509.CertificateRequest{DNSNames: []string{"a.domain.com"}},
			allowed: []string{"*.domain.com"},
			wantErr: nil,
			wantMsg: "",
		},
		{
			name:    "a request with neither a DNS name nor a common name is refused",
			csr:     &x509.CertificateRequest{Subject: pkix.Name{Organization: []string{"system:masters"}}},
			allowed: []string{"*.domain.com"},
			wantErr: ErrInvalidRequest,
			wantMsg: "a DNS name or a common name is required",
		},
		{
			name:    "an organisation is refused even with a permitted DNS name",
			csr:     &x509.CertificateRequest{Subject: pkix.Name{Organization: []string{"system:masters"}}, DNSNames: []string{"a.domain.com"}},
			allowed: []string{"*.domain.com"},
			wantErr: ErrInvalidRequest,
			wantMsg: "subject attributes other than the common name",
		},
		{
			name:    "an organisation with a permitted common name is refused",
			csr:     &x509.CertificateRequest{Subject: pkix.Name{CommonName: "a.domain.com", OrganizationalUnit: []string{"admins"}}},
			allowed: []string{"*.domain.com"},
			wantErr: ErrInvalidRequest,
			wantMsg: "subject attributes other than the common name",
		},
		{
			name: "an attribute with no field of its own, as in a parsed subject, is refused",
			csr: &x509.CertificateRequest{
				Subject: pkix.Name{
					CommonName: "a.domain.com",
					Names: []pkix.AttributeTypeAndValue{
						{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "a.domain.com"},
						{Type: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}, Value: "admin@domain.com"},
					},
				},
			},
			allowed: []string{"*.domain.com"},
			wantErr: ErrInvalidRequest,
			wantMsg: "subject attributes other than the common name",
		},
		{
			name: "a second common name in a parsed subject is refused",
			csr: &x509.CertificateRequest{
				Subject: pkix.Name{
					CommonName: "a.domain.com",
					Names: []pkix.AttributeTypeAndValue{
						{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "evil.com"},
						{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "a.domain.com"},
					},
				},
			},
			allowed: []string{"*.domain.com"},
			wantErr: ErrInvalidRequest,
			wantMsg: "subject attributes other than the common name",
		},
		{
			name: "a parsed subject with only a permitted common name is accepted",
			csr: &x509.CertificateRequest{
				Subject: pkix.Name{
					CommonName: "a.domain.com",
					Names:      []pkix.AttributeTypeAndValue{{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "a.domain.com"}},
				},
			},
			allowed: []string{"*.domain.com"},
			wantErr: nil,
			wantMsg: "",
		},
		{
			name:    "a subject with only a permitted common name and no allowed domains is not checked",
			csr:     &x509.CertificateRequest{Subject: pkix.Name{CommonName: "anything", Organization: []string{"any"}}},
			allowed: nil,
			wantErr: nil,
			wantMsg: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := checkAllowedDomains(tt.csr, tt.allowed)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("checkAllowedDomains() error = %v, want %v", err, tt.wantErr)
			}

			if err != nil && !strings.Contains(err.Error(), tt.wantMsg) {
				t.Errorf("checkAllowedDomains() error = %q, want it to contain %q", err, tt.wantMsg)
			}
		})
	}
}
