package vault

import (
	"bytes"
	"crypto/elliptic"
	"crypto/x509"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azcertificates"
)

func TestCertInfoFrom(t *testing.T) {
	t.Parallel()

	der := []byte("der bytes")

	tests := []struct {
		name        string
		resp        azcertificates.GetCertificateResponse
		wantVersion string
		wantEnabled bool
		wantMsg     string // substring expected in the error message, empty means success
	}{
		{
			name:        "enabled certificate is copied out",
			resp:        certResponse(to.Ptr(testCertID), der, certAttributes(to.Ptr(true))),
			wantVersion: testCertVersion,
			wantEnabled: true,
			wantMsg:     "",
		},
		{
			name:        "disabled certificate is copied out",
			resp:        certResponse(to.Ptr(testCertID), der, certAttributes(to.Ptr(false))),
			wantVersion: testCertVersion,
			wantEnabled: false,
			wantMsg:     "",
		},
		{
			name:        "nil id is an error",
			resp:        certResponse(nil, der, certAttributes(to.Ptr(true))),
			wantVersion: "",
			wantEnabled: false,
			wantMsg:     "nil id",
		},
		{
			name:        "id without a version is an error",
			resp:        certResponse(to.Ptr(testCertIDNoVer), der, certAttributes(to.Ptr(true))),
			wantVersion: "",
			wantEnabled: false,
			wantMsg:     "no version",
		},
		{
			name:        "empty id is an error",
			resp:        certResponse(to.Ptr(testCertIDInvalid), der, certAttributes(to.Ptr(true))),
			wantVersion: "",
			wantEnabled: false,
			wantMsg:     "no version",
		},
		{
			name:        "nil certificate data is an error",
			resp:        certResponse(to.Ptr(testCertID), nil, certAttributes(to.Ptr(true))),
			wantVersion: "",
			wantEnabled: false,
			wantMsg:     "no certificate data",
		},
		{
			name:        "empty certificate data is an error",
			resp:        certResponse(to.Ptr(testCertID), []byte{}, certAttributes(to.Ptr(true))),
			wantVersion: "",
			wantEnabled: false,
			wantMsg:     "no certificate data",
		},
		{
			name:        "nil attributes is an error",
			resp:        certResponse(to.Ptr(testCertID), der, nil),
			wantVersion: "",
			wantEnabled: false,
			wantMsg:     "no enabled attribute",
		},
		{
			name:        "nil enabled attribute is an error",
			resp:        certResponse(to.Ptr(testCertID), der, certAttributes(nil)),
			wantVersion: "",
			wantEnabled: false,
			wantMsg:     "no enabled attribute",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := certInfoFrom(tt.resp)

			if tt.wantMsg == "" {
				if err != nil {
					t.Fatalf("certInfoFrom() error = %v, want nil", err)
				}

				if !bytes.Equal(got.der, der) {
					t.Errorf("certInfoFrom() der = %q, want %q", got.der, der)
				}
			} else {
				if err == nil {
					t.Fatalf("certInfoFrom() error = nil, want error containing %q", tt.wantMsg)
				}

				if !strings.Contains(err.Error(), tt.wantMsg) {
					t.Errorf("certInfoFrom() error = %q, want it to contain %q", err, tt.wantMsg)
				}

				// A malformed response is not a problem with the certificate.
				if errors.Is(err, ErrCertificateUnusable) {
					t.Errorf("certInfoFrom() error = %v, want it not to wrap %v", err, ErrCertificateUnusable)
				}

				if got.der != nil {
					t.Errorf("certInfoFrom() der = %q, want nil on error", got.der)
				}
			}

			if got.version != tt.wantVersion {
				t.Errorf("certInfoFrom() version = %q, want %q", got.version, tt.wantVersion)
			}

			if got.enabled != tt.wantEnabled {
				t.Errorf("certInfoFrom() enabled = %t, want %t", got.enabled, tt.wantEnabled)
			}
		})
	}
}

func TestParseCertificate(t *testing.T) {
	t.Parallel()

	ca := issue(t, newCertSpec("ca"), nil)

	tests := []struct {
		name    string
		der     []byte
		want    *x509.Certificate
		wantMsg string // substring expected in the error message, empty means success
	}{
		{
			name:    "valid der is parsed",
			der:     ca.cert.Raw,
			want:    ca.cert,
			wantMsg: "",
		},
		{
			name:    "nil der is unusable",
			der:     nil,
			want:    nil,
			wantMsg: "parsing certificate",
		},
		{
			name:    "garbage der is unusable",
			der:     []byte("not a certificate"),
			want:    nil,
			wantMsg: "parsing certificate",
		},
		{
			name:    "truncated der is unusable",
			der:     ca.cert.Raw[:len(ca.cert.Raw)/2],
			want:    nil,
			wantMsg: "parsing certificate",
		},
		{
			name:    "pem is unusable as it is not der",
			der:     []byte(encodePEM("CERTIFICATE", ca.cert.Raw)),
			want:    nil,
			wantMsg: "parsing certificate",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := parseCertificate(tt.der)

			if tt.wantMsg == "" {
				if err != nil {
					t.Fatalf("parseCertificate() error = %v, want nil", err)
				}

				if got == nil || !got.Equal(tt.want) {
					t.Errorf("parseCertificate() = %v, want %v", got, tt.want)
				}

				return
			}

			if err == nil {
				t.Fatalf("parseCertificate() error = nil, want error containing %q", tt.wantMsg)
			}

			if !errors.Is(err, ErrCertificateUnusable) {
				t.Errorf("parseCertificate() error = %v, want it to wrap %v", err, ErrCertificateUnusable)
			}

			if !strings.Contains(err.Error(), tt.wantMsg) {
				t.Errorf("parseCertificate() error = %q, want it to contain %q", err, tt.wantMsg)
			}

			if got != nil {
				t.Errorf("parseCertificate() = %v, want nil on error", got)
			}
		})
	}
}

func TestCheckValidity(t *testing.T) {
	t.Parallel()

	ca := issue(t, newCertSpec("ca"), nil)

	tests := []struct {
		name    string
		now     time.Time
		wantMsg string // substring expected in the error message, empty means success
	}{
		{
			name:    "inside the validity period",
			now:     chainTestNow,
			wantMsg: "",
		},
		{
			name:    "exactly at not before",
			now:     ca.cert.NotBefore,
			wantMsg: "",
		},
		{
			name:    "exactly at not after",
			now:     ca.cert.NotAfter,
			wantMsg: "",
		},
		{
			name:    "just before not before",
			now:     ca.cert.NotBefore.Add(-time.Second),
			wantMsg: "is not valid until",
		},
		{
			name:    "just after not after",
			now:     ca.cert.NotAfter.Add(time.Second),
			wantMsg: "expired at",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := checkValidity(ca.cert, tt.now)

			if tt.wantMsg == "" {
				if err != nil {
					t.Fatalf("checkValidity() error = %v, want nil", err)
				}

				return
			}

			if err == nil {
				t.Fatalf("checkValidity() error = nil, want error containing %q", tt.wantMsg)
			}

			if !errors.Is(err, ErrCertificateUnusable) {
				t.Errorf("checkValidity() error = %v, want it to wrap %v", err, ErrCertificateUnusable)
			}

			if !strings.Contains(err.Error(), tt.wantMsg) {
				t.Errorf("checkValidity() error = %q, want it to contain %q", err, tt.wantMsg)
			}

			if !strings.Contains(err.Error(), ca.cert.Subject.String()) {
				t.Errorf("checkValidity() error = %q, want it to name the certificate %q", err, ca.cert.Subject.String())
			}
		})
	}
}

func TestCheckUsable(t *testing.T) {
	t.Parallel()

	keyECDSAP224 := newECDSAKeyType("ecdsa-p224", elliptic.P224())

	// withSpec returns a valid CA spec with changes applied to it.
	withSpec := func(change func(s *certSpec)) certSpec {
		spec := newCertSpec("ca")
		change(&spec)

		return spec
	}

	tests := []struct {
		name    string
		spec    certSpec
		enabled bool
		wantMsg string // substring expected in the error message, empty means success
	}{
		{
			name:    "enabled CA with no key usage extension",
			spec:    newCertSpec("ca"),
			enabled: true,
			wantMsg: "",
		},
		{
			name:    "enabled CA with certificate signing key usage",
			spec:    withSpec(func(s *certSpec) { s.keyUsage = x509.KeyUsageCertSign }),
			enabled: true,
			wantMsg: "",
		},
		{
			name:    "enabled CA with certificate signing among other key usages",
			spec:    withSpec(func(s *certSpec) { s.keyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign }),
			enabled: true,
			wantMsg: "",
		},
		{
			name:    "RSA CA is supported",
			spec:    withSpec(func(s *certSpec) { s.key = keyRSA2048 }),
			enabled: true,
			wantMsg: "",
		},
		{
			name:    "disabled CA",
			spec:    newCertSpec("ca"),
			enabled: false,
			wantMsg: "disabled",
		},
		{
			name:    "disabled is reported before an expired validity period",
			spec:    withSpec(func(s *certSpec) { s.notAfter = chainTestNow.Add(-time.Minute) }),
			enabled: false,
			wantMsg: "disabled",
		},
		{
			name:    "expired CA",
			spec:    withSpec(func(s *certSpec) { s.notAfter = chainTestNow.Add(-time.Minute) }),
			enabled: true,
			wantMsg: "expired at",
		},
		{
			name: "CA that is not yet valid",
			spec: withSpec(func(s *certSpec) {
				s.notBefore = chainTestNow.Add(time.Minute)
				s.notAfter = chainTestNow.Add(time.Hour)
			}),
			enabled: true,
			wantMsg: "is not valid until",
		},
		{
			name:    "leaf certificate is not a CA",
			spec:    withSpec(func(s *certSpec) { s.isCA = false }),
			enabled: true,
			wantMsg: "not a CA",
		},
		{
			name: "certificate without basic constraints is not a CA",
			spec: withSpec(func(s *certSpec) {
				s.isCA = false
				s.basicConstraintsValid = false
			}),
			enabled: true,
			wantMsg: "not a CA",
		},
		{
			name:    "key usage without certificate signing",
			spec:    withSpec(func(s *certSpec) { s.keyUsage = x509.KeyUsageDigitalSignature }),
			enabled: true,
			wantMsg: "lacks the certificate-signing key usage",
		},
		{
			name:    "unsupported key type",
			spec:    withSpec(func(s *certSpec) { s.key = keyECDSAP224 }),
			enabled: true,
			wantMsg: "unsupported ECDSA curve",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ca := issue(t, tt.spec, nil)
			info := certInfo{version: testCertVersion, der: ca.cert.Raw, enabled: tt.enabled}

			err := checkUsable(info, ca.cert, chainTestNow)

			if tt.wantMsg == "" {
				if err != nil {
					t.Fatalf("checkUsable() error = %v, want nil", err)
				}

				return
			}

			if err == nil {
				t.Fatalf("checkUsable() error = nil, want error containing %q", tt.wantMsg)
			}

			if !errors.Is(err, ErrCertificateUnusable) {
				t.Errorf("checkUsable() error = %v, want it to wrap %v", err, ErrCertificateUnusable)
			}

			if !strings.Contains(err.Error(), tt.wantMsg) {
				t.Errorf("checkUsable() error = %q, want it to contain %q", err, tt.wantMsg)
			}
		})
	}
}
