package controllers

import (
	"bytes"
	"crypto/x509"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cert-manager/issuer-lib/controllers/signer"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	api "github.com/mike-guy/azure-keyvault-issuer/api/v1alpha1"
	"github.com/mike-guy/azure-keyvault-issuer/internal/azure/vault"
	"github.com/mike-guy/azure-keyvault-issuer/internal/pki"
)

func TestVaultConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		spec api.BaseIssuerSpec
		want vault.Config
	}{
		{
			name: "every field set",
			spec: api.BaseIssuerSpec{
				VaultURL:           "https://my-ca.vault.azure.net/",
				CertificateName:    "ca",
				CertificateVersion: "0123456789abcdef",
				ChainInSecret:      true,
				Policy:             api.Policy{AllowCA: true, AllowedExtKeyUsages: nil, MaxDuration: nil, AllowedDomains: nil},
			},
			want: vault.Config{
				VaultURL:           "https://my-ca.vault.azure.net/",
				CertificateName:    "ca",
				CertificateVersion: "0123456789abcdef",
				ChainInSecret:      true,
			},
		},
		{
			name: "optional fields unset",
			spec: api.BaseIssuerSpec{
				VaultURL:           "https://my-ca.vault.azure.net/",
				CertificateName:    "ca",
				CertificateVersion: "",
				ChainInSecret:      false,
				Policy:             api.Policy{AllowCA: false, AllowedExtKeyUsages: nil, MaxDuration: nil, AllowedDomains: nil},
			},
			want: vault.Config{
				VaultURL:           "https://my-ca.vault.azure.net/",
				CertificateName:    "ca",
				CertificateVersion: "",
				ChainInSecret:      false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := vaultConfig(tt.spec); got != tt.want {
				t.Errorf("vaultConfig() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestPolicy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		spec api.Policy
		want pki.Policy
	}{
		{
			name: "every field set",
			spec: api.Policy{
				AllowCA:             true,
				AllowedExtKeyUsages: []string{"server auth", "code signing"},
				MaxDuration:         &metav1.Duration{Duration: 48 * time.Hour},
				AllowedDomains:      []string{"app.example.com", "*.example.org"},
			},
			want: pki.Policy{
				AllowCA:             true,
				AllowedExtKeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageCodeSigning},
				MaxDuration:         48 * time.Hour,
				AllowedDomains:      []string{"app.example.com", "*.example.org"},
			},
		},
		{
			name: "no max duration falls back to the default",
			spec: api.Policy{AllowCA: false, AllowedExtKeyUsages: nil, MaxDuration: nil, AllowedDomains: nil},
			want: pki.Policy{AllowCA: false, AllowedExtKeyUsages: nil, MaxDuration: defaultMaxDuration, AllowedDomains: nil},
		},
		{
			name: "a set max duration is not replaced by the default",
			spec: api.Policy{AllowCA: false, AllowedExtKeyUsages: nil, MaxDuration: &metav1.Duration{Duration: time.Hour}, AllowedDomains: nil},
			want: pki.Policy{AllowCA: false, AllowedExtKeyUsages: nil, MaxDuration: time.Hour, AllowedDomains: nil},
		},
		{
			name: "usage names map to extended key usages, and s/mime to email protection",
			spec: api.Policy{AllowCA: false, AllowedExtKeyUsages: []string{"client auth", "s/mime", "any"}, MaxDuration: nil, AllowedDomains: nil},
			want: pki.Policy{
				AllowCA:             false,
				AllowedExtKeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageEmailProtection, x509.ExtKeyUsageAny},
				MaxDuration:         defaultMaxDuration,
				AllowedDomains:      nil,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			spec := api.BaseIssuerSpec{
				VaultURL:           "https://my-ca.vault.azure.net/",
				CertificateName:    "ca",
				CertificateVersion: "",
				ChainInSecret:      false,
				Policy:             tt.spec,
			}

			got, err := policy(spec)
			if err != nil {
				t.Fatalf("policy() error = %v, want nil", err)
			}

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("policy() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

// TestPolicyUnsupportedUsage checks that a usage name the CRD would refuse is an
// error, not dropped, so a mistake cannot quietly narrow what the issuer signs.
func TestPolicyUnsupportedUsage(t *testing.T) {
	t.Parallel()

	spec := api.BaseIssuerSpec{
		VaultURL:           "https://my-ca.vault.azure.net/",
		CertificateName:    "ca",
		CertificateVersion: "",
		ChainInSecret:      false,
		Policy:             api.Policy{AllowCA: false, AllowedExtKeyUsages: []string{"server auth", "digital signature"}, MaxDuration: nil, AllowedDomains: nil},
	}

	_, err := policy(spec)
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("policy() error = %v, want %v", err, ErrInvalidConfig)
	}

	if want := `allowedExtKeyUsages[1] "digital signature"`; !strings.Contains(err.Error(), want) {
		t.Errorf("policy() error = %q, want it to contain %q", err, want)
	}
}

func TestDefaultMaxDuration(t *testing.T) {
	t.Parallel()

	// The CRD defaults policy.maxDuration to "2160h", so the two must agree.
	if want := 90 * 24 * time.Hour; defaultMaxDuration != want {
		t.Errorf("defaultMaxDuration = %s, want %s", defaultMaxDuration, want)
	}
}

func TestSigningRequest(t *testing.T) {
	t.Parallel()

	maxPathLen := 2

	details := signer.CertificateDetails{
		CSR:         []byte("csr"),
		Duration:    24 * time.Hour,
		IsCA:        true,
		MaxPathLen:  &maxPathLen,
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}

	want := pki.CertSigningRequest{
		PEMData:     []byte("csr"),
		Duration:    24 * time.Hour,
		IsCA:        true,
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}

	if got := signingRequest(details); !reflect.DeepEqual(got, want) {
		t.Errorf("signingRequest() = %+v, want %+v", got, want)
	}
}

func TestToPEMBundle(t *testing.T) {
	t.Parallel()

	root := newTestCert(t, "root", true, nil)
	inter1 := newTestCert(t, "inter1", true, &root)
	inter2 := newTestCert(t, "inter2", true, &inter1)
	leaf := newTestCert(t, "leaf", false, &inter2)
	rootLeaf := newTestCert(t, "root-leaf", false, &root)

	join := func(parts ...[]byte) []byte {
		return bytes.Join(parts, nil)
	}

	tests := []struct {
		name   string
		signed *pki.SignedCertificate
		want   signer.PEMBundle
	}{
		{
			name: "a self-signed root is split off as the CA",
			signed: &pki.SignedCertificate{
				LeafPEM:   leaf.pem,
				IssuerPEM: inter2.pem,
				ChainPEM:  [][]byte{inter1.pem, root.pem},
			},
			want: signer.PEMBundle{
				ChainPEM: join(leaf.pem, inter2.pem, inter1.pem),
				CAPEM:    root.pem,
			},
		},
		{
			name: "a chain given out of order is ordered",
			signed: &pki.SignedCertificate{
				LeafPEM:   leaf.pem,
				IssuerPEM: inter2.pem,
				ChainPEM:  [][]byte{root.pem, inter1.pem},
			},
			want: signer.PEMBundle{
				ChainPEM: join(leaf.pem, inter2.pem, inter1.pem),
				CAPEM:    root.pem,
			},
		},
		{
			name: "a duplicate is dropped",
			signed: &pki.SignedCertificate{
				LeafPEM:   leaf.pem,
				IssuerPEM: inter2.pem,
				ChainPEM:  [][]byte{inter2.pem, inter1.pem, root.pem},
			},
			want: signer.PEMBundle{
				ChainPEM: join(leaf.pem, inter2.pem, inter1.pem),
				CAPEM:    root.pem,
			},
		},
		{
			name: "no chain above an issuer that is not self-signed makes the issuer the CA",
			signed: &pki.SignedCertificate{
				LeafPEM:   leaf.pem,
				IssuerPEM: inter2.pem,
				ChainPEM:  nil,
			},
			want: signer.PEMBundle{
				ChainPEM: join(leaf.pem, inter2.pem),
				CAPEM:    inter2.pem,
			},
		},
		{
			name: "a self-signed issuer is the CA",
			signed: &pki.SignedCertificate{
				LeafPEM:   rootLeaf.pem,
				IssuerPEM: root.pem,
				ChainPEM:  nil,
			},
			want: signer.PEMBundle{
				ChainPEM: rootLeaf.pem,
				CAPEM:    root.pem,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := toPEMBundle(tt.signed)
			if err != nil {
				t.Fatalf("toPEMBundle() error = %v, want nil", err)
			}

			if !bytes.Equal(got.ChainPEM, tt.want.ChainPEM) {
				t.Errorf("toPEMBundle() ChainPEM = %q, want %q", got.ChainPEM, tt.want.ChainPEM)
			}

			if !bytes.Equal(got.CAPEM, tt.want.CAPEM) {
				t.Errorf("toPEMBundle() CAPEM = %q, want %q", got.CAPEM, tt.want.CAPEM)
			}
		})
	}
}

func TestToPEMBundleErrors(t *testing.T) {
	t.Parallel()

	root := newTestCert(t, "root", true, nil)
	otherRoot := newTestCert(t, "other-root", true, nil)
	leaf := newTestCert(t, "leaf", false, &root)

	tests := []struct {
		name   string
		signed *pki.SignedCertificate
	}{
		{name: "no PEM at all", signed: &pki.SignedCertificate{LeafPEM: nil, IssuerPEM: nil, ChainPEM: nil}},
		{name: "only text that is not PEM", signed: &pki.SignedCertificate{LeafPEM: []byte("not pem"), IssuerPEM: []byte("not pem"), ChainPEM: nil}},
		{name: "an issuer that did not sign the leaf", signed: &pki.SignedCertificate{LeafPEM: leaf.pem, IssuerPEM: otherRoot.pem, ChainPEM: nil}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if _, err := toPEMBundle(tt.signed); err == nil {
				t.Error("toPEMBundle() error = nil, want an error")
			}
		})
	}
}
