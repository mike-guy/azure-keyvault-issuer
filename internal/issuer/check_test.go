package issuer

import (
	"crypto"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/cert-manager/issuer-lib/controllers/signer"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/mike-guy/azure-keyvault-issuer/api/v1alpha1"
	"github.com/mike-guy/azure-keyvault-issuer/internal/keyvault"
)

// otherIssuer is an issuer type this package does not know.
type otherIssuer struct {
	v1alpha1.AzureKeyVaultIssuer
}

var (
	errBadAuth    = errors.New("bad auth")
	errNotAllowed = errors.New("ambient not permitted")
)

func TestCheck(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                string
		chain               v1alpha1.ChainSource
		version             string
		wantChainFromSecret bool
	}{
		{"certificate chain source", v1alpha1.ChainSourceCertificate, "", false},
		{"secret chain source", v1alpha1.ChainSourceSecret, "", true},
		{"pinned version", v1alpha1.ChainSourceCertificate, strings.Repeat("a", 32), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			fetcher := &fakeFetcher{ca: newTestCA(t, time.Now().Add(365*24*time.Hour)).keyvaultCA(t, nil)}
			iss := New(&fakeCreds{}, fetcher, Options{})

			ci := newClusterIssuer("uid", 1)
			ci.Spec.ChainSource = tt.chain
			ci.Spec.CertificateVersion = tt.version

			if err := iss.Check(t.Context(), ci); err != nil {
				t.Fatalf("Check() error = %v", err)
			}

			wantSource := "test-ca/issuing-ca@current"
			if tt.version != "" {
				wantSource = "test-ca/issuing-ca@" + tt.version
			}

			if len(fetcher.sources) != 1 {
				t.Fatalf("fetched %v, want [%s]", fetcher.sources, wantSource)
			}

			if got := fetcher.sources[0]; got.String() != wantSource || got.ChainFromSecret != tt.wantChainFromSecret {
				t.Errorf("fetched %s with ChainFromSecret %t, want %s with %t",
					got, got.ChainFromSecret, wantSource, tt.wantChainFromSecret)
			}
		})
	}
}

func TestCheckErrors(t *testing.T) {
	t.Parallel()

	allowed, err := keyvault.ParseVaultURL("https://other-ca.vault.azure.net")
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name          string
		issuer        func() v1alpha1.AzureKeyVaultIssuer // namespaced unless cluster is set
		cluster       bool
		credErr       error
		fetchErr      error
		probeErr      error
		wrongKey      bool // the signer's key is not the CA certificate's
		allowedVaults []keyvault.VaultURL
		wantPermanent bool
		wantErr       error    // nil: any error
		wantContains  []string // substrings an operator needs in the condition
	}{
		{
			name: "bad vault URL",
			issuer: func() v1alpha1.AzureKeyVaultIssuer {
				i := *newNamespacedIssuer("uid", 1)
				i.Spec.VaultURL = "https://example.com/"

				return i
			},
			wantPermanent: true,
			wantErr:       keyvault.ErrInvalidVaultURL,
		},
		{
			name: "bad certificate name",
			issuer: func() v1alpha1.AzureKeyVaultIssuer {
				i := *newNamespacedIssuer("uid", 1)
				i.Spec.CertificateName = "a/b"

				return i
			},
			wantPermanent: true,
			wantErr:       ErrInvalidSpec,
		},
		{
			name: "maxDuration under an hour",
			issuer: func() v1alpha1.AzureKeyVaultIssuer {
				i := *newNamespacedIssuer("uid", 1)
				i.Spec.Policy.MaxDuration = &metav1.Duration{Duration: 30 * time.Minute}

				return i
			},
			wantPermanent: true,
			wantErr:       ErrInvalidSpec,
		},
		{
			name:          "permanent credential error",
			credErr:       errBadAuth,
			wantPermanent: true,
			wantErr:       errBadAuth,
		},
		{
			name:    "credential error that depends on controller flags",
			credErr: errNotAllowed,
			wantErr: errNotAllowed,
		},
		{
			name:          "vault not in allow-list",
			allowedVaults: []keyvault.VaultURL{allowed},
			wantErr:       ErrVaultNotAllowed,
		},
		{
			name:         "fetch forbidden",
			fetchErr:     responseError(t, http.StatusForbidden),
			wantContains: []string{"test-ca/issuing-ca@current", "HTTP 403"},
		},
		{
			name:     "CA disabled",
			fetchErr: keyvault.ErrCADisabled,
			wantErr:  keyvault.ErrCADisabled,
		},
		{
			name:         "test signature refused",
			probeErr:     responseError(t, http.StatusForbidden),
			wantContains: []string{"test-ca/issuing-ca@current", "test signature", "HTTP 403"},
		},
		{
			name:         "key does not match the certificate",
			wrongKey:     true,
			wantContains: []string{"test-ca/issuing-ca@current", "test signature", "signature"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var wrap func(crypto.Signer) crypto.Signer
			if tt.probeErr != nil {
				wrap = func(k crypto.Signer) crypto.Signer { return failingSigner{Signer: k, err: tt.probeErr} }
			}

			if tt.wrongKey {
				wrap = func(k crypto.Signer) crypto.Signer { return mismatchedSigner{Signer: k, other: newKey(t)} }
			}

			fetcher := &fakeFetcher{ca: newTestCA(t, time.Now().Add(365*24*time.Hour)).keyvaultCA(t, wrap), err: tt.fetchErr}
			iss := New(&fakeCreds{err: tt.credErr}, fetcher, Options{
				AllowedVaults:     tt.allowedVaults,
				InvalidSpecErrors: []error{errBadAuth},
			})

			obj := newNamespacedIssuer("uid", 1)
			if tt.issuer != nil {
				i := tt.issuer()
				obj = &i
			}

			err := iss.Check(t.Context(), obj)
			if err == nil {
				t.Fatal("Check() error = nil, want an error")
			}

			if got := errors.As(err, &signer.PermanentError{}); got != tt.wantPermanent {
				t.Errorf("Check() error %q permanent = %t, want %t", err, got, tt.wantPermanent)
			}

			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Errorf("Check() error = %v, want %v", err, tt.wantErr)
			}

			for _, want := range tt.wantContains {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("Check() error %q does not contain %q", err, want)
				}
			}

			if strings.Contains(err.Error(), "\n") {
				t.Errorf("Check() error text spans lines: %q", err.Error())
			}
		})
	}
}

func TestCheckAllowListAppliesOnlyToNamespacedIssuers(t *testing.T) {
	t.Parallel()

	allowed, err := keyvault.ParseVaultURL(testVaultURL)
	if err != nil {
		t.Fatal(err)
	}

	other, err := keyvault.ParseVaultURL("https://other-ca.vault.azure.net/")
	if err != nil {
		t.Fatal(err)
	}

	fetcher := &fakeFetcher{ca: newTestCA(t, time.Now().Add(365*24*time.Hour)).keyvaultCA(t, nil)}

	// The vault's URL without a trailing slash still matches.
	ns := newNamespacedIssuer("uid-1", 1)
	ns.Spec.VaultURL = strings.TrimSuffix(testVaultURL, "/")

	if err := New(&fakeCreds{}, fetcher, Options{AllowedVaults: []keyvault.VaultURL{allowed}}).Check(t.Context(), ns); err != nil {
		t.Errorf("Check(namespaced issuer, allowed vault) error = %v", err)
	}

	if err := New(&fakeCreds{}, fetcher, Options{AllowedVaults: []keyvault.VaultURL{other}}).Check(t.Context(), newClusterIssuer("uid-2", 1)); err != nil {
		t.Errorf("Check(ClusterIssuer, vault not in list) error = %v", err)
	}
}

func TestCheckUnsupportedIssuer(t *testing.T) {
	t.Parallel()

	creds := &fakeCreds{}
	iss := New(creds, &fakeFetcher{}, Options{})

	err := iss.Check(t.Context(), &otherIssuer{AzureKeyVaultIssuer: *newNamespacedIssuer("uid", 1)})
	if !errors.Is(err, ErrUnsupportedIssuer) || !errors.As(err, &signer.PermanentError{}) {
		t.Errorf("Check() error = %v, want a permanent %v", err, ErrUnsupportedIssuer)
	}

	if creds.count() != 0 {
		t.Errorf("credential provider called %d times, want 0", creds.count())
	}
}

// TestCheckUsesCachedCredential checks that Check shares the cache with Sign:
// it reuses the credential for the same generation and builds a new one when
// the spec changes.
func TestCheckUsesCachedCredential(t *testing.T) {
	t.Parallel()

	creds := &fakeCreds{}
	fetcher := &fakeFetcher{ca: newTestCA(t, time.Now().Add(365*24*time.Hour)).keyvaultCA(t, nil)}
	iss := New(creds, fetcher, Options{})

	for _, generation := range []int64{1, 1, 2} {
		if err := iss.Check(t.Context(), newClusterIssuer("uid", generation)); err != nil {
			t.Fatalf("Check() error = %v", err)
		}
	}

	if creds.count() != 2 {
		t.Errorf("credential provider called %d times, want 2", creds.count())
	}

	if fetcher.creds[0] != fetcher.creds[1] {
		t.Error("the second Check of the same generation built a new credential")
	}

	if fetcher.creds[1] == fetcher.creds[2] {
		t.Error("the Check after a spec change reused the old credential")
	}
}
