package issuer

import (
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/cert-manager/issuer-lib/controllers/signer"
	certificatesv1 "k8s.io/api/certificates/v1"

	"github.com/mike-guy/azure-keyvault-issuer/api/v1alpha1"
	"github.com/mike-guy/azure-keyvault-issuer/internal/keyvault"
)

// TestSignIssuesVerifiableCertificate checks the issued certificate for a
// two-tier PKI (root, issuing CA) and with intermediates between the issuing CA
// and the root. The self-signed root is always left out of the chain, for
// trust-manager to distribute, and the bundle must be enough, with the root,
// to verify the leaf.
func TestSignIssuesVerifiableCertificate(t *testing.T) {
	t.Parallel()

	for _, count := range []int{0, 1, 2, 3} {
		t.Run(fmt.Sprintf("%d intermediates", count), func(t *testing.T) {
			t.Parallel()

			tca := newTestCAWithIntermediates(t, time.Now().Add(365*24*time.Hour), count)
			events := &fakeEvents{}
			iss := New(&fakeCreds{}, &fakeFetcher{ca: tca.keyvaultCA(t, nil)}, Options{Events: events})

			bundle, err := iss.Sign(t.Context(), newRequest(t, requestSpec{}), newClusterIssuer("uid", 1))
			if err != nil {
				t.Fatalf("Sign() error = %v", err)
			}

			// The leaf, then the issuing CA and each intermediate up to, but
			// not including, the root.
			certs := parseBundle(t, bundle)

			want := tca.chain()
			want = want[:len(want)-1]

			if len(certs) != len(want)+1 {
				t.Fatalf("chain has %d certificates, want the leaf and %d CA certificates", len(certs), len(want))
			}

			for i, w := range want {
				if !certs[i+1].Equal(w) {
					t.Errorf("chain[%d] = %q, want %q", i+1, certs[i+1].Subject.CommonName, w.Subject.CommonName)
				}
			}

			roots := x509.NewCertPool()
			roots.AddCert(tca.root)

			intermediates := x509.NewCertPool()
			for _, c := range certs[1:] {
				intermediates.AddCert(c)
			}

			if _, err := certs[0].Verify(x509.VerifyOptions{
				DNSName: "app.example.com", Roots: roots, Intermediates: intermediates,
			}); err != nil {
				t.Errorf("issued certificate does not verify with the bundle and the root: %v", err)
			}

			if certs[0].IsCA {
				t.Error("issued certificate is a CA")
			}

			// cert-manager's default duration is 90 days, which maxDuration allows.
			if got := certs[0].NotAfter.Sub(certs[0].NotBefore); got != 2160*time.Hour {
				t.Errorf("lifetime = %s, want 2160h", got)
			}

			if len(events.events) != 0 {
				t.Errorf("events = %v, want none", events.events)
			}
		})
	}
}

func TestSignClampsLifetime(t *testing.T) {
	t.Parallel()

	// Beyond caExpiryWarning, so the only event is the clamp.
	caNotAfter := time.Now().Add(45 * 24 * time.Hour).Truncate(time.Second)

	tests := []struct {
		name         string
		caNotAfter   time.Time
		maxDuration  *time.Duration // nil: unset, so the default applies
		duration     time.Duration
		wantLifetime time.Duration // zero: check against caNotAfter instead
		wantClamped  bool
	}{
		{"within maxDuration", time.Time{}, ptr(24 * time.Hour), time.Hour, time.Hour, false},
		{"over maxDuration", time.Time{}, ptr(24 * time.Hour), 48 * time.Hour, 24 * time.Hour, true},
		{"over default maxDuration", time.Time{}, nil, 365 * 24 * time.Hour, 2160 * time.Hour, true},
		{"beyond the CA's expiry", caNotAfter, nil, 60 * 24 * time.Hour, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			notAfter := tt.caNotAfter
			if notAfter.IsZero() {
				notAfter = time.Now().Add(365 * 24 * time.Hour)
			}

			events := &fakeEvents{}
			iss := New(&fakeCreds{}, &fakeFetcher{ca: newTestCA(t, notAfter).keyvaultCA(t, nil)}, Options{Events: events})

			ci := newClusterIssuer("uid", 1)
			ci.Spec.Policy.MaxDuration = nil

			if tt.maxDuration != nil {
				ci.Spec.Policy.MaxDuration = ptrDuration(*tt.maxDuration)
			}

			bundle, err := iss.Sign(t.Context(), newRequest(t, requestSpec{duration: tt.duration}), ci)
			if err != nil {
				t.Fatalf("Sign() error = %v", err)
			}

			leaf := parseBundle(t, bundle)[0]

			if tt.wantLifetime != 0 {
				if got := leaf.NotAfter.Sub(leaf.NotBefore); got != tt.wantLifetime {
					t.Errorf("lifetime = %s, want %s", got, tt.wantLifetime)
				}
			} else if !leaf.NotAfter.Equal(caNotAfter) {
				t.Errorf("NotAfter = %s, want the CA's %s", leaf.NotAfter, caNotAfter)
			}

			if !tt.wantClamped {
				if len(events.events) != 0 {
					t.Errorf("events = %v, want none", events.events)
				}

				return
			}

			if len(events.events) != 1 {
				t.Fatalf("got %d events, want 1", len(events.events))
			}

			e := events.events[0]
			cr, ok := e.regarding.(*cmapi.CertificateRequest)

			if !ok || cr.Namespace != "team-a" || cr.Name != "app" || cr.UID != "cr-uid" || cr.Kind != cmapi.CertificateRequestKind {
				t.Errorf("event regards %#v, want CertificateRequest team-a/app", e.regarding)
			}

			if e.reason != reasonDurationClamped || !strings.Contains(e.note, "shortened") {
				t.Errorf("event = %s %q", e.reason, e.note)
			}
		})
	}
}

func TestSignCARequests(t *testing.T) {
	t.Parallel()

	tca := newTestCA(t, time.Now().Add(365*24*time.Hour))

	// The policy is checked before anything touches Azure, so the refusal is
	// the same even when the issuer's credential is broken: the request fails
	// at once rather than waiting for the issuer to be fixed.
	t.Run("refused by default", func(t *testing.T) {
		t.Parallel()

		creds := &fakeCreds{err: errBadAuth}
		fetcher := &fakeFetcher{ca: tca.keyvaultCA(t, nil)}

		_, err := New(creds, fetcher, Options{}).Sign(t.Context(), newRequest(t, requestSpec{isCA: true}), newClusterIssuer("uid", 1))

		var cond signer.SetCertificateRequestConditionError
		if !errors.As(err, &cond) {
			t.Fatalf("Sign() error = %v, want a condition error", err)
		}

		if cond.ConditionType != cmapi.CertificateRequestConditionInvalidRequest || cond.Reason != reasonCANotAllowed {
			t.Errorf("condition = %s/%s, want InvalidRequest/%s", cond.ConditionType, cond.Reason, reasonCANotAllowed)
		}

		if !errors.As(err, &signer.PermanentError{}) || !errors.Is(err, ErrCANotAllowed) {
			t.Errorf("Sign() error = %v, want a permanent %v", err, ErrCANotAllowed)
		}

		if creds.count() != 0 {
			t.Errorf("credential provider called %d times for a refused request, want 0", creds.count())
		}

		if len(fetcher.sources) != 0 {
			t.Error("the CA was fetched for a refused request")
		}
	})

	t.Run("allowed by policy", func(t *testing.T) {
		t.Parallel()

		ci := newClusterIssuer("uid", 1)
		ci.Spec.Policy.AllowCA = true

		bundle, err := New(&fakeCreds{}, &fakeFetcher{ca: tca.keyvaultCA(t, nil)}, Options{}).
			Sign(t.Context(), newRequest(t, requestSpec{isCA: true}), ci)
		if err != nil {
			t.Fatalf("Sign() error = %v", err)
		}

		if leaf := parseBundle(t, bundle)[0]; !leaf.IsCA {
			t.Error("issued certificate is not a CA")
		}
	})
}

// TestSignCAPathLen checks that an allowed CA request is held to the issuing
// CA's path length constraint. Request rules are TestApplyPathLen's job; this
// checks how Sign applies them.
func TestSignCAPathLen(t *testing.T) {
	t.Parallel()

	allowCA := func() *v1alpha1.AzureKeyVaultClusterIssuer {
		ci := newClusterIssuer("uid", 1)
		ci.Spec.Policy.AllowCA = true

		return ci
	}

	t.Run("refused by a CA with path length 0", func(t *testing.T) {
		t.Parallel()

		fetcher := &fakeFetcher{ca: newTestCAWithPathLen(t, 0).keyvaultCA(t, nil)}

		_, err := New(&fakeCreds{}, fetcher, Options{}).Sign(t.Context(), newRequest(t, requestSpec{isCA: true}), allowCA())

		var cond signer.SetCertificateRequestConditionError
		if !errors.As(err, &cond) {
			t.Fatalf("Sign() error = %v, want a condition error", err)
		}

		if cond.ConditionType != cmapi.CertificateRequestConditionInvalidRequest || cond.Reason != reasonPathLenExceeded {
			t.Errorf("condition = %s/%s, want InvalidRequest/%s", cond.ConditionType, cond.Reason, reasonPathLenExceeded)
		}

		if !errors.As(err, &signer.PermanentError{}) || !errors.Is(err, ErrPathLenExceeded) {
			t.Errorf("Sign() error = %v, want a permanent %v", err, ErrPathLenExceeded)
		}
	})

	// A CertificateRequest from a Certificate asks for no limit, so it gets
	// the most the CA allows.
	t.Run("no limit requested from a CA with path length 2", func(t *testing.T) {
		t.Parallel()

		fetcher := &fakeFetcher{ca: newTestCAWithPathLen(t, 2).keyvaultCA(t, nil)}

		bundle, err := New(&fakeCreds{}, fetcher, Options{}).Sign(t.Context(), newRequest(t, requestSpec{isCA: true}), allowCA())
		if err != nil {
			t.Fatalf("Sign() error = %v", err)
		}

		leaf := parseBundle(t, bundle)[0]
		if !leaf.IsCA || leaf.MaxPathLen != 1 {
			t.Errorf("issued IsCA %t with MaxPathLen %d, want a CA with 1", leaf.IsCA, leaf.MaxPathLen)
		}
	})
}

// TestSignClampsToChainExpiry checks that a lifetime is clamped to the
// earliest expiry in the chain, here an intermediate that expires before the
// Key Vault CA, so no certificate outlives one it is served with.
func TestSignClampsToChainExpiry(t *testing.T) {
	t.Parallel()

	intNotAfter := time.Now().Add(10 * 24 * time.Hour).Truncate(time.Second)

	rootKey, intKey, caKey := newKey(t), newKey(t), newKey(t)
	root := newCACert(t, "Test Root", rootKey.Public(), nil, rootKey, time.Now().Add(10*365*24*time.Hour))
	intermediate := newCACert(t, "Test Intermediate", intKey.Public(), root, rootKey, intNotAfter)
	ca := newCACert(t, "Test Issuing CA", caKey.Public(), intermediate, intKey, time.Now().Add(365*24*time.Hour))
	tca := testCA{root: root, ca: ca, intermediates: []*x509.Certificate{intermediate}, key: caKey}

	events := &fakeEvents{}
	iss := New(&fakeCreds{}, &fakeFetcher{ca: tca.keyvaultCA(t, nil)}, Options{Events: events})

	bundle, err := iss.Sign(t.Context(), newRequest(t, requestSpec{}), newClusterIssuer("uid", 1))
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	if leaf := parseBundle(t, bundle)[0]; !leaf.NotAfter.Equal(intNotAfter) {
		t.Errorf("NotAfter = %s, want the intermediate's %s", leaf.NotAfter, intNotAfter)
	}

	var clamped bool
	for _, e := range events.events {
		clamped = clamped || e.reason == reasonDurationClamped
	}

	if !clamped {
		t.Errorf("events = %v, want a %s event", events.events, reasonDurationClamped)
	}
}

// TestSignKubernetesRequests checks that a Kubernetes CertificateSigningRequest
// is signed under the same policy as a CertificateRequest: its duration comes
// from cert-manager's annotation or spec.expirationSeconds, a clamp is
// recorded on the CertificateSigningRequest itself, and a CA request is
// refused.
func TestSignKubernetesRequests(t *testing.T) {
	t.Parallel()

	tca := newTestCA(t, time.Now().Add(365*24*time.Hour))

	tests := []struct {
		name         string
		spec         requestSpec
		wantLifetime time.Duration
		wantClamped  bool
	}{
		{"default duration", requestSpec{}, 2160 * time.Hour, false},
		{"duration annotation", requestSpec{duration: 48 * time.Hour}, 48 * time.Hour, false},
		{"expirationSeconds", requestSpec{expirationSeconds: 3600}, time.Hour, false},
		{"over maxDuration", requestSpec{duration: 365 * 24 * time.Hour}, 2160 * time.Hour, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			events := &fakeEvents{}
			iss := New(&fakeCreds{}, &fakeFetcher{ca: tca.keyvaultCA(t, nil)}, Options{Events: events})

			ci := newClusterIssuer("uid", 1)
			ci.Spec.Policy.MaxDuration = nil

			tt.spec.kubernetes = true

			bundle, err := iss.Sign(t.Context(), newRequest(t, tt.spec), ci)
			if err != nil {
				t.Fatalf("Sign() error = %v", err)
			}

			chain := parseBundle(t, bundle)
			if got := chain[0].NotAfter.Sub(chain[0].NotBefore); got != tt.wantLifetime {
				t.Errorf("lifetime = %s, want %s", got, tt.wantLifetime)
			}

			if err := chain[0].CheckSignatureFrom(tca.ca); err != nil {
				t.Errorf("certificate not signed by the CA: %v", err)
			}

			if !tt.wantClamped {
				if len(events.events) != 0 {
					t.Errorf("events = %v, want none", events.events)
				}

				return
			}

			if len(events.events) != 1 {
				t.Fatalf("got %d events, want 1", len(events.events))
			}

			csr, ok := events.events[0].regarding.(*certificatesv1.CertificateSigningRequest)
			if !ok || csr.Name != "app" || csr.Namespace != "" || csr.UID != "csr-uid" ||
				csr.Kind != "CertificateSigningRequest" || csr.APIVersion != "certificates.k8s.io/v1" {
				t.Errorf("event regards %#v, want CertificateSigningRequest app", events.events[0].regarding)
			}
		})
	}

	t.Run("CA request refused", func(t *testing.T) {
		t.Parallel()

		_, err := New(&fakeCreds{}, &fakeFetcher{ca: tca.keyvaultCA(t, nil)}, Options{}).
			Sign(t.Context(), newRequest(t, requestSpec{kubernetes: true, isCA: true}), newClusterIssuer("uid", 1))

		if !errors.As(err, &signer.PermanentError{}) || !errors.Is(err, ErrCANotAllowed) {
			t.Errorf("Sign() error = %v, want a permanent %v", err, ErrCANotAllowed)
		}
	})
}

func TestSignErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		request       requestSpec
		spec          func(*v1alpha1.AzureKeyVaultIssuerSpec)
		credErr       error
		fetchErr      error
		signErr       error
		wantPermanent bool
		wantIssuer    bool
		wantContains  []string // substrings an operator needs in the condition
	}{
		{name: "invalid CSR", request: requestSpec{badCSR: true}, wantPermanent: true},
		{name: "invalid spec", spec: func(s *v1alpha1.AzureKeyVaultIssuerSpec) { s.CertificateName = "a/b" }, wantIssuer: true},
		{name: "credential error", credErr: errNotAllowed, wantIssuer: true},
		// Which errors are transient is TestTransient's job. These rows check
		// that Sign retries a transient error and turns the rest into issuer
		// errors, for a fetch and for the signature itself (whose Azure status
		// code errorKeepingSigner must keep).
		{name: "fetch throttled", fetchErr: responseError(t, http.StatusTooManyRequests)},
		{name: "fetch forbidden", fetchErr: responseError(t, http.StatusForbidden), wantIssuer: true},
		{name: "CA disabled", fetchErr: keyvault.ErrCADisabled, wantIssuer: true},
		{name: "sign throttled", signErr: responseError(t, http.StatusTooManyRequests)},
		{
			name:         "sign forbidden",
			signErr:      responseError(t, http.StatusForbidden),
			wantIssuer:   true,
			wantContains: []string{"test-ca/issuing-ca@current", "HTTP 403"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var wrap func(crypto.Signer) crypto.Signer
			if tt.signErr != nil {
				wrap = func(k crypto.Signer) crypto.Signer { return failingSigner{Signer: k, err: tt.signErr} }
			}

			fetcher := &fakeFetcher{ca: newTestCA(t, time.Now().Add(365*24*time.Hour)).keyvaultCA(t, wrap), err: tt.fetchErr}
			creds := &fakeCreds{err: tt.credErr}
			iss := New(creds, fetcher, Options{})

			ci := newClusterIssuer("uid", 1)
			if tt.spec != nil {
				tt.spec(&ci.Spec)
			}

			_, err := iss.Sign(t.Context(), newRequest(t, tt.request), ci)
			if err == nil {
				t.Fatal("Sign() error = nil, want an error")
			}

			if got := errors.As(err, &signer.PermanentError{}); got != tt.wantPermanent {
				t.Errorf("Sign() error %q permanent = %t, want %t", err, got, tt.wantPermanent)
			}

			if got := errors.As(err, &signer.IssuerError{}); got != tt.wantIssuer {
				t.Errorf("Sign() error %q issuer error = %t, want %t", err, got, tt.wantIssuer)
			}

			for _, want := range tt.wantContains {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("Sign() error %q does not contain %q", err, want)
				}
			}

			if strings.Contains(err.Error(), "\n") {
				t.Errorf("Sign() error text spans lines: %q", err.Error())
			}

			// Once a credential has been asked for, an issuer error drops it,
			// so the next attempt builds a new one; a transient error keeps it.
			before := creds.count()
			if before == 0 {
				return
			}

			_, _ = iss.Sign(t.Context(), newRequest(t, tt.request), ci)

			if rebuilt := creds.count() > before; rebuilt != tt.wantIssuer {
				t.Errorf("credential rebuilt on the next Sign = %t, want %t", rebuilt, tt.wantIssuer)
			}
		})
	}
}

func TestSignCachesCredential(t *testing.T) {
	t.Parallel()

	creds := &fakeCreds{}
	iss := New(creds, &fakeFetcher{ca: newTestCA(t, time.Now().Add(365*24*time.Hour)).keyvaultCA(t, nil)}, Options{})

	sign := func(generation int64) {
		t.Helper()

		if _, err := iss.Sign(t.Context(), newRequest(t, requestSpec{}), newClusterIssuer("uid", generation)); err != nil {
			t.Fatalf("Sign() error = %v", err)
		}
	}

	sign(1)
	sign(1)

	if creds.count() != 1 {
		t.Errorf("after two signatures, credential provider called %d times, want 1", creds.count())
	}

	sign(2)

	if creds.count() != 2 {
		t.Errorf("after a spec change, credential provider called %d times, want 2", creds.count())
	}

	iss.Forget(newClusterIssuer("uid", 2))

	sign(2)

	if creds.count() != 3 {
		t.Errorf("after Forget, credential provider called %d times, want 3", creds.count())
	}
}

func TestSignRefusesVaultOutsideAllowList(t *testing.T) {
	t.Parallel()

	other, err := keyvault.ParseVaultURL("https://other-ca.vault.azure.net/")
	if err != nil {
		t.Fatal(err)
	}

	fetcher := &fakeFetcher{ca: newTestCA(t, time.Now().Add(365*24*time.Hour)).keyvaultCA(t, nil)}
	iss := New(&fakeCreds{}, fetcher, Options{AllowedVaults: []keyvault.VaultURL{other}})

	_, err = iss.Sign(t.Context(), newRequest(t, requestSpec{}), newNamespacedIssuer("uid", 1))
	if !errors.Is(err, ErrVaultNotAllowed) || !errors.As(err, &signer.IssuerError{}) {
		t.Errorf("Sign() error = %v, want an issuer error wrapping %v", err, ErrVaultNotAllowed)
	}

	if len(fetcher.sources) != 0 {
		t.Errorf("fetched %v from a vault outside the allow-list", fetcher.sources)
	}
}
