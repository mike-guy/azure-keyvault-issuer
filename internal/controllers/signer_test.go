package controllers

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	issuerapi "github.com/cert-manager/issuer-lib/api/v1alpha1"
	"github.com/cert-manager/issuer-lib/controllers/signer"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	api "github.com/mike-guy/azure-keyvault-issuer/api/v1alpha1"
	"github.com/mike-guy/azure-keyvault-issuer/internal/azure/credential"
	"github.com/mike-guy/azure-keyvault-issuer/internal/azure/vault"
	"github.com/mike-guy/azure-keyvault-issuer/internal/pki"
)

func TestNewKeyVaultSigner(t *testing.T) {
	t.Parallel()

	factory := (&fakeFactory{authority: nil, err: nil, calls: 0, cfg: vault.Config{}, cred: nil}).build

	// with returns the default options after change.
	with := func(change func(*SignerOptions)) SignerOptions {
		o := defaultSignerOptions()
		change(&o)

		return o
	}

	tests := []struct {
		name      string
		creds     credentialBuilder
		factory   authorityFactory
		events    eventRecorder
		namespace string
		options   SignerOptions
		wantMsg   string
	}{
		{name: "valid", creds: &fakeCredentials{}, factory: factory, events: &fakeEvents{}, namespace: "cert-manager", options: defaultSignerOptions(), wantMsg: ""},
		{name: "every option set", creds: &fakeCredentials{}, factory: factory, events: &fakeEvents{}, namespace: "cert-manager", options: SignerOptions{ReconcileTimeout: time.Minute, CAExpiryWarnThreshold: 720 * time.Hour, WarnOnExportableCAKey: !DefaultWarnOnExportableCAKey}, wantMsg: ""},
		{name: "no credential builder", creds: nil, factory: factory, events: &fakeEvents{}, namespace: "cert-manager", options: defaultSignerOptions(), wantMsg: "credential builder"},
		{name: "no authority factory", creds: &fakeCredentials{}, factory: nil, events: &fakeEvents{}, namespace: "cert-manager", options: defaultSignerOptions(), wantMsg: "authority factory"},
		{name: "no event recorder", creds: &fakeCredentials{}, factory: factory, events: nil, namespace: "cert-manager", options: defaultSignerOptions(), wantMsg: "event recorder"},
		{name: "no namespace", creds: &fakeCredentials{}, factory: factory, events: &fakeEvents{}, namespace: "", options: defaultSignerOptions(), wantMsg: "namespace"},
		{name: "a zero timeout", creds: &fakeCredentials{}, factory: factory, events: &fakeEvents{}, namespace: "cert-manager", options: with(func(o *SignerOptions) { o.ReconcileTimeout = 0 }), wantMsg: "reconcile timeout must be positive"},
		{name: "a negative timeout", creds: &fakeCredentials{}, factory: factory, events: &fakeEvents{}, namespace: "cert-manager", options: with(func(o *SignerOptions) { o.ReconcileTimeout = -time.Second }), wantMsg: "reconcile timeout must be positive"},
		{name: "a zero warning threshold", creds: &fakeCredentials{}, factory: factory, events: &fakeEvents{}, namespace: "cert-manager", options: with(func(o *SignerOptions) { o.CAExpiryWarnThreshold = 0 }), wantMsg: "CA expiry warning threshold must be positive"},
		{name: "a negative warning threshold", creds: &fakeCredentials{}, factory: factory, events: &fakeEvents{}, namespace: "cert-manager", options: with(func(o *SignerOptions) { o.CAExpiryWarnThreshold = -time.Hour }), wantMsg: "CA expiry warning threshold must be positive"},
		{name: "the zero options", creds: &fakeCredentials{}, factory: factory, events: &fakeEvents{}, namespace: "cert-manager", options: SignerOptions{}, wantMsg: "reconcile timeout must be positive"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := NewKeyVaultSigner(tt.creds, tt.factory, tt.events, tt.namespace, tt.options)

			if tt.wantMsg == "" {
				if err != nil {
					t.Fatalf("NewKeyVaultSigner() error = %v, want nil", err)
				}

				if got == nil || got.clusterResourceNamespace != tt.namespace || got.options != tt.options {
					t.Errorf("NewKeyVaultSigner() = %+v, want a signer for namespace %q with options %+v", got, tt.namespace, tt.options)
				}

				return
			}

			if err == nil || !strings.Contains(err.Error(), tt.wantMsg) {
				t.Errorf("NewKeyVaultSigner() error = %v, want it to contain %q", err, tt.wantMsg)
			}

			if got != nil {
				t.Errorf("NewKeyVaultSigner() = %+v, want nil", got)
			}
		})
	}
}

func TestNewVaultAuthorityFactory(t *testing.T) {
	t.Parallel()

	factory := NewVaultAuthorityFactory(nil)
	if factory == nil {
		t.Fatal("NewVaultAuthorityFactory() = nil, want a factory")
	}

	// An empty config is refused before any request is made. The result must
	// be a nil interface, not an interface holding a nil pointer, which a
	// caller's nil check would let through.
	got, err := factory(t.Context(), vault.Config{VaultURL: "", CertificateName: "", CertificateVersion: "", ChainInSecret: false}, stubTokenCredential{})
	if !errors.Is(err, vault.ErrInvalidConfig) {
		t.Fatalf("factory() error = %v, want %v", err, vault.ErrInvalidConfig)
	}

	if got != nil {
		t.Errorf("factory() = %#v, want a nil interface", got)
	}
}

func TestCheck(t *testing.T) {
	t.Parallel()

	ambient := clusterIssuer(nil, nil)

	badPolicy := clusterIssuer(nil, nil)
	badPolicy.Spec.Policy.AllowedExtKeyUsages = []string{"not a usage"}

	tests := []struct {
		name string
		// issuer is what Check is given.
		issuer       issuerapi.Issuer
		credErr      error
		factoryErr   error
		nilAuthority bool

		wantPermanent bool
		wantIs        error
		wantMsg       string
		wantCreds     int
		wantFactory   int
	}{
		{name: "a namespaced issuer", issuer: namespacedIssuer("team-a"), credErr: nil, factoryErr: nil, nilAuthority: false, wantPermanent: false, wantIs: nil, wantMsg: "", wantCreds: 1, wantFactory: 1},
		{name: "a cluster issuer using the ambient identity", issuer: ambient, credErr: nil, factoryErr: nil, nilAuthority: false, wantPermanent: false, wantIs: nil, wantMsg: "", wantCreds: 1, wantFactory: 1},
		{
			name: "an unsupported issuer", issuer: unsupportedIssuer{Issuer: nil}, credErr: nil, factoryErr: nil, nilAuthority: false,
			wantPermanent: false, wantIs: nil, wantMsg: "unsupported type", wantCreds: 0, wantFactory: 0,
		},
		{
			name: "an invalid allowed namespace", issuer: clusterIssuer(nil, []string{"Bad_Name"}), credErr: nil, factoryErr: nil, nilAuthority: false,
			wantPermanent: true, wantIs: ErrInvalidConfig, wantMsg: "allowedNamespaces[0]", wantCreds: 0, wantFactory: 0,
		},
		{
			name: "an invalid policy is reported before any credential error", issuer: badPolicy, credErr: credential.ErrSecretNotFound, factoryErr: nil, nilAuthority: false,
			wantPermanent: true, wantIs: ErrInvalidConfig, wantMsg: "allowedExtKeyUsages[0]", wantCreds: 0, wantFactory: 0,
		},
		{
			name: "a credential error is retried with backoff", issuer: ambient, credErr: credential.ErrSecretNotFound, factoryErr: nil, nilAuthority: false,
			wantPermanent: false, wantIs: credential.ErrSecretNotFound, wantMsg: "building credential", wantCreds: 1, wantFactory: 0,
		},
		{
			name: "a permanent vault error", issuer: ambient, credErr: nil, factoryErr: vault.ErrInvalidConfig, nilAuthority: false,
			wantPermanent: true, wantIs: vault.ErrInvalidConfig, wantMsg: "loading CA from Key Vault", wantCreds: 1, wantFactory: 1,
		},
		{
			name: "a vault error that is retried", issuer: ambient, credErr: nil, factoryErr: vault.ErrAccessDenied, nilAuthority: false,
			wantPermanent: false, wantIs: vault.ErrAccessDenied, wantMsg: "loading CA from Key Vault", wantCreds: 1, wantFactory: 1,
		},
		{
			name: "an unclassified vault error", issuer: ambient, credErr: nil, factoryErr: errUnclassified, nilAuthority: false,
			wantPermanent: false, wantIs: errUnclassified, wantMsg: "loading CA from Key Vault", wantCreds: 1, wantFactory: 1,
		},
		{
			name: "an authority that cannot make a signer", issuer: ambient, credErr: nil, factoryErr: nil, nilAuthority: true,
			wantPermanent: false, wantIs: nil, wantMsg: "creating signer", wantCreds: 1, wantFactory: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			authority, _ := newFakeAuthority(t)

			var factoryAuthority pki.Authority = authority
			if tt.nilAuthority {
				factoryAuthority = nil
			}

			creds := &fakeCredentials{err: tt.credErr, calls: 0, issuerType: "", auth: nil, namespace: ""}
			factory := &fakeFactory{authority: factoryAuthority, err: tt.factoryErr, calls: 0, cfg: vault.Config{}, cred: nil}

			err := newSignerUnderTest(t, creds, factory.build).Check(t.Context(), tt.issuer)

			if tt.wantMsg == "" {
				if err != nil {
					t.Fatalf("Check() error = %v, want nil", err)
				}
			} else {
				if err == nil {
					t.Fatal("Check() error = nil, want an error")
				}

				if !strings.Contains(err.Error(), tt.wantMsg) {
					t.Errorf("Check() error = %q, want it to contain %q", err, tt.wantMsg)
				}
			}

			var permanent signer.PermanentError
			if got := errors.As(err, &permanent); got != tt.wantPermanent {
				t.Errorf("Check() error is a PermanentError = %t, want %t", got, tt.wantPermanent)
			}

			if tt.wantIs != nil && !errors.Is(err, tt.wantIs) {
				t.Errorf("Check() error = %v, want it to wrap %v", err, tt.wantIs)
			}

			if creds.calls != tt.wantCreds {
				t.Errorf("credential builder calls = %d, want %d", creds.calls, tt.wantCreds)
			}

			if factory.calls != tt.wantFactory {
				t.Errorf("authority factory calls = %d, want %d", factory.calls, tt.wantFactory)
			}
		})
	}
}

// TestBuildArguments checks what build hands to the credential builder and the
// authority factory for each issuer kind.
func TestBuildArguments(t *testing.T) {
	t.Parallel()

	explicitAuth := &api.Auth{WorkloadIdentity: nil, ClientCertificate: nil, ClientSecret: nil}

	tests := []struct {
		name          string
		issuer        issuerapi.Issuer
		wantType      credential.IssuerType
		wantAuth      *api.Auth
		wantNamespace string
	}{
		{name: "a namespaced issuer", issuer: namespacedIssuer("team-a"), wantType: credential.NamespacedIssuer, wantAuth: nil, wantNamespace: "team-a"},
		{name: "a cluster issuer with auth", issuer: clusterIssuer(explicitAuth, nil), wantType: credential.ClusterIssuer, wantAuth: explicitAuth, wantNamespace: "cert-manager"},
		{name: "a cluster issuer without auth", issuer: clusterIssuer(nil, nil), wantType: credential.ClusterIssuer, wantAuth: nil, wantNamespace: "cert-manager"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			authority, _ := newFakeAuthority(t)
			creds := &fakeCredentials{err: nil, calls: 0, issuerType: "", auth: nil, namespace: ""}
			factory := &fakeFactory{authority: authority, err: nil, calls: 0, cfg: vault.Config{}, cred: nil}

			if err := newSignerUnderTest(t, creds, factory.build).Check(t.Context(), tt.issuer); err != nil {
				t.Fatalf("Check() error = %v, want nil", err)
			}

			if creds.issuerType != tt.wantType {
				t.Errorf("issuer type = %q, want %q", creds.issuerType, tt.wantType)
			}

			if creds.namespace != tt.wantNamespace {
				t.Errorf("secret namespace = %q, want %q", creds.namespace, tt.wantNamespace)
			}

			// A namespaced issuer's auth is its own, so only check the
			// cluster issuer's, which is passed through, nil or not.
			if tt.wantAuth != nil || tt.wantType == credential.ClusterIssuer {
				if creds.auth != tt.wantAuth {
					t.Errorf("auth = %p, want %p", creds.auth, tt.wantAuth)
				}
			}

			wantCfg := vault.Config{
				VaultURL:           "https://my-ca.vault.azure.net/",
				CertificateName:    "ca",
				CertificateVersion: "v1",
				ChainInSecret:      true,
			}
			if factory.cfg != wantCfg {
				t.Errorf("vault config = %+v, want %+v", factory.cfg, wantCfg)
			}

			if _, ok := factory.cred.(stubTokenCredential); !ok {
				t.Errorf("factory credential = %T, want the one the credential builder returned", factory.cred)
			}
		})
	}
}

func TestSign(t *testing.T) {
	t.Parallel()

	allowed := []string{"team-a"}

	badPolicy := namespacedIssuer("team-a")
	badPolicy.Spec.Policy.AllowedExtKeyUsages = []string{"not a usage"}

	tests := []struct {
		name string
		// issuer is what Sign is given, and namespace is where the request
		// comes from.
		issuer     issuerapi.Issuer
		namespace  string
		detailsErr error
		credErr    error
		factoryErr error
		badCSR     bool

		wantPermanent bool
		wantIssuerErr bool
		wantPending   bool
		wantIs        error
		wantMsg       string
		wantCreds     int
	}{
		{
			name: "a namespaced issuer", issuer: namespacedIssuer("team-a"), namespace: "team-a",
			wantPermanent: false, wantIssuerErr: false, wantPending: false, wantIs: nil, wantMsg: "", wantCreds: 1,
		},
		{
			name: "a cluster issuer for an allowed namespace", issuer: clusterIssuer(nil, allowed), namespace: "team-a",
			wantPermanent: false, wantIssuerErr: false, wantPending: false, wantIs: nil, wantMsg: "", wantCreds: 1,
		},
		{
			name: "an unsupported issuer", issuer: unsupportedIssuer{Issuer: nil}, namespace: "team-a",
			wantPermanent: false, wantIssuerErr: false, wantPending: false, wantIs: nil, wantMsg: "unsupported type", wantCreds: 0,
		},
		{
			name: "a namespace that is not allowed", issuer: clusterIssuer(nil, allowed), namespace: "team-b",
			wantPermanent: true, wantIssuerErr: false, wantPending: false, wantIs: ErrNamespaceNotAllowed, wantMsg: "team-b", wantCreds: 0,
		},
		{
			name: "a request that cannot be read", issuer: namespacedIssuer("team-a"), namespace: "team-a", detailsErr: errors.New("unknown usage"),
			wantPermanent: true, wantIssuerErr: false, wantPending: false, wantIs: nil, wantMsg: "reading certificate details", wantCreds: 0,
		},
		{
			name: "an invalid policy is reported before any credential error", issuer: badPolicy, namespace: "team-a", credErr: credential.ErrSecretNotFound,
			wantPermanent: true, wantIssuerErr: true, wantPending: false, wantIs: ErrInvalidConfig, wantMsg: "allowedExtKeyUsages[0]", wantCreds: 0,
		},
		{
			name: "a credential error the issuer's owner must fix", issuer: namespacedIssuer("team-a"), namespace: "team-a", credErr: credential.ErrSecretNotFound,
			wantPermanent: false, wantIssuerErr: true, wantPending: false, wantIs: credential.ErrSecretNotFound, wantMsg: "building credential", wantCreds: 1,
		},
		{
			name: "an issuer spec that is wrong", issuer: namespacedIssuer("team-a"), namespace: "team-a", factoryErr: vault.ErrInvalidConfig,
			wantPermanent: true, wantIssuerErr: true, wantPending: false, wantIs: vault.ErrInvalidConfig, wantMsg: "loading CA from Key Vault", wantCreds: 1,
		},
		{
			name: "a vault error that is not classified", issuer: namespacedIssuer("team-a"), namespace: "team-a", factoryErr: errUnclassified,
			wantPermanent: false, wantIssuerErr: false, wantPending: false, wantIs: errUnclassified, wantMsg: "loading CA from Key Vault", wantCreds: 1,
		},
		{
			name: "a CSR that cannot be parsed", issuer: namespacedIssuer("team-a"), namespace: "team-a", badCSR: true,
			wantPermanent: true, wantIssuerErr: false, wantPending: false, wantIs: pki.ErrInvalidRequest, wantMsg: "signing certificate request", wantCreds: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			authority, root := newFakeAuthority(t)
			creds := &fakeCredentials{err: tt.credErr, calls: 0, issuerType: "", auth: nil, namespace: ""}
			factory := &fakeFactory{authority: authority, err: tt.factoryErr, calls: 0, cfg: vault.Config{}, cred: nil}

			request := newTestRequest(t, tt.namespace, time.Hour)
			request.detailsErr = tt.detailsErr

			if tt.badCSR {
				request.details.CSR = []byte("not a csr")
			}

			bundle, err := newSignerUnderTest(t, creds, factory.build).Sign(t.Context(), request, tt.issuer)

			var (
				permanent signer.PermanentError
				issuerErr signer.IssuerError
				pending   signer.PendingError
			)

			if got := errors.As(err, &permanent); got != tt.wantPermanent {
				t.Errorf("Sign() error is a PermanentError = %t, want %t (error: %v)", got, tt.wantPermanent, err)
			}

			if got := errors.As(err, &issuerErr); got != tt.wantIssuerErr {
				t.Errorf("Sign() error is an IssuerError = %t, want %t (error: %v)", got, tt.wantIssuerErr, err)
			}

			if got := errors.As(err, &pending); got != tt.wantPending {
				t.Errorf("Sign() error is a PendingError = %t, want %t (error: %v)", got, tt.wantPending, err)
			}

			if tt.wantIs != nil && !errors.Is(err, tt.wantIs) {
				t.Errorf("Sign() error = %v, want it to wrap %v", err, tt.wantIs)
			}

			if creds.calls != tt.wantCreds {
				t.Errorf("credential builder calls = %d, want %d", creds.calls, tt.wantCreds)
			}

			if tt.wantMsg != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantMsg) {
					t.Fatalf("Sign() error = %v, want it to contain %q", err, tt.wantMsg)
				}

				if len(bundle.ChainPEM) != 0 || len(bundle.CAPEM) != 0 {
					t.Errorf("Sign() bundle = %+v, want it empty on error", bundle)
				}

				return
			}

			if err != nil {
				t.Fatalf("Sign() error = %v, want nil", err)
			}

			checkSignedBundle(t, bundle, root, authority.cert)
		})
	}
}

// TestSignCAExpiryEvents checks that a certificate cut short by the expiry of
// the CA chain, and a CA chain that expires within the warning threshold, are
// each announced on the issuer, and that nothing else is. The test CA chain
// expires in an hour.
func TestSignCAExpiryEvents(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		duration  time.Duration
		threshold time.Duration
		badCSR    bool

		wantReasons []string
	}{
		{name: "a lifetime within the CA chain, outside the threshold", duration: 10 * time.Minute, threshold: 30 * time.Minute, badCSR: false, wantReasons: nil},
		{name: "a lifetime within the CA chain, inside the threshold", duration: 10 * time.Minute, threshold: 2 * time.Hour, badCSR: false, wantReasons: []string{eventReasonCAExpiring}},
		{name: "a lifetime past the CA chain, inside the threshold", duration: 24 * time.Hour, threshold: 2 * time.Hour, badCSR: false, wantReasons: []string{eventReasonCertificateClamped, eventReasonCAExpiring}},
		{name: "a lifetime past the CA chain, outside the threshold", duration: 24 * time.Hour, threshold: 30 * time.Minute, badCSR: false, wantReasons: []string{eventReasonCertificateClamped}},
		{name: "a request that fails", duration: 24 * time.Hour, threshold: 2 * time.Hour, badCSR: true, wantReasons: nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			authority, root := newFakeAuthority(t)
			creds := &fakeCredentials{err: nil, calls: 0, issuerType: "", auth: nil, namespace: ""}
			factory := &fakeFactory{authority: authority, err: nil, calls: 0, cfg: vault.Config{}, cred: nil}
			s, events := newSignerWithEvents(t, creds, factory.build)
			s.options.CAExpiryWarnThreshold = tt.threshold

			issuer := namespacedIssuer("team-a")

			request := newTestRequest(t, "team-a", tt.duration)
			if tt.badCSR {
				request.details.CSR = []byte("not a csr")
			}

			// Sign twice, as a busy issuer does, to see that the events are
			// the same and so fold into one.
			for range 2 {
				_, err := s.Sign(t.Context(), request, issuer)
				if tt.badCSR != (err != nil) {
					t.Fatalf("Sign() error = %v, want an error = %t", err, tt.badCSR)
				}
			}

			perSign := len(tt.wantReasons)
			if len(events.events) != perSign*2 {
				t.Fatalf("recorded %d events, want %d: %+v", len(events.events), perSign*2, events.events)
			}

			caExpiry := authority.cert.NotAfter
			if root.cert.NotAfter.Before(caExpiry) {
				caExpiry = root.cert.NotAfter
			}

			for i, got := range events.events {
				wantReason := tt.wantReasons[i%perSign]

				if got.regarding != any(issuer) {
					t.Errorf("event %d is about %v, want the issuer", i, got.regarding)
				}

				if got.eventType != corev1.EventTypeWarning || got.reason != wantReason || got.action != eventActionSigning {
					t.Errorf("event %d = %s %s %s, want Warning %s %s", i, got.eventType, got.reason, got.action, wantReason, eventActionSigning)
				}

				if want := caExpiry.UTC().Format(time.RFC3339); !strings.Contains(got.note, want) {
					t.Errorf("event %d note = %q, want it to contain the CA's expiry %q", i, got.note, want)
				}

				if wantReason == eventReasonCAExpiring && !strings.Contains(got.note, tt.threshold.String()) {
					t.Errorf("event %d note = %q, want it to contain the threshold %q", i, got.note, tt.threshold)
				}
			}

			// The second signing must say the same as the first, so that the
			// events fold into one.
			for i := range perSign {
				if events.events[i].note != events.events[i+perSign].note {
					t.Errorf("%s notes differ, so they would not fold into one: %q, %q",
						tt.wantReasons[i], events.events[i].note, events.events[i+perSign].note)
				}
			}
		})
	}
}

// TestCheckCAKeyExportableEvent checks that an exportable CA key is announced on
// the issuer when the warning is on, and only then.
func TestCheckCAKeyExportableEvent(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		exportable bool
		warn       bool
		plain      bool

		wantEvents int
	}{
		{name: "an exportable key, warning on", exportable: true, warn: true, plain: false, wantEvents: 1},
		{name: "an exportable key, warning off", exportable: true, warn: false, plain: false, wantEvents: 0},
		{name: "a non-exportable key, warning on", exportable: false, warn: true, plain: false, wantEvents: 0},
		{name: "an authority that cannot tell, warning on", exportable: false, warn: true, plain: true, wantEvents: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			fake, _ := newFakeAuthority(t)

			var authority pki.Authority = &exportableAuthority{fakeAuthority: fake, exportable: tt.exportable}
			if tt.plain {
				authority = fake
			}

			creds := &fakeCredentials{err: nil, calls: 0, issuerType: "", auth: nil, namespace: ""}
			factory := &fakeFactory{authority: authority, err: nil, calls: 0, cfg: vault.Config{}, cred: nil}
			s, events := newSignerWithEvents(t, creds, factory.build)
			s.options.WarnOnExportableCAKey = tt.warn

			issuer := namespacedIssuer("team-a")

			// Check twice, as the issuer reconciler does, to see that the events
			// are the same and so fold into one.
			for range 2 {
				if err := s.Check(t.Context(), issuer); err != nil {
					t.Fatalf("Check() error = %v, want nil", err)
				}
			}

			if len(events.events) != tt.wantEvents*2 {
				t.Fatalf("recorded %d events, want %d: %+v", len(events.events), tt.wantEvents*2, events.events)
			}

			if tt.wantEvents == 0 {
				return
			}

			for _, got := range events.events {
				if got.regarding != any(issuer) {
					t.Errorf("event is about %v, want the issuer", got.regarding)
				}

				if got.eventType != corev1.EventTypeWarning || got.reason != eventReasonCAKeyExportable || got.action != eventActionChecking {
					t.Errorf("event = %s %s %s, want Warning %s %s", got.eventType, got.reason, got.action, eventReasonCAKeyExportable, eventActionChecking)
				}
			}

			if events.events[0].note != events.events[1].note {
				t.Errorf("event notes differ, so they would not fold into one: %q, %q", events.events[0].note, events.events[1].note)
			}
		})
	}
}

// checkSignedBundle checks that bundle holds a leaf for app.example.com that
// the issuing CA signed, followed by that CA, with the root as the CA.
func checkSignedBundle(t *testing.T, bundle signer.PEMBundle, root testCert, issuing *x509.Certificate) {
	t.Helper()

	if string(bundle.CAPEM) != string(root.pem) {
		t.Errorf("Sign() CAPEM = %q, want the root", bundle.CAPEM)
	}

	block, rest := pem.Decode(bundle.ChainPEM)
	if block == nil {
		t.Fatalf("Sign() ChainPEM = %q, want a leaf first", bundle.ChainPEM)
	}

	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parsing leaf: %v", err)
	}

	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "app.example.com" {
		t.Errorf("leaf DNSNames = %v, want [app.example.com]", leaf.DNSNames)
	}

	if err := leaf.CheckSignatureFrom(issuing); err != nil {
		t.Errorf("leaf is not signed by the issuing CA: %v", err)
	}

	block, _ = pem.Decode(rest)
	if block == nil || string(block.Bytes) != string(issuing.Raw) {
		t.Errorf("Sign() ChainPEM does not continue with the issuing CA")
	}
}

// deadlineRecorder is a credentialBuilder and authorityFactory that records
// whether the context it was given has a deadline, and what it is.
type deadlineRecorder struct {
	credentialDeadline time.Time
	credentialHas      bool
	authorityDeadline  time.Time
	authorityHas       bool
	authority          pki.Authority
}

func (d *deadlineRecorder) BuildTokenFetcher(ctx context.Context, _ credential.IssuerType, _ *api.Auth, _ string) (azcore.TokenCredential, error) {
	d.credentialDeadline, d.credentialHas = ctx.Deadline()

	return stubTokenCredential{}, nil
}

func (d *deadlineRecorder) build(ctx context.Context, _ vault.Config, _ azcore.TokenCredential) (pki.Authority, error) {
	d.authorityDeadline, d.authorityHas = ctx.Deadline()

	return d.authority, nil
}

// TestCallsAreBounded checks that Check and Sign put the configured reconcile
// timeout on the context they pass on, both to build the credential, which reads
// a Secret and requests a token, and to load the CA, so a hung API server cannot
// hold a worker for good. The timeout differs from the default, to show that the
// configured one is used.
func TestCallsAreBounded(t *testing.T) {
	t.Parallel()

	const timeout = 90 * time.Second

	tests := []struct {
		name string
		call func(t *testing.T, s *KeyVaultSigner) error
	}{
		{
			name: "check",
			call: func(_ *testing.T, s *KeyVaultSigner) error {
				return s.Check(context.Background(), namespacedIssuer("team-a"))
			},
		},
		{
			name: "sign",
			call: func(t *testing.T, s *KeyVaultSigner) error {
				_, err := s.Sign(context.Background(), newTestRequest(t, "team-a", time.Hour), namespacedIssuer("team-a"))

				return err
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			authority, _ := newFakeAuthority(t)
			recorder := &deadlineRecorder{authority: authority}

			options := defaultSignerOptions()
			options.ReconcileTimeout = timeout

			s, err := NewKeyVaultSigner(recorder, recorder.build, &fakeEvents{events: nil}, "cert-manager", options)
			if err != nil {
				t.Fatalf("NewKeyVaultSigner() error = %v, want nil", err)
			}

			before := time.Now()

			if err := tt.call(t, s); err != nil {
				t.Fatalf("call error = %v, want nil", err)
			}

			for name, got := range map[string]struct {
				has      bool
				deadline time.Time
			}{
				"credential": {has: recorder.credentialHas, deadline: recorder.credentialDeadline},
				"authority":  {has: recorder.authorityHas, deadline: recorder.authorityDeadline},
			} {
				if !got.has {
					t.Errorf("%s context has no deadline, want one within %s", name, timeout)

					continue
				}

				if got.deadline.Before(before.Add(timeout)) || got.deadline.After(time.Now().Add(timeout)) {
					t.Errorf("%s context deadline = %s, want about %s from the call", name, got.deadline, timeout)
				}
			}
		})
	}
}

// TestReconcileTimeoutKeepsAnEarlierDeadline checks that a caller's own shorter
// deadline is not extended.
func TestReconcileTimeoutKeepsAnEarlierDeadline(t *testing.T) {
	t.Parallel()

	authority, _ := newFakeAuthority(t)
	recorder := &deadlineRecorder{authority: authority}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	want, _ := ctx.Deadline()

	if err := newSignerUnderTest(t, recorder, recorder.build).Check(ctx, namespacedIssuer("team-a")); err != nil {
		t.Fatalf("Check() error = %v, want nil", err)
	}

	if !recorder.credentialDeadline.Equal(want) {
		t.Errorf("credential context deadline = %s, want the caller's %s", recorder.credentialDeadline, want)
	}
}

// TestSignClampsToPolicy checks that the issuer's policy reaches the signer: a
// request for longer than policy.maxDuration is clamped, not refused.
func TestSignClampsToPolicy(t *testing.T) {
	t.Parallel()

	authority, _ := newFakeAuthority(t)
	factory := &fakeFactory{authority: authority, err: nil, calls: 0, cfg: vault.Config{}, cred: nil}
	creds := &fakeCredentials{err: nil, calls: 0, issuerType: "", auth: nil, namespace: ""}

	issuer := namespacedIssuer("team-a")
	issuer.Spec.Policy.MaxDuration = &metav1.Duration{Duration: 30 * time.Minute}

	request := newTestRequest(t, "team-a", 1000*time.Hour)

	bundle, err := newSignerUnderTest(t, creds, factory.build).Sign(t.Context(), request, issuer)
	if err != nil {
		t.Fatalf("Sign() error = %v, want nil", err)
	}

	block, _ := pem.Decode(bundle.ChainPEM)
	if block == nil {
		t.Fatalf("Sign() ChainPEM = %q, want a leaf first", bundle.ChainPEM)
	}

	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parsing leaf: %v", err)
	}

	if left := time.Until(leaf.NotAfter); left > 31*time.Minute {
		t.Errorf("leaf expires in %s, want at most about 30m", left)
	}
}

// TestSignDurationClampedEvent checks that a request whose duration the issuer's
// maxDuration cut is told so on the request, and that one within it, or one
// that asked for no duration, is not.
func TestSignDurationClampedEvent(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		duration time.Duration

		wantEvents int
	}{
		{name: "a duration within maxDuration", duration: 10 * time.Minute, wantEvents: 0},
		{name: "a duration at maxDuration", duration: 30 * time.Minute, wantEvents: 0},
		{name: "a duration past maxDuration", duration: 1000 * time.Hour, wantEvents: 1},
		{name: "no duration, with a default past maxDuration", duration: 0, wantEvents: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			authority, _ := newFakeAuthority(t)
			factory := &fakeFactory{authority: authority, err: nil, calls: 0, cfg: vault.Config{}, cred: nil}
			creds := &fakeCredentials{err: nil, calls: 0, issuerType: "", auth: nil, namespace: ""}
			s, events := newSignerWithEvents(t, creds, factory.build)

			issuer := namespacedIssuer("team-a")
			issuer.Spec.Policy.MaxDuration = &metav1.Duration{Duration: 30 * time.Minute}

			request := newTestRequest(t, "team-a", tt.duration)

			if _, err := s.Sign(t.Context(), request, issuer); err != nil {
				t.Fatalf("Sign() error = %v, want nil", err)
			}

			// The test CA expires within the default warning threshold, so the
			// events about the CA are expected too, and are not what is tested.
			var got []recordedEvent

			for _, e := range events.events {
				if e.reason == eventReasonDurationClamped {
					got = append(got, e)
				}
			}

			if len(got) != tt.wantEvents {
				t.Fatalf("recorded %d %s events, want %d: %+v", len(got), eventReasonDurationClamped, tt.wantEvents, events.events)
			}

			if tt.wantEvents == 0 {
				return
			}

			if got[0].regarding != any(request) {
				t.Errorf("event is about %v, want the request", got[0].regarding)
			}

			if got[0].eventType != corev1.EventTypeNormal || got[0].action != eventActionSigning {
				t.Errorf("event = %s %s, want Normal %s", got[0].eventType, got[0].action, eventActionSigning)
			}

			if want := (30 * time.Minute).String(); !strings.Contains(got[0].note, want) {
				t.Errorf("event note = %q, want it to contain maxDuration %q", got[0].note, want)
			}
		})
	}
}

// TestSignDoesNotBuildForRejectedRequests guards the order of Sign: a request
// from a namespace that is not allowed, or one that cannot be read, must not
// reach Key Vault.
func TestSignDoesNotBuildForRejectedRequests(t *testing.T) {
	t.Parallel()

	authority, _ := newFakeAuthority(t)
	factory := &fakeFactory{authority: authority, err: nil, calls: 0, cfg: vault.Config{}, cred: nil}
	creds := &fakeCredentials{err: nil, calls: 0, issuerType: "", auth: nil, namespace: ""}

	s := newSignerUnderTest(t, creds, factory.build)

	_, _ = s.Sign(t.Context(), newTestRequest(t, "team-b", time.Hour), clusterIssuer(nil, []string{"team-a"}))

	unreadable := newTestRequest(t, "team-a", time.Hour)
	unreadable.detailsErr = errors.New("unknown usage")

	_, _ = s.Sign(t.Context(), unreadable, namespacedIssuer("team-a"))

	if creds.calls != 0 || factory.calls != 0 {
		t.Errorf("credential builder calls = %d, authority factory calls = %d, want both 0", creds.calls, factory.calls)
	}
}
