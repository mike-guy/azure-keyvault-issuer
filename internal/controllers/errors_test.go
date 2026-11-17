package controllers

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/cert-manager/issuer-lib/controllers/signer"

	"github.com/mike-guy/azure-keyvault-issuer/internal/azure/credential"
	"github.com/mike-guy/azure-keyvault-issuer/internal/azure/vault"
	"github.com/mike-guy/azure-keyvault-issuer/internal/pki"
)

// TestSentinelsNamePackage guards the convention that every classified error
// starts with its package name, so its origin is clear in logs.
func TestSentinelsNamePackage(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		sentinel error
	}{
		{name: "ErrInvalidConfig", sentinel: ErrInvalidConfig},
		{name: "ErrNamespaceNotAllowed", sentinel: ErrNamespaceNotAllowed},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if !strings.HasPrefix(tt.sentinel.Error(), "controllers: ") {
				t.Errorf("%s = %q, want prefix %q", tt.name, tt.sentinel, "controllers: ")
			}
		})
	}
}

// classification is the class an error falls in, which every classifier maps
// to its own result.
type classification int

const (
	classOther classification = iota
	classPermanent
	classRetrySlowly
)

// classifiedErrors lists every sentinel the classifiers know, the class it
// belongs to, and one case for an error that no sentinel names.
var classifiedErrors = []struct {
	name  string
	err   error
	class classification
}{
	{name: "controllers.ErrInvalidConfig", err: ErrInvalidConfig, class: classPermanent},
	{name: "controllers.ErrNamespaceNotAllowed", err: ErrNamespaceNotAllowed, class: classPermanent},
	{name: "vault.ErrInvalidConfig", err: vault.ErrInvalidConfig, class: classPermanent},
	{name: "pki.ErrInvalidConfig", err: pki.ErrInvalidConfig, class: classPermanent},
	{name: "pki.ErrInvalidRequest", err: pki.ErrInvalidRequest, class: classPermanent},
	{name: "credential.ErrInvalidConfig", err: credential.ErrInvalidConfig, class: classRetrySlowly},
	{name: "credential.ErrAmbientIdentityUnavailable", err: credential.ErrAmbientIdentityUnavailable, class: classRetrySlowly},
	{name: "credential.ErrSecretNotFound", err: credential.ErrSecretNotFound, class: classRetrySlowly},
	{name: "vault.ErrNotFound", err: vault.ErrNotFound, class: classRetrySlowly},
	{name: "vault.ErrAccessDenied", err: vault.ErrAccessDenied, class: classRetrySlowly},
	{name: "vault.ErrCertificateUnusable", err: vault.ErrCertificateUnusable, class: classRetrySlowly},
	{name: "pki.ErrAuthorityUnusable", err: pki.ErrAuthorityUnusable, class: classRetrySlowly},
	{name: "an unclassified error", err: errUnclassified, class: classOther},
}

// wrapped returns err wrapped as a caller would wrap it, so that tests prove
// the classifiers look through the chain and not only at the top error.
func wrapped(err error) error {
	return fmt.Errorf("building signer: %w", err)
}

// sameError reports whether a and b are the same error value. errors.Is would
// also accept one that wraps the other, which is what the tests that use this
// rule out.
func sameError(a, b error) bool { return a == b } //nolint:errorlint // identity is the point.

func TestIsPermanent(t *testing.T) {
	t.Parallel()

	for _, tt := range classifiedErrors {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			want := tt.class == classPermanent

			if got := isPermanent(tt.err); got != want {
				t.Errorf("isPermanent(%v) = %t, want %t", tt.err, got, want)
			}

			if got := isPermanent(wrapped(tt.err)); got != want {
				t.Errorf("isPermanent(wrapped %v) = %t, want %t", tt.err, got, want)
			}
		})
	}

	t.Run("nil", func(t *testing.T) {
		t.Parallel()

		if isPermanent(nil) {
			t.Error("isPermanent(nil) = true, want false")
		}
	})
}

func TestIsRetrySlowly(t *testing.T) {
	t.Parallel()

	for _, tt := range classifiedErrors {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			want := tt.class == classRetrySlowly

			if got := isRetrySlowly(tt.err); got != want {
				t.Errorf("isRetrySlowly(%v) = %t, want %t", tt.err, got, want)
			}

			if got := isRetrySlowly(wrapped(tt.err)); got != want {
				t.Errorf("isRetrySlowly(wrapped %v) = %t, want %t", tt.err, got, want)
			}
		})
	}

	t.Run("nil", func(t *testing.T) {
		t.Parallel()

		if isRetrySlowly(nil) {
			t.Error("isRetrySlowly(nil) = true, want false")
		}
	})
}

// TestCredentialInvalidConfigIsNotPermanent guards the deliberate gap that
// errors.go documents: a bad Secret is fixed without reconciling the issuer, so
// failing the issuer for good would leave it stuck.
func TestCredentialInvalidConfigIsNotPermanent(t *testing.T) {
	t.Parallel()

	if isPermanent(credential.ErrInvalidConfig) {
		t.Error("isPermanent(credential.ErrInvalidConfig) = true, want false")
	}
}

func TestClassifyBuildError(t *testing.T) {
	t.Parallel()

	for _, tt := range classifiedErrors {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := wrapped(tt.err)
			got := classifyBuildError(err)

			if !errors.Is(got, tt.err) {
				t.Errorf("classifyBuildError(%v) = %v, want it to wrap the original", err, got)
			}

			var permanent signer.PermanentError

			isWrapped := errors.As(got, &permanent)
			if want := tt.class == classPermanent; isWrapped != want {
				t.Errorf("classifyBuildError(%v) is a PermanentError = %t, want %t", err, isWrapped, want)
			}

			// Retry slowly errors are returned unchanged, because a
			// PendingError is for Sign only.
			if tt.class != classPermanent && !sameError(got, err) {
				t.Errorf("classifyBuildError(%v) = %v, want it unchanged", err, got)
			}
		})
	}
}

func TestClassifySignBuildError(t *testing.T) {
	t.Parallel()

	for _, tt := range classifiedErrors {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := wrapped(tt.err)
			got := classifySignBuildError(err)

			if !errors.Is(got, tt.err) {
				t.Errorf("classifySignBuildError(%v) = %v, want it to wrap the original", err, got)
			}

			var issuerErr signer.IssuerError

			isIssuerErr := errors.As(got, &issuerErr)
			if want := tt.class != classOther; isIssuerErr != want {
				t.Errorf("classifySignBuildError(%v) is an IssuerError = %t, want %t", err, isIssuerErr, want)
			}

			var permanent signer.PermanentError

			isPermanentErr := errors.As(got, &permanent)
			if want := tt.class == classPermanent; isPermanentErr != want {
				t.Errorf("classifySignBuildError(%v) wraps a PermanentError = %t, want %t", err, isPermanentErr, want)
			}

			// A permanent error is wrapped inside the IssuerError.
			if isIssuerErr && isPermanentErr {
				var inner signer.PermanentError
				if !errors.As(issuerErr.Err, &inner) {
					t.Errorf("classifySignBuildError(%v) IssuerError.Err = %T, want signer.PermanentError", err, issuerErr.Err)
				}
			}

			// Anything else is returned unchanged, so one request backs off
			// without marking the issuer not Ready.
			if tt.class == classOther && !sameError(got, err) {
				t.Errorf("classifySignBuildError(%v) = %v, want it unchanged", err, got)
			}
		})
	}
}

func TestClassifySignError(t *testing.T) {
	t.Parallel()

	for _, tt := range classifiedErrors {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := wrapped(tt.err)
			got := classifySignError(err)

			if !errors.Is(got, tt.err) {
				t.Errorf("classifySignError(%v) = %v, want it to wrap the original", err, got)
			}

			var (
				permanent signer.PermanentError
				pending   signer.PendingError
			)

			isPermanentErr := errors.As(got, &permanent)
			isPendingErr := errors.As(got, &pending)

			if want := tt.class == classPermanent; isPermanentErr != want {
				t.Errorf("classifySignError(%v) is a PermanentError = %t, want %t", err, isPermanentErr, want)
			}

			if want := tt.class == classRetrySlowly; isPendingErr != want {
				t.Errorf("classifySignError(%v) is a PendingError = %t, want %t", err, isPendingErr, want)
			}

			if isPendingErr && pending.RequeueAfter != retryInterval {
				t.Errorf("classifySignError(%v) RequeueAfter = %s, want %s", err, pending.RequeueAfter, retryInterval)
			}

			if tt.class == classOther && !sameError(got, err) {
				t.Errorf("classifySignError(%v) = %v, want it unchanged", err, got)
			}
		})
	}
}
