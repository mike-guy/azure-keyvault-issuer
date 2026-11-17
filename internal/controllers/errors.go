package controllers

import (
	"errors"
	"time"

	"github.com/cert-manager/issuer-lib/controllers/signer"

	"github.com/mike-guy/azure-keyvault-issuer/internal/azure/credential"
	"github.com/mike-guy/azure-keyvault-issuer/internal/azure/vault"
	"github.com/mike-guy/azure-keyvault-issuer/internal/pki"
)

// ErrInvalidConfig means the issuer's spec is wrong in a way that only this
// package checks, such as an allowedNamespaces entry that is not a valid
// namespace name. It stays so until the issuer changes. The message names the
// offending field.
var ErrInvalidConfig = errors.New("controllers: invalid configuration")

// ErrNamespaceNotAllowed means a CertificateRequest came from a namespace that
// the ClusterIssuer's allowedNamespaces does not permit. The requester must use
// another issuer or the list must change, so it is permanent.
var ErrNamespaceNotAllowed = errors.New("controllers: namespace not allowed")

// retryInterval is how long Sign waits before retrying an error that is fixed
// outside the issuer. Nothing announces such a fix, so the interval is fixed
// rather than a backoff that grows.
const retryInterval = 5 * time.Minute

// isPermanent reports whether err wraps a sentinel for something that must
// change before a retry can succeed: the issuer's spec, or the request.
//
// credential.ErrInvalidConfig is deliberately in isRetrySlowly instead. It also
// covers a Secret with the wrong content, and fixing a Secret does not trigger a
// reconcile, so failing the issuer for good would leave it stuck.
func isPermanent(err error) bool {
	return errors.Is(err, ErrInvalidConfig) ||
		errors.Is(err, ErrNamespaceNotAllowed) ||
		errors.Is(err, vault.ErrInvalidConfig) ||
		errors.Is(err, pki.ErrInvalidConfig) ||
		errors.Is(err, pki.ErrInvalidRequest)
}

// isRetrySlowly reports whether err wraps a sentinel for something that is
// fixed outside the issuer, in the cluster or the vault.
func isRetrySlowly(err error) bool {
	return errors.Is(err, credential.ErrInvalidConfig) ||
		errors.Is(err, credential.ErrAmbientIdentityUnavailable) ||
		errors.Is(err, credential.ErrSecretNotFound) ||
		errors.Is(err, vault.ErrNotFound) ||
		errors.Is(err, vault.ErrAccessDenied) ||
		errors.Is(err, vault.ErrCertificateUnusable) ||
		errors.Is(err, pki.ErrAuthorityUnusable)
}

// classifyBuildError classifies an error from building a signer in Check. A
// permanent error becomes a signer.PermanentError. Everything else is returned
// unchanged for backoff, including retry slowly errors, as signer.PendingError
// is for Sign only.
func classifyBuildError(err error) error {
	if isPermanent(err) {
		return signer.PermanentError{Err: err}
	}

	return err
}

// classifySignBuildError classifies an error from building a signer inside
// Sign. A permanent or retry slowly error is the issuer's fault, so it is
// wrapped in a signer.IssuerError and the request waits instead of failing.
// Anything else, such as throttling, is returned unchanged, so that one request
// backs off without marking the issuer not Ready.
func classifySignBuildError(err error) error {
	if isPermanent(err) || isRetrySlowly(err) {
		return signer.IssuerError{Err: classifyBuildError(err)}
	}

	return err
}

// classifySignError classifies an error from signing a request. A permanent
// error becomes a signer.PermanentError and a retry slowly error a
// signer.PendingError, which MaxRetryDuration does not apply to. Everything
// else is returned unchanged for backoff.
func classifySignError(err error) error {
	switch {
	case isPermanent(err):
		return signer.PermanentError{Err: err}
	case isRetrySlowly(err):
		return signer.PendingError{Err: err, RequeueAfter: retryInterval}
	default:
		return err
	}
}
