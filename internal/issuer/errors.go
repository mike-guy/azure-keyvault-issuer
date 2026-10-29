package issuer

import (
	"context"
	"errors"
	"net/http"

	apierrors "k8s.io/apimachinery/pkg/api/errors"

	"github.com/mike-guy/azure-keyvault-issuer/internal/azure"
)

// Errors returned, wrapped with context, by Check and Sign.
var (
	// ErrUnsupportedIssuer reports an issuer type this package does not know.
	ErrUnsupportedIssuer = errors.New("unsupported issuer type")

	// ErrInvalidSpec reports an issuer spec that breaks the CRD's rules,
	// which only an edit to the issuer can fix.
	ErrInvalidSpec = errors.New("invalid issuer spec")

	// ErrVaultNotAllowed reports a namespaced issuer whose vault is not in
	// the controller's allow-list.
	ErrVaultNotAllowed = errors.New("vault is not in the controller's allow-list for namespaced issuers")

	// ErrCANotAllowed reports a request for a CA certificate to an issuer
	// whose policy does not allow them.
	ErrCANotAllowed = errors.New("CA certificates (isCA: true) are not allowed by this issuer's policy (spec.policy.allowCA)")

	// ErrPathLenExceeded reports a request for a CA certificate that the
	// issuing CA's path length constraint does not allow.
	ErrPathLenExceeded = errors.New("path length exceeds the CA's limit")
)

// transient reports whether err is worth retrying as it is: throttling, a
// server error or a timeout, from Azure or from the Kubernetes API server
// (which credentials read Secrets from). Other failures, such as a 403, mean
// the issuer is not working and should be checked again.
func transient(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return true
	}

	if apierrors.IsTooManyRequests(err) || apierrors.IsServerTimeout(err) || apierrors.IsTimeout(err) ||
		apierrors.IsInternalError(err) || apierrors.IsServiceUnavailable(err) {
		return true
	}

	code, ok := azure.StatusCode(err)

	return ok && (code == http.StatusTooManyRequests || code >= http.StatusInternalServerError)
}
