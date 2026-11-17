package vault

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
)

// ErrInvalidConfig means the vault configuration is wrong, such as a vault URL
// or certificate name that fails validation, or client options that the SDK
// rejects. It stays so until the issuer changes. The message names the
// offending input.
var ErrInvalidConfig = errors.New("vault: invalid configuration")

// ErrNotFound means Key Vault has no certificate, secret or key with the
// requested name or version (HTTP 404). It may be fixed in the vault without
// changing the issuer, so callers should retry slowly.
var ErrNotFound = errors.New("vault: item not found")

// ErrAccessDenied means Key Vault refused the request (HTTP 401 or 403), or
// Entra ID refused the token request (a 4xx response). The identity lacks a
// permission, the vault's network rules block the controller, or the credential
// was rejected. The fix is in the vault's access configuration or the
// credential, so callers should retry slowly. A 401 from the vault cannot be
// told apart from a rejected credential.
var ErrAccessDenied = errors.New("vault: access denied")

// ErrCertificateUnusable means the certificate was found but cannot act as a
// signing CA: it is disabled, expired, not yet valid, not a CA, lacks the
// certificate-signing key usage or has an unsupported key type. It also covers
// a backing secret that did not come back as PEM or cannot be read, and a vault
// key whose signatures do not verify against the certificate. The fix is in the
// vault, so callers should retry slowly.
var ErrCertificateUnusable = errors.New("vault: certificate cannot be used as a CA")

// classify maps an error from the Azure SDK onto this package's sentinels, using
// the HTTP status of the vault's response or of Entra ID's response to the token
// request. The result wraps both the sentinel and err, so errors.Is matches the
// sentinel and errors.As still reaches the SDK error. Errors that are not
// responses, such as context cancellation, are returned unchanged. A response
// error has its message put on one line, see oneLineError, whether or not its
// status has a sentinel.
func classify(err error) error {
	var authErr *azidentity.AuthenticationFailedError
	if errors.As(err, &authErr) {
		flat := oneLineError{err: err}

		if authRejected(authErr) {
			return fmt.Errorf("%w: %w", ErrAccessDenied, flat)
		}

		return flat
	}

	var respErr *azcore.ResponseError
	if !errors.As(err, &respErr) {
		return err
	}

	flat := oneLineError{err: err}

	switch respErr.StatusCode {
	case http.StatusUnauthorized, http.StatusForbidden:
		return fmt.Errorf("%w: %w", ErrAccessDenied, flat)
	case http.StatusNotFound:
		return fmt.Errorf("%w: %w", ErrNotFound, flat)
	default:
		return flat
	}
}

// maxSDKMessageBytes caps the message of an Azure SDK error. The message ends up
// in a status condition and an event, whose note is limited to 1024 bytes, so
// this leaves 224 for the sentinel and context added on the way up.
const maxSDKMessageBytes = 800

// ellipsis ends a message that was cut. It is three bytes.
const ellipsis = "…"

// oneLineError is an error from the Azure SDK whose message is on one line and
// at most maxSDKMessageBytes bytes. The SDK's own message dumps the whole
// request and response, which does not belong in a status message or a log
// line. Unwrap keeps the original reachable.
type oneLineError struct {
	err error
}

func (e oneLineError) Error() string { return oneLine(e.err.Error()) }

func (e oneLineError) Unwrap() error { return e.err }

// oneLine drops the blank and separator lines of s, joins the rest with single
// spaces and cuts the result to maxSDKMessageBytes, ending in an ellipsis. The
// cut falls between characters, so the result is valid UTF-8.
func oneLine(s string) string {
	var kept []string

	for _, line := range strings.Split(s, "\n") {
		if strings.Trim(strings.TrimSpace(line), "-") == "" {
			continue
		}

		kept = append(kept, line)
	}

	message := strings.Join(strings.Fields(strings.Join(kept, " ")), " ")

	if len(message) > maxSDKMessageBytes {
		cut := maxSDKMessageBytes - len(ellipsis)
		for cut > 0 && !utf8.RuneStart(message[cut]) {
			cut--
		}

		message = message[:cut] + ellipsis
	}

	return message
}

// authRejected reports whether Entra ID refused the credential, as a client
// error other than throttling or a timeout. A 5xx or an error with no response,
// such as a network failure, is not a refusal.
func authRejected(err *azidentity.AuthenticationFailedError) bool {
	if err.RawResponse == nil {
		return false
	}

	status := err.RawResponse.StatusCode

	return status >= http.StatusBadRequest && status < http.StatusInternalServerError &&
		status != http.StatusRequestTimeout && status != http.StatusTooManyRequests
}
