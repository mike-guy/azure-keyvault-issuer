package vault

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
)

// TestClassifyMessageIsOneLine checks that the message of an SDK response error,
// which is a multi-line dump of the request and response, comes out on one line
// with its useful parts, for every kind of response error and every outcome.
func TestClassifyMessageIsOneLine(t *testing.T) {
	t.Parallel()

	const vaultBody = `{"error":{"code":"Forbidden","message":"Caller is not authorized to perform action on resource."}}`

	const entraBody = `{"error":"invalid_client","error_description":"AADSTS7000215: Invalid client secret provided."}`

	tests := []struct {
		name      string
		err       func(t *testing.T) error
		sentinel  error
		wantParts []string
	}{
		{
			name:      "a vault 403 that is access denied",
			err:       func(t *testing.T) error { return newResponseErrorWithBody(t, http.StatusForbidden, vaultBody) },
			sentinel:  ErrAccessDenied,
			wantParts: []string{"vault: access denied: POST https://vault.example.net/keys/ca-cert/sign", "RESPONSE 403", `"message": "Caller is not authorized to perform action on resource."`},
		},
		{
			name:      "a vault 404 that is not found",
			err:       func(t *testing.T) error { return newResponseErrorWithBody(t, http.StatusNotFound, vaultBody) },
			sentinel:  ErrNotFound,
			wantParts: []string{"vault: item not found: POST https://vault.example.net/keys/ca-cert/sign", "RESPONSE 404"},
		},
		{
			name:      "a vault 503 that has no sentinel",
			err:       func(t *testing.T) error { return newResponseErrorWithBody(t, http.StatusServiceUnavailable, vaultBody) },
			sentinel:  nil,
			wantParts: []string{"POST https://vault.example.net/keys/ca-cert/sign", "RESPONSE 503"},
		},
		{
			name: "an Entra 401 that is access denied",
			err: func(t *testing.T) error {
				return newAuthenticationFailedErrorWithBody(t, http.StatusUnauthorized, entraBody)
			},
			sentinel:  ErrAccessDenied,
			wantParts: []string{"vault: access denied:", "RESPONSE 401", "AADSTS7000215: Invalid client secret provided."},
		},
		{
			name: "an Entra 503 that has no sentinel",
			err: func(t *testing.T) error {
				return newAuthenticationFailedErrorWithBody(t, http.StatusServiceUnavailable, entraBody)
			},
			sentinel:  nil,
			wantParts: []string{"RESPONSE 503"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			original := tt.err(t)
			got := classify(original)
			message := got.Error()

			if strings.ContainsAny(message, "\n\r") {
				t.Errorf("classify() message has a line break: %q", message)
			}

			if strings.Contains(message, "-----") {
				t.Errorf("classify() message has a separator: %q", message)
			}

			for _, want := range tt.wantParts {
				if !strings.Contains(message, want) {
					t.Errorf("classify() message = %q, want it to contain %q", message, want)
				}
			}

			if tt.sentinel != nil && !errors.Is(got, tt.sentinel) {
				t.Errorf("classify() = %v, want it to wrap %v", got, tt.sentinel)
			}

			// The original stays reachable, for its status code and request ID.
			if !errors.Is(got, original) {
				t.Errorf("classify() = %v, want it to wrap the original error", got)
			}
		})
	}
}

// TestClassifyLeavesOtherErrorsAlone checks that an error that is not a response
// is returned as it is, so its type and message are untouched.
func TestClassifyLeavesOtherErrorsAlone(t *testing.T) {
	t.Parallel()

	if got := classify(context.Canceled); got != context.Canceled { //nolint:errorlint // asserting identity, not matching.
		t.Errorf("classify(context.Canceled) = %v, want it returned unchanged", got)
	}
}

func TestOneLine(t *testing.T) {
	t.Parallel()

	// é is two bytes, and 💥 four, so a cut at the limit lands inside one.
	long := strings.Repeat("é", maxSDKMessageBytes*2)
	longWide := strings.Repeat("💥", maxSDKMessageBytes)

	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "one line is unchanged", in: "already one line", want: "already one line"},
		{name: "lines are joined with one space", in: "first\nsecond\n  third  ", want: "first second third"},
		{name: "separator and blank lines are dropped", in: "a\n--------\n\nb\n----\n", want: "a b"},
		{name: "a dash inside a line is kept", in: "a-b\n- c", want: "a-b - c"},
		{name: "indentation and runs of spaces collapse", in: "{\n  \"a\":   1\n}", want: `{ "a": 1 }`},
		// 797 bytes of room before the ellipsis falls inside an é, so 398 fit.
		{name: "a long message is cut on a character boundary with an ellipsis", in: long, want: strings.Repeat("é", 398) + "…"},
		{name: "a wide character is not split by the cut", in: longWide, want: strings.Repeat("💥", 199) + "…"},
		{name: "a message at the limit is not cut", in: strings.Repeat("x", maxSDKMessageBytes), want: strings.Repeat("x", maxSDKMessageBytes)},
		{name: "a message one byte over the limit is cut", in: strings.Repeat("x", maxSDKMessageBytes+1), want: strings.Repeat("x", maxSDKMessageBytes-len("…")) + "…"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := oneLine(tt.in)
			if got != tt.want {
				t.Errorf("oneLine(%q) = %q, want %q", tt.in, got, tt.want)
			}

			if len(got) > maxSDKMessageBytes {
				t.Errorf("oneLine() is %d bytes, want at most %d", len(got), maxSDKMessageBytes)
			}

			if !utf8.ValidString(got) {
				t.Errorf("oneLine() = %q, want valid UTF-8", got)
			}
		})
	}
}

// TestClassifyAuthenticationFailed checks that Entra ID refusing a credential is
// access denied, which is retried slowly, while throttling, a timeout, a server
// error and a token request that got no response are left to back off.
func TestClassifyAuthenticationFailed(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		err        func(t *testing.T) error
		wantDenied bool
	}{
		{name: "400 bad request, as for an unknown tenant or client", err: func(t *testing.T) error { return newAuthenticationFailedError(t, http.StatusBadRequest) }, wantDenied: true},
		{name: "401 unauthorized, as for a wrong client secret", err: func(t *testing.T) error { return newAuthenticationFailedError(t, http.StatusUnauthorized) }, wantDenied: true},
		{name: "403 forbidden", err: func(t *testing.T) error { return newAuthenticationFailedError(t, http.StatusForbidden) }, wantDenied: true},
		{name: "408 request timeout is transient", err: func(t *testing.T) error { return newAuthenticationFailedError(t, http.StatusRequestTimeout) }, wantDenied: false},
		{name: "429 throttling is transient", err: func(t *testing.T) error { return newAuthenticationFailedError(t, http.StatusTooManyRequests) }, wantDenied: false},
		{name: "500 is transient", err: func(t *testing.T) error { return newAuthenticationFailedError(t, http.StatusInternalServerError) }, wantDenied: false},
		{name: "503 is transient", err: func(t *testing.T) error { return newAuthenticationFailedError(t, http.StatusServiceUnavailable) }, wantDenied: false},
		{name: "no response, as for a network failure, is transient", err: func(*testing.T) error { return &azidentity.AuthenticationFailedError{RawResponse: nil} }, wantDenied: false},
		{name: "wrapped by the SDK", err: func(t *testing.T) error {
			return fmt.Errorf("pipeline: %w", newAuthenticationFailedError(t, http.StatusUnauthorized))
		}, wantDenied: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := tt.err(t)
			got := classify(err)

			if denied := errors.Is(got, ErrAccessDenied); denied != tt.wantDenied {
				t.Fatalf("classify() access denied = %t, want %t (error %v)", denied, tt.wantDenied, got)
			}

			if !tt.wantDenied && !errors.Is(got, err) {
				t.Errorf("classify() = %v, want the error returned unchanged", got)
			}

			// The original error stays reachable, for its status and message.
			var authErr *azidentity.AuthenticationFailedError
			if !errors.As(got, &authErr) {
				t.Errorf("classify() = %v, want it to wrap an *azidentity.AuthenticationFailedError", got)
			}
		})
	}
}

// TestSentinelsNamePackage guards the convention that every classified error
// starts with its package name, so its origin is clear in logs.
func TestSentinelsNamePackage(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		sentinel error
	}{
		{name: "ErrInvalidConfig", sentinel: ErrInvalidConfig},
		{name: "ErrNotFound", sentinel: ErrNotFound},
		{name: "ErrAccessDenied", sentinel: ErrAccessDenied},
		{name: "ErrCertificateUnusable", sentinel: ErrCertificateUnusable},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if !strings.HasPrefix(tt.sentinel.Error(), "vault: ") {
				t.Errorf("%s = %q, want prefix %q", tt.name, tt.sentinel, "vault: ")
			}
		})
	}
}
