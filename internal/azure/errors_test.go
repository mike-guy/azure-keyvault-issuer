package azure

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
)

func newResponseError(t *testing.T, status int, body string) error {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://my-ca.vault.azure.net/certificates/ca", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}

	resp := &http.Response{
		StatusCode: status,
		Status:     http.StatusText(status),
		Header:     http.Header{"Content-Type": {"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    req,
	}

	return runtime.NewResponseError(resp)
}

func TestErrorText(t *testing.T) {
	t.Parallel()

	forbidden := newResponseError(t, http.StatusForbidden,
		`{"error":{"code":"Forbidden","message":"Caller is not authorized.\n  Assignment: (not found)","innererror":{"code":"ForbiddenByRbac"}}}`)
	notFound := newResponseError(t, http.StatusNotFound, `not json`)
	long := newResponseError(t, http.StatusBadRequest,
		fmt.Sprintf(`{"error":{"code":"BadParameter","message":%q}}`, strings.Repeat("x", 400)))
	entra := &azidentity.AuthenticationFailedError{RawResponse: &http.Response{
		StatusCode: http.StatusBadRequest,
		Body: io.NopCloser(strings.NewReader(
			`{"error":"invalid_request","error_description":"AADSTS70021: No matching federated identity record found.\r\nTrace ID: abc"}`)),
	}}

	tests := []struct {
		name string
		err  error
		want string
	}{
		{"nil", nil, ""},
		{"plain", errors.New("boom"), "boom"},
		{
			"wrapped forbidden",
			fmt.Errorf("getting certificate %q: %w", "ca", forbidden),
			`getting certificate "ca": HTTP 403 Forbidden (ForbiddenByRbac): Caller is not authorized. Assignment: (not found)`,
		},
		{"no body message", notFound, "HTTP 404 Not Found"},
		{
			"wrapped Entra failure",
			fmt.Errorf("getting token: %w", entra),
			"getting token: authentication failed: HTTP 400 Bad Request (invalid_request): AADSTS70021: No matching federated identity record found. Trace ID: abc",
		},
		{"long message truncated", long, "HTTP 400 Bad Request (BadParameter): " + strings.Repeat("x", maxMessageLength) + "..."},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := errorText(tt.err)
			if got != tt.want {
				t.Errorf("errorText() =\n%q\nwant\n%q", got, tt.want)
			}

			if strings.Contains(got, "\n") {
				t.Errorf("errorText() contains a newline: %q", got)
			}
		})
	}
}

func TestShorten(t *testing.T) {
	t.Parallel()

	if Shorten(nil) != nil {
		t.Error("Shorten(nil) is not nil")
	}

	forbidden := newResponseError(t, http.StatusForbidden,
		`{"error":{"code":"Forbidden","message":"Caller is not authorized.\n  Assignment: (not found)","innererror":{"code":"ForbiddenByRbac"}}}`)
	err := fmt.Errorf("getting certificate %q: %w", "ca", Shorten(forbidden))

	want := `getting certificate "ca": HTTP 403 Forbidden (ForbiddenByRbac): Caller is not authorized. Assignment: (not found)`
	if got := err.Error(); got != want {
		t.Errorf("Error() =\n%q\nwant\n%q", got, want)
	}

	var re *azcore.ResponseError
	if !errors.As(err, &re) {
		t.Error("errors.As cannot reach the ResponseError")
	}

	if code, ok := StatusCode(err); !ok || code != http.StatusForbidden {
		t.Errorf("StatusCode() = %d, %t; want 403, true", code, ok)
	}
}

func TestStatusCode(t *testing.T) {
	t.Parallel()

	if code, ok := StatusCode(fmt.Errorf("wrapped: %w", newResponseError(t, http.StatusTooManyRequests, `{}`))); !ok || code != http.StatusTooManyRequests {
		t.Errorf("StatusCode(wrapped 429) = %d, %t; want 429, true", code, ok)
	}

	entra := &azidentity.AuthenticationFailedError{RawResponse: &http.Response{StatusCode: http.StatusServiceUnavailable}}
	if code, ok := StatusCode(fmt.Errorf("getting token: %w", entra)); !ok || code != http.StatusServiceUnavailable {
		t.Errorf("StatusCode(wrapped Entra 503) = %d, %t; want 503, true", code, ok)
	}

	if code, ok := StatusCode(&azidentity.AuthenticationFailedError{}); ok || code != 0 {
		t.Errorf("StatusCode(Entra without response) = %d, %t; want 0, false", code, ok)
	}

	if code, ok := StatusCode(errors.New("boom")); ok || code != 0 {
		t.Errorf("StatusCode(plain) = %d, %t; want 0, false", code, ok)
	}
}
