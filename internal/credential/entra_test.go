package credential

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
)

const entraHost = "https://login.microsoftonline.com"

// entraTokenRequest is one token request that reached the fake Entra.
type entraTokenRequest struct {
	tenant string
	form   url.Values
}

// fakeEntra stands in for Microsoft Entra as an azcore transport. It answers
// instance discovery, each tenant's OpenID configuration and the token
// endpoint, and records the token requests so tests can check what was sent.
type fakeEntra struct {
	t *testing.T

	mu       sync.Mutex
	requests []entraTokenRequest
}

func newFakeEntra(t *testing.T) *fakeEntra {
	t.Helper()

	return &fakeEntra{t: t}
}

// tokenRequests returns a copy of the token requests seen so far.
func (f *fakeEntra) tokenRequests() []entraTokenRequest {
	f.mu.Lock()
	defer f.mu.Unlock()

	return append([]entraTokenRequest(nil), f.requests...)
}

// Do implements policy.Transporter.
func (f *fakeEntra) Do(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme+"://"+req.URL.Host != entraHost {
		f.t.Errorf("request to unexpected host: %s", req.URL)
		return respond(req, http.StatusNotFound, `{}`), nil
	}

	segments := strings.Split(strings.Trim(req.URL.Path, "/"), "/")
	tenant := segments[0]
	rest := strings.Join(segments[1:], "/")

	switch {
	case tenant == "common" && rest == "discovery/instance":
		authority, err := url.Parse(req.URL.Query().Get("authorization_endpoint"))
		if err != nil {
			return nil, err
		}

		authTenant := strings.Split(strings.Trim(authority.Path, "/"), "/")[0]

		return respond(req, http.StatusOK, fmt.Sprintf(
			`{"tenant_discovery_endpoint":%q,"api-version":"1.1","metadata":[{"preferred_network":"login.microsoftonline.com","preferred_cache":"login.windows.net","aliases":["login.microsoftonline.com","login.windows.net"]}]}`,
			entraHost+"/"+authTenant+"/v2.0/.well-known/openid-configuration")), nil

	case rest == "v2.0/.well-known/openid-configuration":
		base := entraHost + "/" + tenant
		return respond(req, http.StatusOK, fmt.Sprintf(
			`{"authorization_endpoint":%q,"token_endpoint":%q,"issuer":%q}`,
			base+"/oauth2/v2.0/authorize", base+"/oauth2/v2.0/token", base+"/v2.0")), nil

	case rest == "oauth2/v2.0/token" && req.Method == http.MethodPost:
		body, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}

		form, err := url.ParseQuery(string(body))
		if err != nil {
			return nil, err
		}

		f.mu.Lock()
		f.requests = append(f.requests, entraTokenRequest{tenant: tenant, form: form})
		n := len(f.requests)
		f.mu.Unlock()

		return respond(req, http.StatusOK, fmt.Sprintf(
			`{"token_type":"Bearer","expires_in":3600,"ext_expires_in":3600,"access_token":"access-token-%d"}`, n)), nil

	default:
		f.t.Errorf("unexpected Entra request: %s %s", req.Method, req.URL)
		return respond(req, http.StatusNotFound, `{}`), nil
	}
}

func respond(req *http.Request, status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Status:     http.StatusText(status),
		Header:     http.Header{"Content-Type": {"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    req,
	}
}
