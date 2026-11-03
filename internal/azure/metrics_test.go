package azure

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// transportFunc is a policy.Transporter that answers with a function.
type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) Do(req *http.Request) (*http.Response, error) { return f(req) }

// TestRequestMetrics checks that every attempt through ClientOptions'
// pipeline is counted and timed by host, method and status code, and that an
// attempt with no response is counted as "error".
func TestRequestMetrics(t *testing.T) {
	t.Parallel()

	statuses := map[string]int{"/ok": http.StatusOK, "/forbidden": http.StatusForbidden}
	transport := transportFunc(func(req *http.Request) (*http.Response, error) {
		status, ok := statuses[req.URL.Path]
		if !ok {
			return nil, errors.New("connection refused")
		}

		return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader("")), Request: req}, nil
	})

	m := NewRequestMetrics()
	opts := ClientOptions(transport, m)
	opts.Retry.MaxRetries = -1 // one attempt each, so the counts are exact

	pl := runtime.NewPipeline("test", "v0.0.0", runtime.PipelineOptions{}, &opts)

	for _, path := range []string{"/ok", "/ok", "/forbidden", "/unreachable"} {
		req, err := runtime.NewRequest(t.Context(), http.MethodGet, "https://test-ca.vault.azure.net"+path)
		if err != nil {
			t.Fatal(err)
		}

		resp, err := pl.Do(req)
		if err == nil {
			_ = resp.Body.Close()
		}
	}

	for _, tt := range []struct {
		code string
		want float64
	}{
		{"200", 2},
		{"403", 1},
		{"error", 1},
	} {
		if got := testutil.ToFloat64(m.requests.WithLabelValues("test-ca.vault.azure.net", http.MethodGet, tt.code)); got != tt.want {
			t.Errorf("requests with code %s = %v, want %v", tt.code, got, tt.want)
		}
	}

	if n := testutil.CollectAndCount(m, "azure_keyvault_issuer_azure_request_duration_seconds"); n != 3 {
		t.Errorf("duration series = %d, want one per host, method and code (3)", n)
	}
}

func TestClientOptionsWithoutMetrics(t *testing.T) {
	t.Parallel()

	if opts := ClientOptions(nil, nil); len(opts.PerRetryPolicies) != 0 {
		t.Errorf("PerRetryPolicies = %v, want none without metrics", opts.PerRetryPolicies)
	}
}
