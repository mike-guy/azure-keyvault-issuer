package azure

import (
	"net/http"
	"strconv"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/prometheus/client_golang/prometheus"
)

// RequestMetrics counts and times every HTTP attempt the Azure SDK clients
// make, to Key Vault and to Microsoft Entra, by host, method and status code.
// It shows why reconciles fail (throttling, a 403, Entra) where the
// controller's own metrics show only that they do. It follows cert-manager's
// metrics for its ACME client.
//
// It runs once per attempt, after authentication, so throttled and retried
// attempts each count, and so does the 401 with which Key Vault answers each
// new client's first request: that is its authentication challenge, not a
// failure.
//
// It is safe for concurrent use. ClientOptions adds it to a client's
// pipeline; passing nil there records nothing.
type RequestMetrics struct {
	requests *prometheus.CounterVec
	duration *prometheus.HistogramVec
}

// NewRequestMetrics returns a RequestMetrics, for the composition root to
// register and pass to every package that builds Azure clients.
func NewRequestMetrics() *RequestMetrics {
	labels := []string{"host", "method", "code"}

	return &RequestMetrics{
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "azure_keyvault_issuer_azure_requests_total",
			Help: "HTTP attempts made to Azure (Key Vault and Microsoft Entra), by host, method and status code; code is \"error\" when no response arrived.",
		}, labels),
		duration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "azure_keyvault_issuer_azure_request_duration_seconds",
			Help:    "Duration of HTTP attempts made to Azure (Key Vault and Microsoft Entra), by host, method and status code.",
			Buckets: prometheus.DefBuckets,
		}, labels),
	}
}

// Describe implements prometheus.Collector.
func (m *RequestMetrics) Describe(ch chan<- *prometheus.Desc) {
	m.requests.Describe(ch)
	m.duration.Describe(ch)
}

// Collect implements prometheus.Collector.
func (m *RequestMetrics) Collect(ch chan<- prometheus.Metric) {
	m.requests.Collect(ch)
	m.duration.Collect(ch)
}

// Do implements policy.Policy.
func (m *RequestMetrics) Do(req *policy.Request) (*http.Response, error) {
	start := time.Now()
	resp, err := req.Next()

	code := "error"
	if resp != nil {
		code = strconv.Itoa(resp.StatusCode)
	}

	raw := req.Raw()
	m.requests.WithLabelValues(raw.URL.Host, raw.Method, code).Inc()
	m.duration.WithLabelValues(raw.URL.Host, raw.Method, code).Observe(time.Since(start).Seconds())

	return resp, err
}
