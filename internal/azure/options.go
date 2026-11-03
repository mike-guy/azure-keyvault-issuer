package azure

import (
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
)

const (
	// applicationID is added to the User-Agent of every request. Azure allows
	// at most 24 characters.
	applicationID = "azure-keyvault-issuer"

	// tryTimeout bounds each attempt of an HTTP request. azcore sets no limit
	// by default, so a connection that never answers would hold a reconcile
	// worker for good. Key Vault and Entra normally answer in well under a
	// second; a timed-out attempt is retried like a 5xx.
	tryTimeout = 30 * time.Second
)

// ClientOptions returns the options shared by every Azure SDK client. The
// default retry policy is kept: it already retries throttled (429) and
// server-error responses and honours Retry-After. Each attempt is limited to
// 30 seconds, and recorded in metrics unless it is nil.
//
// transport is nil in production. Tests pass an SDK fake server transport.
func ClientOptions(transport policy.Transporter, metrics *RequestMetrics) azcore.ClientOptions {
	opts := azcore.ClientOptions{
		Retry:     policy.RetryOptions{TryTimeout: tryTimeout},
		Telemetry: policy.TelemetryOptions{ApplicationID: applicationID},
		Transport: transport,
	}

	if metrics != nil {
		opts.PerRetryPolicies = []policy.Policy{metrics}
	}

	return opts
}
