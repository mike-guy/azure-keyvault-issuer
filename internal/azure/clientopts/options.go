// Package clientopts holds the azcore.ClientOptions defaults shared by every
// Azure SDK client the controller builds.
package clientopts

import (
	"fmt"
	"math"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
)

const (
	// telemetryApplicationID is added to the User-Agent of Azure requests. The
	// SDK limits it to 24 characters with no spaces.
	telemetryApplicationID = "azure-keyvault-issuer"

	// DefaultMaxRetries and DefaultTryTimeout keep throttled requests from
	// blocking a reconcile for long: the worst case is about 4 attempts x 10s
	// plus backoff, or 47s. SetRetry changes both.
	DefaultMaxRetries = 3
	DefaultTryTimeout = 10 * time.Second

	defaultRetryDelay    = time.Second
	defaultMaxRetryDelay = 10 * time.Second
)

// New returns azcore.ClientOptions with the defaults. Callers may change the
// result, for example with SetRetry, before passing it to a constructor such as
// credential.NewBuilder, but not after, as constructors only shallow-copy it.
func New() azcore.ClientOptions {
	return azcore.ClientOptions{
		Retry: policy.RetryOptions{
			MaxRetries:    DefaultMaxRetries,
			TryTimeout:    DefaultTryTimeout,
			RetryDelay:    defaultRetryDelay,
			MaxRetryDelay: defaultMaxRetryDelay,
		},
		Telemetry: policy.TelemetryOptions{
			ApplicationID: telemetryApplicationID,
		},
	}
}

// SetRetry sets how many times a failed request is retried and how long each
// attempt may take. A maxRetries of 0 disables retries.
//
// The SDK treats zero as "use the default", so SetRetry sends it a negative
// value to disable retries, and refuses a tryTimeout that is not positive, as
// that would remove the bound on an attempt. It also refuses a maxRetries that
// is negative or does not fit the SDK's int32. On an error opts is unchanged.
//
// tryTimeout limits each attempt, not the whole call, which takes about
// (maxRetries+1) x tryTimeout plus backoff. Only a deadline on the context
// bounds it tighter, and the SDK then stops retrying.
func SetRetry(opts *azcore.ClientOptions, maxRetries int, tryTimeout time.Duration) error {
	if tryTimeout <= 0 {
		return fmt.Errorf("try timeout must be positive, got %s", tryTimeout)
	}

	if maxRetries < 0 || maxRetries > math.MaxInt32 {
		return fmt.Errorf("max retries must be between 0 and %d, got %d", math.MaxInt32, maxRetries)
	}

	if maxRetries == 0 {
		maxRetries = -1
	}

	opts.Retry.MaxRetries = int32(maxRetries)
	opts.Retry.TryTimeout = tryTimeout

	return nil
}
