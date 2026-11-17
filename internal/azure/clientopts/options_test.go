package clientopts

import (
	"math"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	t.Parallel()

	opts := New()

	tests := []struct {
		name string
		got  any
		want any
	}{
		{
			name: "max retries defaults to 3",
			got:  opts.Retry.MaxRetries,
			want: int32(3),
		},
		{
			name: "try timeout defaults to 10 seconds",
			got:  opts.Retry.TryTimeout,
			want: 10 * time.Second,
		},
		{
			name: "retry delay defaults to 1 second",
			got:  opts.Retry.RetryDelay,
			want: time.Second,
		},
		{
			name: "max retry delay defaults to 10 seconds",
			got:  opts.Retry.MaxRetryDelay,
			want: 10 * time.Second,
		},
		{
			name: "telemetry application id is set",
			got:  opts.Telemetry.ApplicationID,
			want: "azure-keyvault-issuer",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if tt.got != tt.want {
				t.Errorf("New() %s = %v, want %v", tt.name, tt.got, tt.want)
			}
		})
	}
}

func TestTelemetryApplicationID(t *testing.T) {
	t.Parallel()

	// The SDK limits the application id to 24 characters with no spaces.
	const maxLen = 24

	if len(telemetryApplicationID) > maxLen {
		t.Errorf("telemetryApplicationID = %q, want at most %d characters", telemetryApplicationID, maxLen)
	}

	if strings.Contains(telemetryApplicationID, " ") {
		t.Errorf("telemetryApplicationID = %q, want no spaces", telemetryApplicationID)
	}
}

func TestNewReturnsIndependentValues(t *testing.T) {
	t.Parallel()

	first := New()
	first.Retry.MaxRetries = 99
	first.Telemetry.ApplicationID = "changed"

	second := New()

	if second.Retry.MaxRetries != DefaultMaxRetries {
		t.Errorf("New() MaxRetries = %d after mutating another result, want %d", second.Retry.MaxRetries, DefaultMaxRetries)
	}

	if second.Telemetry.ApplicationID != telemetryApplicationID {
		t.Errorf("New() ApplicationID = %q after mutating another result, want %q", second.Telemetry.ApplicationID, telemetryApplicationID)
	}
}

// TestSetRetryRefusesUnsafeValues checks that a value that would defeat the
// documented bound is refused, and that opts is left as it was.
func TestSetRetryRefusesUnsafeValues(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		maxRetries int
		tryTimeout time.Duration
		wantMsg    string
	}{
		{name: "a zero try timeout, which the SDK reads as no timeout", maxRetries: 3, tryTimeout: 0, wantMsg: "try timeout must be positive"},
		{name: "a negative try timeout", maxRetries: 3, tryTimeout: -time.Second, wantMsg: "try timeout must be positive"},
		{name: "negative retries", maxRetries: -1, tryTimeout: time.Second, wantMsg: "max retries must be between 0 and"},
		{name: "retries too many for the SDK's int32", maxRetries: math.MaxInt32 + 1, tryTimeout: time.Second, wantMsg: "max retries must be between 0 and"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			opts := New()
			before := opts

			err := SetRetry(&opts, tt.maxRetries, tt.tryTimeout)
			if err == nil || !strings.Contains(err.Error(), tt.wantMsg) {
				t.Fatalf("SetRetry(%d, %v) error = %v, want it to contain %q", tt.maxRetries, tt.tryTimeout, err, tt.wantMsg)
			}

			if !reflect.DeepEqual(opts.Retry, before.Retry) {
				t.Errorf("SetRetry(%d, %v) changed the retry options to %+v, want them unchanged at %+v", tt.maxRetries, tt.tryTimeout, opts.Retry, before.Retry)
			}
		})
	}
}

// TestSetRetryAcceptsTheLargestRetries checks the upper edge of the range.
func TestSetRetryAcceptsTheLargestRetries(t *testing.T) {
	t.Parallel()

	opts := New()

	if err := SetRetry(&opts, math.MaxInt32, time.Second); err != nil {
		t.Fatalf("SetRetry(MaxInt32) error = %v, want nil", err)
	}

	if opts.Retry.MaxRetries != math.MaxInt32 {
		t.Errorf("SetRetry(MaxInt32) MaxRetries = %d, want %d", opts.Retry.MaxRetries, int32(math.MaxInt32))
	}
}

func TestSetRetry(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		maxRetries     int
		tryTimeout     time.Duration
		wantMaxRetries int32
	}{
		{
			name:           "zero retries is sent as negative so the SDK disables retries",
			maxRetries:     0,
			tryTimeout:     5 * time.Second,
			wantMaxRetries: -1,
		},
		{
			name:           "positive retries are passed through",
			maxRetries:     5,
			tryTimeout:     30 * time.Second,
			wantMaxRetries: 5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			opts := New()
			if err := SetRetry(&opts, tt.maxRetries, tt.tryTimeout); err != nil {
				t.Fatalf("SetRetry(%d, %v) error = %v, want nil", tt.maxRetries, tt.tryTimeout, err)
			}

			if opts.Retry.MaxRetries != tt.wantMaxRetries {
				t.Errorf("SetRetry(%d, %v) MaxRetries = %d, want %d", tt.maxRetries, tt.tryTimeout, opts.Retry.MaxRetries, tt.wantMaxRetries)
			}

			if opts.Retry.TryTimeout != tt.tryTimeout {
				t.Errorf("SetRetry(%d, %v) TryTimeout = %v, want %v", tt.maxRetries, tt.tryTimeout, opts.Retry.TryTimeout, tt.tryTimeout)
			}

			if opts.Retry.RetryDelay != defaultRetryDelay {
				t.Errorf("SetRetry(%d, %v) RetryDelay = %v, want it unchanged at %v", tt.maxRetries, tt.tryTimeout, opts.Retry.RetryDelay, defaultRetryDelay)
			}
		})
	}
}
