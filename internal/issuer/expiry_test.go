package issuer

import (
	"testing"
	"time"

	issuerapi "github.com/cert-manager/issuer-lib/api/v1alpha1"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// TestCAExpiry checks that Check and Sign both record when the CA chain
// expires, and warn on the issuer only when that is within caExpiryWarning.
func TestCAExpiry(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		expires  time.Duration
		wantWarn bool
	}{
		{"far off", 365 * 24 * time.Hour, false},
		{"within the warning", 10 * 24 * time.Hour, true},
	}

	for _, tt := range tests {
		for _, op := range []string{"Check", "Sign"} {
			t.Run(tt.name+"/"+op, func(t *testing.T) {
				t.Parallel()

				tca := newTestCA(t, time.Now().Add(tt.expires).Truncate(time.Second))
				events := &fakeEvents{}
				iss := New(&fakeCreds{}, &fakeFetcher{ca: tca.keyvaultCA(t, nil)}, Options{Events: events})
				ni := newNamespacedIssuer("uid", 1)

				var err error
				if op == "Check" {
					err = iss.Check(t.Context(), ni)
				} else {
					_, err = iss.Sign(t.Context(), newRequest(t, requestSpec{duration: time.Hour}), ni)
				}

				if err != nil {
					t.Fatalf("%s() error = %v", op, err)
				}

				if got, want := gaugeValue(iss, ni), float64(tca.ca.NotAfter.Unix()); got != want {
					t.Errorf("gauge = %v, want %v", got, want)
				}

				var warnings []event

				for _, e := range events.events {
					if e.reason == reasonCAExpiringSoon {
						warnings = append(warnings, e)
					}
				}

				if got := len(warnings) > 0; got != tt.wantWarn {
					t.Fatalf("%s events = %v, want %t", reasonCAExpiringSoon, warnings, tt.wantWarn)
				}

				if tt.wantWarn && warnings[0].regarding != ni {
					t.Errorf("warning regards %#v, want the issuer", warnings[0].regarding)
				}
			})
		}
	}
}

// TestCAExpiryFollowsRotation checks that Sign updates the gauge when the CA
// is rotated, because issuer-lib does not run Check again for a Ready issuer.
func TestCAExpiryFollowsRotation(t *testing.T) {
	t.Parallel()

	oldCA := newTestCA(t, time.Now().Add(10*24*time.Hour).Truncate(time.Second))
	newCA := newTestCA(t, time.Now().Add(2*365*24*time.Hour).Truncate(time.Second))

	fetcher := &fakeFetcher{ca: oldCA.keyvaultCA(t, nil)}
	iss := New(&fakeCreds{}, fetcher, Options{})
	ci := newClusterIssuer("uid", 1)

	if err := iss.Check(t.Context(), ci); err != nil {
		t.Fatalf("Check() error = %v", err)
	}

	fetcher.ca = newCA.keyvaultCA(t, nil)

	if _, err := iss.Sign(t.Context(), newRequest(t, requestSpec{}), ci); err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	if got, want := gaugeValue(iss, ci), float64(newCA.ca.NotAfter.Unix()); got != want {
		t.Errorf("gauge after rotation = %v, want the new CA's %v", got, want)
	}
}

// TestForgetRemovesCAExpiry checks that a deleted issuer's gauge goes, so it
// cannot raise an alert later.
func TestForgetRemovesCAExpiry(t *testing.T) {
	t.Parallel()

	iss := New(&fakeCreds{}, &fakeFetcher{ca: newTestCA(t, time.Now().Add(365*24*time.Hour)).keyvaultCA(t, nil)}, Options{})
	ci := newClusterIssuer("uid", 1)

	if err := iss.Check(t.Context(), ci); err != nil {
		t.Fatalf("Check() error = %v", err)
	}

	if n := testutil.CollectAndCount(iss.Metrics()); n != 1 {
		t.Fatalf("after Check, %d series, want 1", n)
	}

	iss.Forget(ci)

	if n := testutil.CollectAndCount(iss.Metrics()); n != 0 {
		t.Errorf("after Forget, %d series, want 0", n)
	}
}

func gaugeValue(iss *Issuer, obj issuerapi.Issuer) float64 {
	return testutil.ToFloat64(iss.caExpiry.WithLabelValues(kindOf(obj), obj.GetNamespace(), obj.GetName()))
}
