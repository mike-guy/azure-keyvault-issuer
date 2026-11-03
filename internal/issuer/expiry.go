package issuer

import (
	"fmt"
	"time"

	issuerapi "github.com/cert-manager/issuer-lib/api/v1alpha1"
	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"

	"github.com/mike-guy/azure-keyvault-issuer/api/v1alpha1"
	"github.com/mike-guy/azure-keyvault-issuer/internal/keyvault"
)

const (
	// caExpiryWarning is how long before the CA chain expires each Check and
	// Sign records a CAExpiringSoon event on the issuer. It is fixed: alerting
	// thresholds belong on the gauge, and the event is only a hint in
	// kubectl describe.
	caExpiryWarning = 30 * 24 * time.Hour

	// reasonCAExpiringSoon is the reason of the event recorded on an issuer
	// whose CA chain expires within caExpiryWarning.
	reasonCAExpiringSoon = "CAExpiringSoon"
)

// newCAExpiryGauge returns the gauge that holds when each issuer's CA chain
// expires. Lifetimes are clamped to that moment, so as it nears, certificates
// get shorter until the issuer stops working; the gauge lets that be alerted
// on.
func newCAExpiryGauge() *prometheus.GaugeVec {
	return prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "azure_keyvault_issuer_ca_expiration_timestamp_seconds",
		Help: "When each issuer's CA chain expires, as a Unix timestamp: the earliest expiry in the chain, to which issued lifetimes are clamped.",
	}, []string{"kind", "namespace", "name"})
}

// Metrics returns the collector of the issuer's metrics, for the composition
// root to register.
func (i *Issuer) Metrics() prometheus.Collector {
	return i.caExpiry
}

// observeCA records when ca's chain expires for iss, and warns on iss when
// that is near. Both Check and Sign call it, because Check runs only when the
// issuer changes, while Sign sees a rotated CA at once. action is the event's
// action. Repeated identical events are merged into a series by the events
// API, so a warning on every Sign does not flood the issuer.
func (i *Issuer) observeCA(iss issuerapi.Issuer, ca *keyvault.CA, src keyvault.CASource, action string) {
	notAfter := ca.NotAfter()

	i.caExpiry.WithLabelValues(kindOf(iss), iss.GetNamespace(), iss.GetName()).Set(float64(notAfter.Unix()))

	if i.events == nil || time.Until(notAfter) > caExpiryWarning {
		return
	}

	i.events.Eventf(iss, nil, corev1.EventTypeWarning, reasonCAExpiringSoon, action,
		"CA %s chain expires at %s; issued certificates are shortened to match. Rotate the CA (docs/ca-provisioning.md, Rotation).",
		src, notAfter.UTC().Format(time.RFC3339))
}

// kindOf returns iss's kind, for metric labels. Objects read from the cache
// may have no TypeMeta, so the Go type decides.
func kindOf(iss issuerapi.Issuer) string {
	switch iss.(type) {
	case *v1alpha1.AzureKeyVaultIssuer:
		return "AzureKeyVaultIssuer"
	case *v1alpha1.AzureKeyVaultClusterIssuer:
		return "AzureKeyVaultClusterIssuer"
	default:
		return fmt.Sprintf("%T", iss)
	}
}
