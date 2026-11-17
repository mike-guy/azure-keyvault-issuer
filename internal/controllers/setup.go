package controllers

import (
	"context"
	"errors"
	"fmt"
	"time"

	issuerapi "github.com/cert-manager/issuer-lib/api/v1alpha1"
	issuercontrollers "github.com/cert-manager/issuer-lib/controllers"
	"k8s.io/utils/clock"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/controller"

	api "github.com/mike-guy/azure-keyvault-issuer/api/v1alpha1"
)

const (
	// DefaultFieldOwner is the default for SetupOptions.FieldOwner.
	DefaultFieldOwner = "azure-keyvault-issuer"

	// DefaultMaxRetryDuration is the default for SetupOptions.MaxRetryDuration.
	DefaultMaxRetryDuration = 5 * time.Minute

	// DefaultMaxConcurrentReconciles is the default for
	// SetupOptions.MaxConcurrentReconciles. More than one stops a slow or failing
	// issuer from holding up every other. See docs/design-notes.md.
	DefaultMaxConcurrentReconciles = 3
)

// SetupOptions holds the settings for SetupWithManager. Every field is
// required: SetupWithManager refuses a zero value rather than guess, so a
// mistake is reported. The Default constants are the values to use otherwise.
type SetupOptions struct {
	// FieldOwner is the field manager for status patches and the name of the
	// event recorder. It must not be empty, and must be stable between
	// releases.
	FieldOwner string

	// MaxRetryDuration is how long a request that fails with a backoff error
	// is retried, measured from its creation, before it is failed. Errors that
	// are retried slowly ignore it. It must be greater than zero.
	MaxRetryDuration time.Duration

	// MaxConcurrentReconciles is how many objects each controller reconciles
	// at once, so the total is a multiple of it. It must be at least one, as
	// issuer-lib would coerce a lower value, which hides the mistake.
	MaxConcurrentReconciles int
}

// validate reports every invalid field, not just the first.
func (o SetupOptions) validate() error {
	var errs []error

	if o.FieldOwner == "" {
		errs = append(errs, errors.New("field owner must not be empty"))
	}

	if o.MaxRetryDuration <= 0 {
		errs = append(errs, fmt.Errorf("max retry duration must be greater than 0, got %s", o.MaxRetryDuration))
	}

	if o.MaxConcurrentReconciles < 1 {
		errs = append(errs, fmt.Errorf("max concurrent reconciles must be at least 1, got %d", o.MaxConcurrentReconciles))
	}

	return errors.Join(errs...)
}

// SetupWithManager registers issuer-lib's controllers, with s as their Check
// and Sign, for both issuer kinds and for CertificateRequests. The Kubernetes
// CertificateSigningRequest controller is disabled: only the cert-manager API
// is supported, and it needs no extra RBAC.
//
// The manager's scheme must already hold the api and cert-manager types.
func SetupWithManager(ctx context.Context, mgr ctrl.Manager, s *KeyVaultSigner, opts SetupOptions) error {
	if err := opts.validate(); err != nil {
		return fmt.Errorf("invalid setup options: %w", err)
	}

	c := &issuercontrollers.CombinedController{
		IssuerTypes:                         []issuerapi.Issuer{&api.AzureKeyVaultIssuer{}},
		ClusterIssuerTypes:                  []issuerapi.Issuer{&api.AzureKeyVaultClusterIssuer{}},
		FieldOwner:                          opts.FieldOwner,
		MaxRetryDuration:                    opts.MaxRetryDuration,
		ControllerOptions:                   controller.Options{MaxConcurrentReconciles: opts.MaxConcurrentReconciles},
		Check:                               s.Check,
		Sign:                                s.Sign,
		EventRecorder:                       mgr.GetEventRecorder(opts.FieldOwner),
		Clock:                               clock.RealClock{},
		DisableCertificateRequestController: false,
		DisableKubernetesCSRController:      true,
	}

	if err := c.SetupWithManager(ctx, mgr); err != nil {
		return fmt.Errorf("setting up issuer controllers: %w", err)
	}

	return nil
}
