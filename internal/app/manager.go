package app

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"path/filepath"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	issuerapi "github.com/cert-manager/issuer-lib/api/v1alpha1"
	"github.com/cert-manager/issuer-lib/controllers"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	toolscache "k8s.io/client-go/tools/cache"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	crconfig "sigs.k8s.io/controller-runtime/pkg/config"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/metrics/filters"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/mike-guy/azure-keyvault-issuer/api/v1alpha1"
	"github.com/mike-guy/azure-keyvault-issuer/internal/issuer"
)

const (
	// fieldOwner is the field manager of the status patches issuer-lib
	// applies, and the name events are recorded under.
	fieldOwner = "azure-keyvault-issuer"

	// leaderElectionID names the leader election lease.
	leaderElectionID = "azure-keyvault-issuer-leader"
)

// newScheme returns a scheme with the built-in Kubernetes types, cert-manager's
// CertificateRequest and our issuer kinds. Schemes map GVK to Go types.
func newScheme() (*runtime.Scheme, error) {
	s := runtime.NewScheme()

	for _, add := range []func(*runtime.Scheme) error{clientgoscheme.AddToScheme, cmapi.AddToScheme, v1alpha1.AddToScheme} {
		if err := add(s); err != nil {
			return nil, fmt.Errorf("building scheme: %w", err)
		}
	}

	return s, nil
}

// newManager returns a controller-runtime manager configured from c.
func newManager(cfg *rest.Config, scheme *runtime.Scheme, c config) (ctrl.Manager, error) {
	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme:                  scheme,
		Metrics:                 metricsServerOptions(c),
		HealthProbeBindAddress:  c.probeAddr,
		LeaderElection:          c.leaderElect,
		LeaderElectionID:        leaderElectionID,
		LeaderElectionNamespace: c.leaderElectionNamespace,
		// Run returns as soon as the manager stops, so releasing the lease on
		// shutdown is safe, and lets the next leader start at once.
		LeaderElectionReleaseOnCancel: true,
		GracefulShutdownTimeout:       &c.shutdownTimeout,
		// The CertificateRequest and CertificateSigningRequest controllers
		// take their worker count from here: issuer-lib v0.12 doesn't pass
		// CombinedController.ControllerOptions to them. setupControllers sets the issuer controllers' count. Several
		// workers keep one slow or throttled vault from holding up every
		// other issuer.
		Controller: crconfig.Controller{MaxConcurrentReconciles: c.concurrentWorkers},
		// Managed fields are never read, and dropping them saves memory on
		// every cached CertificateRequest.
		Cache: cache.Options{DefaultTransform: cache.TransformStripManagedFields()},
	})
	if err != nil {
		return nil, fmt.Errorf("creating manager: %w", err)
	}

	if err := mgr.AddHealthzCheck("ping", healthz.Ping); err != nil {
		return nil, fmt.Errorf("adding health check: %w", err)
	}

	if err := mgr.AddReadyzCheck("ping", healthz.Ping); err != nil {
		return nil, fmt.Errorf("adding readiness check: %w", err)
	}

	return mgr, nil
}

// metricsServerOptions returns the metrics endpoint's options. Metrics are
// served over HTTPS, and only to callers that pass a TokenReview and a
// SubjectAccessReview for GET /metrics. With c.metricsCertPath set,
// controller-runtime serves tls.crt and tls.key from it and reloads them when
// they change; otherwise it generates a self-signed certificate.
func metricsServerOptions(c config) metricsserver.Options {
	o := metricsserver.Options{
		BindAddress:    c.metricsAddr,
		SecureServing:  true,
		FilterProvider: filters.WithAuthenticationAndAuthorization,
	}

	if c.metricsCertPath != "" {
		o.CertDir = c.metricsCertPath
		o.CertName = metricsCertFile
		o.KeyName = metricsKeyFile
	}

	return o
}

// The file names in --metrics-cert-path: the keys of a kubernetes.io/tls
// Secret, which is what the chart mounts there.
const (
	metricsCertFile = "tls.crt"
	metricsKeyFile  = "tls.key"
)

// usableMetricsCertPath returns path if it holds a certificate and key that
// load, and "" otherwise, logging which certificate the metrics endpoint
// serves. controller-runtime checks for the files only once, at start-up,
// and fails to start if they are present but don't load. The chart mounts
// them from an optional Secret, which may be issued by this controller, so
// a missing or broken Secret must not stop it starting: it falls back to a
// self-signed certificate, and a restart picks the files up once they are
// usable (docs/metrics.md).
func usableMetricsCertPath(ctx context.Context, logger *slog.Logger, path string) string {
	if path == "" {
		logger.InfoContext(ctx, "metrics endpoint serves a self-signed certificate")

		return ""
	}

	if _, err := tls.LoadX509KeyPair(filepath.Join(path, metricsCertFile), filepath.Join(path, metricsKeyFile)); err != nil {
		logger.WarnContext(ctx, "metrics endpoint serves a self-signed certificate until the controller restarts, because its certificate can't be loaded",
			"path", path, "error", err)

		return ""
	}

	logger.InfoContext(ctx, "metrics endpoint serves the certificate in its certificate path", "path", path)

	return path
}

// newCredentialClient returns the uncached client the credential provider
// uses to request ServiceAccount tokens and read auth Secrets. It is separate
// from the manager's client, so nothing starts an informer on ServiceAccounts
// or Secrets: each is needed only by name, and the controller is granted
// access only to the names it may use, so it could not list them anyway.
func newCredentialClient(cfg *rest.Config, scheme *runtime.Scheme) (client.Client, error) {
	c, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		return nil, fmt.Errorf("creating credential client: %w", err)
	}

	return c, nil
}

// setupControllers registers issuer-lib's controllers for both issuer kinds
// with mgr, and calls forget with each deleted issuer of either kind, so its
// cached credential and metric are dropped. Production passes iss.Forget.
func setupControllers(ctx context.Context, mgr ctrl.Manager, iss *issuer.Issuer, c config, forget func(issuerapi.Issuer)) error {
	issuerTypes := []issuerapi.Issuer{&v1alpha1.AzureKeyVaultIssuer{}}
	clusterIssuerTypes := []issuerapi.Issuer{&v1alpha1.AzureKeyVaultClusterIssuer{}}

	ctl := &controllers.CombinedController{
		IssuerTypes:        issuerTypes,
		ClusterIssuerTypes: clusterIssuerTypes,
		FieldOwner:         fieldOwner,
		MaxRetryDuration:   c.maxRetryDuration,
		Check:              iss.Check,
		Sign:               iss.Sign,
		EventRecorder:      mgr.GetEventRecorder(fieldOwner),
		// issuer-lib signs Kubernetes CertificateSigningRequests by default.
		// It is opt-in here, because it adds a cluster-wide informer on them
		// and needs extra RBAC. issuer-lib accepts them for ClusterIssuers
		// only.
		DisableKubernetesCSRController: !c.signCertificateSigningRequests,
		// The issuer controllers take their worker count from here. Left
		// unset, issuer-lib sets it to 1, overriding the manager's
		// value. It reaches neither the CertificateRequest nor the
		// CertificateSigningRequest controller (see newManager).
		ControllerOptions: controller.Options{MaxConcurrentReconciles: c.concurrentWorkers},
	}

	if err := ctl.SetupWithManager(ctx, mgr); err != nil {
		return fmt.Errorf("setting up controllers: %w", err)
	}

	for _, obj := range append(issuerTypes, clusterIssuerTypes...) {
		if err := forgetOnDelete(ctx, mgr, obj, forget); err != nil {
			return err
		}
	}

	return nil
}

// forgetOnDelete calls forget with each deleted object of obj's type. It
// shares the informer issuer-lib already watches.
func forgetOnDelete(ctx context.Context, mgr ctrl.Manager, obj client.Object, forget func(issuerapi.Issuer)) error {
	inf, err := mgr.GetCache().GetInformer(ctx, obj)
	if err != nil {
		return fmt.Errorf("getting informer for %T: %w", obj, err)
	}

	_, err = inf.AddEventHandler(toolscache.ResourceEventHandlerFuncs{
		DeleteFunc: func(o any) {
			// A delete missed during a watch gap arrives wrapped.
			if tombstone, ok := o.(toolscache.DeletedFinalStateUnknown); ok {
				o = tombstone.Obj
			}

			if iss, ok := o.(issuerapi.Issuer); ok {
				forget(iss)
			}
		},
	})
	if err != nil {
		return fmt.Errorf("watching deletions of %T: %w", obj, err)
	}

	return nil
}
