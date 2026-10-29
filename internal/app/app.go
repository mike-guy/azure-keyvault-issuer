package app

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"runtime/debug"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	issuerapi "github.com/cert-manager/issuer-lib/api/v1alpha1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/mike-guy/azure-keyvault-issuer/internal/azure"
	"github.com/mike-guy/azure-keyvault-issuer/internal/credential"
	"github.com/mike-guy/azure-keyvault-issuer/internal/issuer"
	"github.com/mike-guy/azure-keyvault-issuer/internal/keyvault"
)

// Exit codes returned by Run.
const (
	exitOK    = 0
	exitError = 1
	exitUsage = 2
)

// Run runs the controller until ctx is cancelled and returns the process exit
// code. version is printed by --version and logged at start-up.
//
// The Kubernetes API server is found as client-go does: the KUBECONFIG
// variable or ~/.kube/config outside a cluster, and the pod's ServiceAccount
// inside one.
func Run(ctx context.Context, args []string, stdout, stderr io.Writer, version string) int {
	c, err := parseArgs(args, stderr)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}

		return exitUsage
	}

	if c.showVersion {
		_, _ = fmt.Fprintln(stdout, version)

		return exitOK
	}

	logger := newLogger(stderr, c.logLevel)
	installLoggers(logger, c.logLevel)

	if err := run(ctx, logger, c, version); err != nil {
		logger.With("component", "app").ErrorContext(ctx, "controller failed", "error", err)

		return exitError
	}

	return exitOK
}

// run builds every dependency and runs the manager until ctx is cancelled.
// logger is the root logger: each component adds its own component attribute,
// so only run's own lines use appLogger.
func run(ctx context.Context, logger *slog.Logger, c config, version string) error {
	appLogger := logger.With("component", "app")
	env := environment{getenv: os.Getenv, readFile: os.ReadFile}

	if err := readEnv(&c, env); err != nil {
		return err
	}

	if limit := memoryLimit(env); limit > 0 {
		debug.SetMemoryLimit(limit)
		appLogger.DebugContext(ctx, "set the Go memory limit", "bytes", limit)
	}

	appLogger.InfoContext(ctx, "starting",
		"version", version,
		"clusterResourceNamespace", c.clusterResourceNamespace,
		"clusterIssuerAmbientCredentials", c.clusterIssuerAmbient,
		"issuerAmbientCredentials", c.issuerAmbient,
		"ambientIdentity", c.ambient != nil,
		"allowedVaults", len(c.allowedVaults),
		"signCertificateSigningRequests", c.signCertificateSigningRequests,
		"leaderElect", c.leaderElect)

	if c.metricsAddr != "0" {
		c.metricsCertPath = usableMetricsCertPath(ctx, appLogger, c.metricsCertPath)
	}

	cfg, err := ctrl.GetConfig()
	if err != nil {
		return fmt.Errorf("loading Kubernetes client configuration: %w", err)
	}

	scheme, err := newScheme()
	if err != nil {
		return err
	}

	requests := azure.NewRequestMetrics()
	fetcher := keyvault.NewCAFetcher(keyvault.Options{Logger: logger, Metrics: requests})

	mgr, err := wire(ctx, cfg, scheme, c, logger, fetcher, requests, nil)
	if err != nil {
		return err
	}

	if err := mgr.Start(ctx); err != nil {
		return fmt.Errorf("running manager: %w", err)
	}

	appLogger.InfoContext(ctx, "stopped")

	return nil
}

// caFetcher is what wire needs from keyvault.CAFetcher, so the envtest suite
// can pass a fake vault.
type caFetcher interface {
	Fetch(ctx context.Context, cred azcore.TokenCredential, src keyvault.CASource) (*keyvault.CA, error)
}

// wire builds the manager, the credential provider and the issuer, registers
// the controllers, and registers the metrics with controller-runtime's
// registry, which the manager serves. run and the envtest suite share it, so
// the suite tests the real wiring. requests records the Azure requests of the
// credential provider, and should be the one fetcher records into.
// onForget, if not nil, is also told about each deleted issuer; production
// passes nil.
func wire(ctx context.Context, cfg *rest.Config, scheme *runtime.Scheme, c config, logger *slog.Logger,
	fetcher caFetcher, requests *azure.RequestMetrics, onForget func(types.UID),
) (ctrl.Manager, error) {
	mgr, err := newManager(cfg, scheme, c)
	if err != nil {
		return nil, err
	}

	if err := metrics.Registry.Register(requests); err != nil {
		return nil, fmt.Errorf("registering Azure request metrics: %w", err)
	}

	credClient, err := newCredentialClient(cfg, scheme)
	if err != nil {
		return nil, err
	}

	creds, err := credential.NewProvider(credential.Options{
		Logger:                          logger,
		Metrics:                         requests,
		TokenClient:                     credClient,
		SecretReader:                    credClient,
		ClusterResourceNamespace:        c.clusterResourceNamespace,
		DefaultTenantID:                 c.defaultTenantID,
		Ambient:                         c.ambient,
		ClusterIssuerAmbientCredentials: c.clusterIssuerAmbient,
		IssuerAmbientCredentials:        c.issuerAmbient,
	})
	if err != nil {
		return nil, fmt.Errorf("creating credential provider: %w", err)
	}

	iss := issuer.New(creds, fetcher, issuerOptions(logger, mgr.GetEventRecorder(fieldOwner), c))

	if err := metrics.Registry.Register(iss.Metrics()); err != nil {
		return nil, fmt.Errorf("registering issuer metrics: %w", err)
	}

	forget := iss.Forget
	if onForget != nil {
		forget = func(deleted issuerapi.Issuer) {
			iss.Forget(deleted)
			onForget(deleted.GetUID())
		}
	}

	if err := setupControllers(ctx, mgr, iss, c, forget); err != nil {
		return nil, err
	}

	return mgr, nil
}

// issuerOptions returns the issuer's options. The credential errors listed as
// invalid-spec errors are those only an edit to the issuer can fix; the
// others depend on the controller's flags, so they are retried. An unknown
// issuer type never reaches the credential provider, because the issuer
// rejects it first.
func issuerOptions(logger *slog.Logger, events events.EventRecorder, c config) issuer.Options {
	return issuer.Options{
		Logger:            logger,
		Events:            events,
		AllowedVaults:     c.allowedVaults,
		InvalidSpecErrors: []error{credential.ErrInvalidAuth},
	}
}
