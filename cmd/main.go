// Command main runs the Azure Key Vault external issuer for cert-manager.
package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"

	"github.com/KimMachineGun/automemlimit/memlimit"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/metrics/filters"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	api "github.com/mike-guy/azure-keyvault-issuer/api/v1alpha1"
	"github.com/mike-guy/azure-keyvault-issuer/internal/azure/clientopts"
	"github.com/mike-guy/azure-keyvault-issuer/internal/azure/credential"
	"github.com/mike-guy/azure-keyvault-issuer/internal/azure/sdklog"
	"github.com/mike-guy/azure-keyvault-issuer/internal/controllers"
	"github.com/mike-guy/azure-keyvault-issuer/internal/kubernetes"
)

// inClusterNamespacePath is where Kubernetes mounts the namespace a pod runs in.
const inClusterNamespacePath = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"

// version is set at build time, with -ldflags "-X=main.version=<version>".
// It is "dev" for a build that does not set it.
var version = "dev"

var scheme = runtime.NewScheme()

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(cmapi.AddToScheme(scheme))
	utilruntime.Must(api.AddToScheme(scheme))
}

func main() {
	if err := run(); err != nil {
		os.Exit(1)
	}
}

// run does everything main does, so that a failure is logged where it happens
// and returned rather than exiting mid-setup. An error is logged by the time
// it is returned.
func run() error {
	opts, err := parseOptions(os.Args[1:])
	if isHelp(err) {
		return nil
	}

	if err != nil {
		return err
	}

	if opts.printVersion {
		fmt.Println(version)
		return nil
	}

	logger := zap.New(zap.UseFlagOptions(&opts.zap))
	ctrl.SetLogger(logger)
	klog.SetLogger(logger)

	// Before any Azure client is built: the SDK's listener is a global.
	sdklog.Bridge(logger.WithName("azure-sdk"))

	setupLog := ctrl.Log.WithName("setup")

	// The Go runtime ignores the container's memory limit and would be
	// OOM-killed past it. GOMEMLIMIT, if set, takes precedence, and AUTOMEMLIMIT
	// changes the ratio from its default 0.9.
	if limit, err := memlimit.Set(); err != nil {
		setupLog.Error(err, "unable to set the Go memory limit from the container's, continuing without one")
	} else {
		setupLog.Info("set the Go memory limit", "bytes", limit)
	}

	namespace, err := resolveClusterResourceNamespace(opts.clusterResourceNamespace, inClusterNamespacePath)
	if err != nil {
		setupLog.Error(err, "unable to find the cluster resource namespace")
		return err
	}

	// HTTP/2 is off by default, as in the Kubebuilder scaffold. The metrics
	// endpoint serves few clients and gains nothing from multiplexing, so this
	// removes attack surface. Stream Cancellation and Rapid Reset are already
	// fixed (Go 1.21.3, golang.org/x/net 0.17.0), but this guards against flaws
	// not yet found:
	// - https://github.com/advisories/GHSA-qppj-fm5r-hxr3
	// - https://github.com/advisories/GHSA-4374-p667-p6c8
	var tlsOpts []func(*tls.Config)
	if !opts.enableHTTP2 {
		tlsOpts = append(tlsOpts, func(c *tls.Config) {
			c.NextProtos = []string{"http/1.1"}
		})
	}

	// With no certificate path, controller-runtime serves a self-signed
	// certificate. With one it serves the files and reloads them when they
	// change. parseOptions has checked they exist, as controller-runtime would
	// otherwise fall back to the self-signed one silently.
	metricsOpts := metricsserver.Options{
		BindAddress:   opts.metricsAddr,
		SecureServing: opts.secureMetrics,
		CertDir:       opts.metricsCertPath,
		CertName:      opts.metricsCertName,
		KeyName:       opts.metricsCertKey,
		TLSOpts:       tlsOpts,
	}
	if opts.secureMetrics {
		// Needs tokenreviews and subjectaccessreviews RBAC.
		metricsOpts.FilterProvider = filters.WithAuthenticationAndAuthorization
	}

	restConfig, err := ctrl.GetConfig()
	if err != nil {
		setupLog.Error(err, "unable to load the Kubernetes client configuration")
		return err
	}

	mgr, err := ctrl.NewManager(restConfig, ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsOpts,
		HealthProbeBindAddress: opts.probeAddr,
		LeaderElection:         opts.enableLeaderElection,
		LeaderElectionID:       api.GroupName,
		// Safe because run returns as soon as the manager stops, so nothing
		// else runs while the lease is released.
		LeaderElectionReleaseOnCancel: true,
		Cache: cache.Options{
			// Saves memory, as the cache holds every CertificateRequest and
			// issuer in the cluster.
			DefaultTransform: cache.TransformStripManagedFields(),
		},
		Client: client.Options{
			Cache: &client.CacheOptions{
				// Secrets are read through the API reader. This makes sure that
				// nothing starts an informer that would hold every Secret in the cluster.
				DisableFor: []client.Object{&corev1.Secret{}},
			},
		},
	})
	if err != nil {
		setupLog.Error(err, "unable to create the manager")
		return err
	}

	secrets, err := kubernetes.NewSecretFetcher(mgr.GetAPIReader())
	if err != nil {
		setupLog.Error(err, "unable to create the secret fetcher")
		return err
	}

	tokens, err := kubernetes.NewTokenRequester(mgr.GetClient())
	if err != nil {
		setupLog.Error(err, "unable to create the token requester")
		return err
	}

	azureOpts := clientopts.New()
	if err := clientopts.SetRetry(&azureOpts, opts.azureMaxRetries, opts.azureTryTimeout); err != nil {
		setupLog.Error(err, "unable to set the Azure retry options")
		return err
	}

	credentials, err := credential.NewBuilder(secrets, tokens, &azureOpts)
	if err != nil {
		setupLog.Error(err, "unable to create the credential builder")
		return err
	}

	keyVaultSigner, err := controllers.NewKeyVaultSigner(
		credentials,
		controllers.NewVaultAuthorityFactory(&azureOpts),
		mgr.GetEventRecorder(controllers.DefaultFieldOwner),
		namespace,
		controllers.SignerOptions{
			ReconcileTimeout:      opts.reconcileTimeout,
			CAExpiryWarnThreshold: opts.caExpiryWarnThreshold,
			WarnOnExportableCAKey: opts.warnOnExportableCAKey,
		})
	if err != nil {
		setupLog.Error(err, "unable to create the signer")
		return err
	}

	ctx := ctrl.SetupSignalHandler()

	if err := controllers.SetupWithManager(ctx, mgr, keyVaultSigner, controllers.SetupOptions{
		FieldOwner:              controllers.DefaultFieldOwner,
		MaxRetryDuration:        controllers.DefaultMaxRetryDuration,
		MaxConcurrentReconciles: opts.maxConcurrentReconciles,
	}); err != nil {
		setupLog.Error(err, "unable to set up the controllers")
		return err
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up the health check")
		return err
	}

	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up the ready check")
		return err
	}

	setupLog.Info("starting manager",
		"version", version,
		"leaderElection", opts.enableLeaderElection,
		"metricsAddress", opts.metricsAddr,
		"metricsCertPath", opts.metricsCertPath,
		"clusterResourceNamespace", namespace,
		"azureMaxRetries", opts.azureMaxRetries,
		"azureTryTimeout", opts.azureTryTimeout,
		"reconcileTimeout", opts.reconcileTimeout,
		"caExpiryWarnThreshold", opts.caExpiryWarnThreshold,
		"warnOnExportableCAKey", opts.warnOnExportableCAKey)

	if err := mgr.Start(ctx); err != nil {
		setupLog.Error(err, "problem running the manager")
		return err
	}

	return nil
}

// resolveClusterResourceNamespace returns flagValue if set, and otherwise the
// namespace the pod runs in, read from namespacePath. That file is missing when
// running outside a cluster, so the flag is then required.
func resolveClusterResourceNamespace(flagValue, namespacePath string) (string, error) {
	if flagValue != "" {
		return flagValue, nil
	}

	b, err := os.ReadFile(namespacePath)
	if errors.Is(err, fs.ErrNotExist) {
		return "", fmt.Errorf("could not detect the pod namespace (%s not found), so --cluster-resource-namespace must be set", namespacePath)
	}

	if err != nil {
		return "", fmt.Errorf("reading namespace file: %w", err)
	}

	return strings.TrimSpace(string(b)), nil
}
