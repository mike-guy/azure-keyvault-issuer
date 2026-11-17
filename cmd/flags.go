package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/util/validation"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	"github.com/mike-guy/azure-keyvault-issuer/internal/azure/clientopts"
	"github.com/mike-guy/azure-keyvault-issuer/internal/controllers"
)

// options holds everything the command line configures.
type options struct {
	clusterResourceNamespace string
	printVersion             bool
	metricsAddr              string
	secureMetrics            bool
	metricsCertPath          string
	metricsCertName          string
	metricsCertKey           string
	probeAddr                string
	enableLeaderElection     bool
	enableHTTP2              bool
	maxConcurrentReconciles  int
	azureMaxRetries          int
	azureTryTimeout          time.Duration
	reconcileTimeout         time.Duration
	caExpiryWarnThreshold    time.Duration
	warnOnExportableCAKey    bool
	zap                      zap.Options
}

// maxAzureRetries caps --azure-max-retries. Past this, backoff is at its ceiling
// and more attempts only hold a worker for longer.
const maxAzureRetries = 10

// maxAzureTryTimeout caps --azure-try-timeout. Key Vault calls finish in
// seconds, and a reconcile could otherwise hold a worker for up to
// (maxAzureRetries+1) x this.
const maxAzureTryTimeout = time.Minute

// maxReconcileTimeout caps --reconcile-timeout. A check or sign that takes
// longer is hung, not slow.
const maxReconcileTimeout = 10 * time.Minute

// maxCAExpiryWarnThreshold caps --ca-expiry-warning-threshold. A CA is rarely
// valid for longer, so a larger value would warn on every signing.
const maxCAExpiryWarnThreshold = 10 * 365 * 24 * time.Hour

// metricsDisabled is the --metrics-bind-address value that turns metrics off.
const metricsDisabled = "0"

// parseOptions parses and validates args, which must not include the program
// name.
func parseOptions(args []string) (options, error) {
	var opts options

	flags := flag.NewFlagSet("manager", flag.ContinueOnError)
	opts.bindFlags(flags)

	if err := flags.Parse(args); err != nil {
		return options{}, err
	}

	if err := opts.validate(); err != nil {
		// Logging is not set up yet, so print it where the flag package prints.
		_, _ = fmt.Fprintln(flags.Output(), err)
		return options{}, err
	}

	return opts, nil
}

// bindFlags registers every flag on flags, with its default.
func (o *options) bindFlags(flags *flag.FlagSet) {
	flags.StringVar(&o.clusterResourceNamespace, "cluster-resource-namespace", "",
		"The namespace in which a ClusterIssuer's Secrets and ServiceAccount are found. "+
			"Defaults to the namespace the controller runs in.")

	flags.BoolVar(&o.printVersion, "version", false, "Print version to stdout and exit.")

	flags.StringVar(&o.metricsAddr, "metrics-bind-address", metricsDisabled,
		"The address the metrics endpoint binds to. Use :8443 for HTTPS or :8080 for HTTP, "+
			"or leave as 0 to disable it. Must differ from --health-probe-bind-address.")

	flags.BoolVar(&o.secureMetrics, "metrics-secure", true,
		"Serve metrics over HTTPS, with authentication and authorization. Use --metrics-secure=false for HTTP.")

	flags.StringVar(&o.metricsCertPath, "metrics-cert-path", "",
		"The directory holding the certificate and key that the metrics endpoint serves. "+
			"Leave empty to serve a self-signed certificate. The files are reloaded when they change.")

	flags.StringVar(&o.metricsCertName, "metrics-cert-name", "tls.crt",
		"The name of the metrics certificate file in --metrics-cert-path.")

	flags.StringVar(&o.metricsCertKey, "metrics-cert-key", "tls.key",
		"The name of the metrics key file in --metrics-cert-path.")

	flags.StringVar(&o.probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")

	flags.BoolVar(&o.enableLeaderElection, "leader-elect", true,
		"Enable leader election, so that only one replica reconciles at a time. It needs to run in a cluster, "+
			"so use --leader-elect=false to run the controller on your own machine.")

	flags.BoolVar(&o.enableHTTP2, "enable-http2", false, "Enable HTTP/2 for the metrics server.")

	flags.IntVar(&o.maxConcurrentReconciles, "max-concurrent-reconciles", controllers.DefaultMaxConcurrentReconciles,
		"How many objects each controller reconciles at once. Must be at least 1.")

	flags.IntVar(&o.azureMaxRetries, "azure-max-retries", clientopts.DefaultMaxRetries,
		fmt.Sprintf("How many times a failed Azure request is retried, for example when throttled. "+
			"0 disables retries. At most %d.", maxAzureRetries))

	flags.DurationVar(&o.azureTryTimeout, "azure-try-timeout", clientopts.DefaultTryTimeout,
		"How long a single Azure request attempt may take. It applies to each retry, so one request can take "+
			"about (retries+1) x this, plus backoff, and a reconcile holds a worker for all of it, up to "+
			"the limit of --reconcile-timeout. "+
			fmt.Sprintf("Must be positive and at most %s.", maxAzureTryTimeout))

	flags.DurationVar(&o.reconcileTimeout, "reconcile-timeout", controllers.DefaultReconcileTimeout,
		"The longest a single issuer check or certificate signing may take, in total: reading the credential's "+
			"Secret, requesting a token and every Key Vault call, including their retries. It also stops a hung "+
			"Kubernetes API server from holding a worker for good. "+
			fmt.Sprintf("Must be positive and at most %s.", maxReconcileTimeout))

	flags.DurationVar(&o.caExpiryWarnThreshold, "ca-expiry-warning-threshold", controllers.DefaultCAExpiryWarningThreshold,
		"How close to expiry the CA chain must be for the controller to record a CAExpiring warning event on the "+
			"issuer when it signs a certificate. Go durations have no day unit, so 90 days is 2160h. "+
			fmt.Sprintf("Must be positive and at most %s.", maxCAExpiryWarnThreshold))

	flags.BoolVar(&o.warnOnExportableCAKey, "warn-on-exportable-ca-key", controllers.DefaultWarnOnExportableCAKey,
		"Record a CAKeyExportable warning event on an issuer whose CA private key can be exported from Key Vault. "+
			"It only affects the event, never issuance. The key is judged from the certificate's policy, and from "+
			"the backing secret when the issuer reads the chain from it. No event means no evidence, not that "+
			"the key is safe. Use --warn-on-exportable-ca-key=false to turn it off.")

	o.zap.BindFlags(flags)
}

// validate checks the rules that a flag's type cannot.
func (o *options) validate() error {
	if o.clusterResourceNamespace != "" {
		if problems := validation.IsDNS1123Label(o.clusterResourceNamespace); len(problems) > 0 {
			return fmt.Errorf("--cluster-resource-namespace %q is not a valid namespace name: %s",
				o.clusterResourceNamespace, strings.Join(problems, "; "))
		}
	}

	// controller-runtime only passes the addresses to net.Listen, which fails late
	// and without naming the flag.
	var metricsPort string
	if o.metricsAddr != metricsDisabled {
		var err error
		if _, metricsPort, err = parseBindAddress(o.metricsAddr); err != nil {
			return fmt.Errorf("--metrics-bind-address: %w", err)
		}
	}

	if err := o.validateMetricsCert(); err != nil {
		return err
	}

	probeHost, probePort, err := parseBindAddress(o.probeAddr)
	if err != nil {
		return fmt.Errorf("--health-probe-bind-address: %w", err)
	}

	if metricsPort == probePort {
		// The same port on different hosts could work, but in a cluster both bind
		// to every address.
		metricsHost, _, _ := net.SplitHostPort(o.metricsAddr)
		if metricsHost == probeHost || metricsHost == "" || probeHost == "" {
			return fmt.Errorf("--metrics-bind-address and --health-probe-bind-address both use port %s", probePort)
		}
	}

	if o.maxConcurrentReconciles < 1 {
		return fmt.Errorf("--max-concurrent-reconciles must be at least 1, got %d", o.maxConcurrentReconciles)
	}

	if o.azureMaxRetries < 0 || o.azureMaxRetries > maxAzureRetries {
		return fmt.Errorf("--azure-max-retries must be between 0 and %d, got %d", maxAzureRetries, o.azureMaxRetries)
	}

	// The SDK reads zero as no timeout, so a hung connection would hold a worker
	// for good.
	if o.azureTryTimeout <= 0 || o.azureTryTimeout > maxAzureTryTimeout {
		return fmt.Errorf("--azure-try-timeout must be positive and at most %s, got %s", maxAzureTryTimeout, o.azureTryTimeout)
	}

	if o.reconcileTimeout <= 0 || o.reconcileTimeout > maxReconcileTimeout {
		return fmt.Errorf("--reconcile-timeout must be positive and at most %s, got %s", maxReconcileTimeout, o.reconcileTimeout)
	}

	if o.caExpiryWarnThreshold <= 0 || o.caExpiryWarnThreshold > maxCAExpiryWarnThreshold {
		return fmt.Errorf("--ca-expiry-warning-threshold must be positive and at most %s, got %s", maxCAExpiryWarnThreshold, o.caExpiryWarnThreshold)
	}

	return nil
}

// validateMetricsCert checks --metrics-cert-path and the names of its files.
// controller-runtime serves a self-signed certificate when it cannot find them,
// so a wrong path would go unnoticed until a scraper failed to verify it.
func (o *options) validateMetricsCert() error {
	if o.metricsCertPath == "" {
		return nil
	}

	if o.metricsAddr == metricsDisabled {
		return errors.New("--metrics-cert-path needs --metrics-bind-address, because metrics are disabled")
	}

	if !o.secureMetrics {
		return errors.New("--metrics-cert-path needs --metrics-secure=true, because plain HTTP has no certificate")
	}

	for _, f := range []struct{ flag, name string }{
		{flag: "--metrics-cert-name", name: o.metricsCertName},
		{flag: "--metrics-cert-key", name: o.metricsCertKey},
	} {
		if f.name == "" {
			return fmt.Errorf("%s must not be empty", f.flag)
		}

		if _, err := os.Stat(filepath.Join(o.metricsCertPath, f.name)); err != nil {
			return fmt.Errorf("%s: %w", f.flag, err)
		}
	}

	return nil
}

// parseBindAddress splits addr, which must be host:port with a port from 1 to
// 65535. The host may be empty.
func parseBindAddress(addr string) (host, port string, err error) {
	host, port, err = net.SplitHostPort(addr)
	if err != nil {
		return "", "", fmt.Errorf("%q must be host:port, such as :8080: %w", addr, err)
	}

	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return "", "", fmt.Errorf("%q has port %q, which must be a number from 1 to 65535", addr, port)
	}

	return host, port, nil
}

// isHelp reports whether err is from asking for --help, which is not a failure.
func isHelp(err error) bool {
	return errors.Is(err, flag.ErrHelp)
}
