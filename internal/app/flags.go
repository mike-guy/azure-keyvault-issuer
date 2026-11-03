package app

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"github.com/mike-guy/azure-keyvault-issuer/internal/credential"
	"github.com/mike-guy/azure-keyvault-issuer/internal/keyvault"
)

// config is the controller's configuration from its flags, completed from
// the environment by readEnv.
type config struct {
	showVersion bool
	logLevel    slog.Level

	clusterResourceNamespace string
	clusterIssuerAmbient     bool
	issuerAmbient            bool
	defaultTenantID          string
	allowedVaults            []keyvault.VaultURL

	maxRetryDuration  time.Duration
	concurrentWorkers int

	// signCertificateSigningRequests also signs Kubernetes
	// CertificateSigningRequests (certificates.k8s.io) addressed to a
	// ClusterIssuer, not just cert-manager CertificateRequests.
	signCertificateSigningRequests bool

	// ambient is the controller's own workload identity, read from the
	// environment by readEnv. Nil means it has none.
	ambient *credential.AmbientConfig

	metricsAddr string
	// metricsCertPath is a directory holding tls.crt and tls.key for the
	// metrics endpoint. Empty, or missing files, means a self-signed
	// certificate.
	metricsCertPath         string
	probeAddr               string
	leaderElect             bool
	leaderElectionNamespace string
	shutdownTimeout         time.Duration
}

// parseArgs parses args. It returns flag.ErrHelp for -h or --help, after
// printing the usage to stderr.
func parseArgs(args []string, stderr io.Writer) (config, error) {
	c := config{logLevel: slog.LevelInfo}

	fs := flag.NewFlagSet("azure-keyvault-issuer", flag.ContinueOnError)
	fs.SetOutput(stderr)

	fs.BoolVar(&c.showVersion, "version", false, "print the version and exit")
	fs.TextVar(&c.logLevel, "log-level", slog.LevelInfo, "log level: debug, info, warn or error")

	fs.StringVar(&c.clusterResourceNamespace, "cluster-resource-namespace", "",
		"namespace in which ClusterIssuer ServiceAccount references resolve (default: the controller's own namespace)")
	fs.BoolVar(&c.clusterIssuerAmbient, "cluster-issuer-ambient-credentials", true,
		"let ClusterIssuers with no auth method use the controller's own workload identity")
	fs.BoolVar(&c.issuerAmbient, "issuer-ambient-credentials", false,
		"let namespaced Issuers with no auth method use the controller's own workload identity")
	fs.StringVar(&c.defaultTenantID, "default-tenant-id", "",
		"Entra tenant ID for workload identities that set none (default: AZURE_TENANT_ID)")
	fs.Func("issuer-allowed-vaults",
		"comma-separated Key Vault URLs that namespaced Issuers may use (default: any)",
		func(s string) error {
			vaults, err := parseVaults(s)
			if err != nil {
				return err
			}

			c.allowedVaults = append(c.allowedVaults, vaults...)

			return nil
		})

	fs.DurationVar(&c.maxRetryDuration, "max-retry-duration", 5*time.Minute,
		"how long a CertificateRequest is retried after transient errors before it is failed")
	fs.IntVar(&c.concurrentWorkers, "concurrent-workers", 5,
		"how many requests, and how many issuers, each controller reconciles at once")
	fs.BoolVar(&c.signCertificateSigningRequests, "sign-certificatesigningrequests", false,
		"also sign Kubernetes CertificateSigningRequests (certificates.k8s.io) whose signer name is a ClusterIssuer")

	fs.StringVar(&c.metricsAddr, "metrics-bind-address", ":8443", "address of the HTTPS metrics endpoint; 0 disables it")
	fs.StringVar(&c.metricsCertPath, "metrics-cert-path", "",
		"directory holding tls.crt and tls.key for the metrics endpoint, read at start-up (default: a self-signed certificate)")
	fs.StringVar(&c.probeAddr, "health-probe-bind-address", ":8081", "address of the health and readiness probes")
	fs.BoolVar(&c.leaderElect, "leader-elect", true, "elect a leader, so only one replica reconciles at a time")
	fs.StringVar(&c.leaderElectionNamespace, "leader-election-namespace", "",
		"namespace of the leader election lease (default: the cluster resource namespace)")
	fs.DurationVar(&c.shutdownTimeout, "graceful-shutdown-timeout", 30*time.Second,
		"how long to wait for in-flight work when stopping")

	if err := fs.Parse(args); err != nil {
		return config{}, err
	}

	if fs.NArg() > 0 {
		return config{}, usageError(fs, fmt.Errorf("unexpected argument %q", fs.Arg(0)))
	}

	if c.maxRetryDuration <= 0 {
		return config{}, usageError(fs, errors.New("--max-retry-duration must be positive"))
	}

	if c.concurrentWorkers < 1 {
		return config{}, usageError(fs, errors.New("--concurrent-workers must be at least 1"))
	}

	if c.shutdownTimeout < 0 {
		return config{}, usageError(fs, errors.New("--graceful-shutdown-timeout must not be negative"))
	}

	return c, nil
}

// usageError prints err and the usage, as the flag package does for a bad
// flag, and returns err.
func usageError(fs *flag.FlagSet, err error) error {
	_, _ = fmt.Fprintln(fs.Output(), err)
	fs.Usage()

	return err
}

// parseVaults parses a comma-separated list of vault URLs.
func parseVaults(s string) ([]keyvault.VaultURL, error) {
	var vaults []keyvault.VaultURL

	for raw := range strings.SplitSeq(s, ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}

		v, err := keyvault.ParseVaultURL(raw)
		if err != nil {
			return nil, fmt.Errorf("%q: %w", raw, err)
		}

		vaults = append(vaults, v)
	}

	if len(vaults) == 0 {
		return nil, errors.New("no vault URLs given")
	}

	return vaults, nil
}
