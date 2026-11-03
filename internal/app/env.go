package app

import (
	"cmp"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/mike-guy/azure-keyvault-issuer/internal/credential"
)

// Environment variables the controller reads. The chart sets POD_NAMESPACE and
// MEMORY_LIMIT_BYTES through the downward API. The AZURE_* variables are those the Azure
// workload identity webhook sets, and the chart sets them itself when it
// projects the token without the webhook.
const (
	envPodNamespace = "POD_NAMESPACE"
	envMemoryLimit  = "MEMORY_LIMIT_BYTES"
	envGoMemLimit   = "GOMEMLIMIT"
	envClientID     = "AZURE_CLIENT_ID"
	envTenantID     = "AZURE_TENANT_ID"
	envTokenFile    = "AZURE_FEDERATED_TOKEN_FILE"
)

// serviceAccountNamespaceFile holds the pod's namespace when the
// ServiceAccount token is mounted.
const serviceAccountNamespaceFile = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"

// environment is how readEnv reads the process environment, so tests can
// replace it.
type environment struct {
	getenv   func(string) string
	readFile func(string) ([]byte, error)
}

// readEnv completes c from the environment after parseArgs: the namespaces
// left unset, the controller's ambient workload identity (nil if it has
// none), and the default tenant.
//
// The environment is read only here, so the credential and issuer packages
// never read it themselves.
func readEnv(c *config, env environment) error {
	if c.clusterResourceNamespace == "" {
		ns, err := podNamespace(env)
		if err != nil {
			return err
		}

		c.clusterResourceNamespace = ns
	}

	c.leaderElectionNamespace = cmp.Or(c.leaderElectionNamespace, c.clusterResourceNamespace)

	ambient, err := ambientIdentity(env)
	if err != nil {
		return err
	}

	c.ambient = ambient

	if ambient != nil {
		c.defaultTenantID = cmp.Or(c.defaultTenantID, ambient.TenantID)
	}

	return nil
}

// memoryLimit returns the soft memory limit for the Go runtime: 90% of the
// container's limit, leaving headroom for memory the runtime doesn't manage.
// It returns 0, meaning leave the runtime's default, when GOMEMLIMIT is set
// explicitly or the container limit is missing or invalid.
func memoryLimit(env environment) int64 {
	if env.getenv(envGoMemLimit) != "" {
		return 0
	}

	limit, err := strconv.ParseInt(env.getenv(envMemoryLimit), 10, 64)
	if err != nil || limit <= 0 {
		return 0
	}

	return limit / 10 * 9
}

// ambientIdentity reads the controller's own workload identity from the
// AZURE_* variables. It returns nil when none is set.
func ambientIdentity(env environment) (*credential.AmbientConfig, error) {
	ambient := &credential.AmbientConfig{
		ClientID:  env.getenv(envClientID),
		TenantID:  env.getenv(envTenantID),
		TokenFile: env.getenv(envTokenFile),
	}

	switch countSet(ambient.ClientID, ambient.TenantID, ambient.TokenFile) {
	case 0:
		return nil, nil //nolint:nilnil // no ambient identity is a valid configuration.
	case 3:
		return ambient, nil
	default:
		// A half-configured identity is a deployment mistake. Failing at
		// start-up shows it at once, rather than at the first issuance.
		return nil, fmt.Errorf("ambient workload identity: %s, %s and %s must all be set, or none", envClientID, envTenantID, envTokenFile)
	}
}

// podNamespace returns the controller's own namespace.
func podNamespace(env environment) (string, error) {
	if ns := env.getenv(envPodNamespace); ns != "" {
		return ns, nil
	}

	if b, err := env.readFile(serviceAccountNamespaceFile); err == nil {
		if ns := strings.TrimSpace(string(b)); ns != "" {
			return ns, nil
		}
	}

	return "", errors.New("cannot tell the controller's namespace: set --cluster-resource-namespace or " + envPodNamespace)
}

func countSet(values ...string) int {
	n := 0

	for _, v := range values {
		if v != "" {
			n++
		}
	}

	return n
}
