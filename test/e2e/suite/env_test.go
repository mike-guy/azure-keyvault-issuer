//go:build e2e

package e2e

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// outputs are the per-run Terraform outputs the tests need.
type outputs struct {
	VaultURL               string
	ECCertificate          string
	RSACertificate         string
	SubordinateCertificate string
	SubordinateNoRoleCert  string
	TenantID               string
	AmbientClientID        string
	TenantClientID         string
	OIDCIssuerURL          string
	RunID                  string
	ACRLoginServer         string // Empty on kind.

	// FallbackClientID and FallbackObjectID are the Entra application the
	// client certificate and client secret scenarios sign in as: its client
	// ID, and the object ID Microsoft Graph addresses it by.
	FallbackClientID string
	FallbackObjectID string
}

// settings is everything the suite takes from its environment. The make
// targets set them, so a run needs nothing exported by hand.
type settings struct {
	outputs
	kubeconfig   string
	cluster      string // The kind cluster's name.
	imageArchive string // The ko tarball from 'make image'.
	imageTag     string
	// imageRepository is where the AKS job pushes the image: the run's
	// registry. It is empty on kind, which loads the tarball instead.
	imageRepository string
	chartDir        string
	workDir         string // Scratch directory for this run (test/e2e/.work).
	// approveAll makes cert-manager approve every ClusterIssuer by wildcard,
	// as a real install would, rather than only the names the scenarios use.
	// Only 'make e2e-deploy' sets it, so issuers made by hand get approved.
	approveAll bool
}

// loadSettings reads the environment and the Terraform outputs file.
func loadSettings() (settings, error) {
	s := settings{
		kubeconfig:   os.Getenv("KUBECONFIG"),
		cluster:      envOr("E2E_CLUSTER", "akvi-e2e"),
		imageArchive: os.Getenv("E2E_IMAGE_ARCHIVE"),
		imageTag:     envOr("E2E_IMAGE_TAG", "dev"),
		chartDir:     os.Getenv("E2E_CHART_DIR"),
		approveAll:   os.Getenv("E2E_APPROVE_ALL") != "",
	}

	for name, v := range map[string]string{
		"KUBECONFIG": s.kubeconfig, "E2E_IMAGE_ARCHIVE": s.imageArchive,
		"E2E_CHART_DIR": s.chartDir, "E2E_OUTPUTS": os.Getenv("E2E_OUTPUTS"),
	} {
		if v == "" {
			return settings{}, fmt.Errorf("%s is not set: run the tests with 'make test-e2e'", name)
		}
	}

	path := os.Getenv("E2E_OUTPUTS")
	s.workDir = filepath.Dir(path)

	raw, err := os.ReadFile(path)
	if err != nil {
		return settings{}, fmt.Errorf("reading Terraform outputs (run 'make e2e-up' first): %w", err)
	}

	var tf map[string]struct{ Value string }
	if err := json.Unmarshal(raw, &tf); err != nil {
		return settings{}, fmt.Errorf("parsing %s: %w", path, err)
	}

	s.outputs = outputs{
		VaultURL:               tf["vault_url"].Value,
		ECCertificate:          tf["ec_certificate_name"].Value,
		RSACertificate:         tf["rsa_certificate_name"].Value,
		SubordinateCertificate: tf["subordinate_certificate_name"].Value,
		SubordinateNoRoleCert:  tf["subordinate_norole_certificate_name"].Value,
		TenantID:               tf["tenant_id"].Value,
		AmbientClientID:        tf["ambient_client_id"].Value,
		TenantClientID:         tf["tenant_client_id"].Value,
		FallbackClientID:       tf["fallback_client_id"].Value,
		FallbackObjectID:       tf["fallback_application_object_id"].Value,
		OIDCIssuerURL:          tf["oidc_issuer_url"].Value,
		RunID:                  tf["run_id"].Value,
		ACRLoginServer:         tf["acr_login_server"].Value,
	}

	if s.ACRLoginServer != "" {
		s.imageRepository = s.ACRLoginServer + "/azure-keyvault-issuer"
	}

	for name, v := range map[string]string{
		"vault_url": s.VaultURL, "tenant_id": s.TenantID, "ambient_client_id": s.AmbientClientID,
		"tenant_client_id": s.TenantClientID, "ec_certificate_name": s.ECCertificate,
		"fallback_client_id": s.FallbackClientID, "fallback_application_object_id": s.FallbackObjectID,
	} {
		if v == "" {
			return settings{}, fmt.Errorf("Terraform output %q is empty in %s", name, path)
		}
	}

	return s, nil
}

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}

	return fallback
}
