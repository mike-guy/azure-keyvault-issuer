//go:build e2e

package e2e

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azcertificates"
)

// hierarchy is the throwaway root and intermediate that sign the Key Vault CAs.
// Its keys are saved with the certificates in the git-ignored work directory,
// so a setup that failed part-way can sign the remaining CAs under the same
// root.
type hierarchy struct {
	root         *x509.Certificate
	intermediate *x509.Certificate
}

// pendingCAs says how each pending Key Vault certificate is signed: directly
// by the root (two tiers) or by the intermediate (three tiers).
func pendingCAs(o outputs) map[string]bool {
	return map[string]bool{
		o.ECCertificate:          false,
		o.RSACertificate:         false,
		o.SubordinateCertificate: true,
		o.SubordinateNoRoleCert:  true,
	}
}

// setupCAs signs and merges every pending CA, as an organisation's PKI would
// (docs: CA provisioning). Key Vault generates the keys and CSRs, so the CA
// keys never leave it. It returns only the root: specs verify issued chains
// against it alone, so a chain that leaves out the intermediate fails.
//
// Re-running against an environment whose CAs are already merged reuses the
// public certificates saved by the first run.
func setupCAs(ctx context.Context, cred azcore.TokenCredential, s settings) (*x509.Certificate, error) {
	client, err := azcertificates.NewClient(s.VaultURL, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("creating certificates client: %w", err)
	}

	pending := map[string]bool{} // Name to three-tier.
	csrs := map[string]*x509.CertificateRequest{}

	for name, threeTier := range pendingCAs(s.outputs) {
		csr, isPending, err := pendingCSR(ctx, client, name)
		if err != nil {
			return nil, err
		}

		if isPending {
			pending[name], csrs[name] = threeTier, csr
		}
	}

	saved := filepath.Join(s.workDir, "pki")

	if len(pending) == 0 {
		h, err := loadCertificates(saved)

		return h.root, err
	}

	// Reuse the hierarchy of an earlier run that failed part-way, so the CAs it
	// merged still chain to the root the tests verify against. A new hierarchy
	// is saved before any merge for the same reason.
	h, rootKey, intKey, err := loadHierarchy(saved)
	if errors.Is(err, fs.ErrNotExist) {
		if rootKey, intKey, h, err = newHierarchy(); err == nil {
			err = saveHierarchy(saved, h, rootKey, intKey)
		}
	}

	if err != nil {
		return nil, err
	}

	for name, threeTier := range pending {
		parent, parentKey, chain := h.root, rootKey, []*x509.Certificate{h.root}
		if threeTier {
			parent, parentKey, chain = h.intermediate, intKey, []*x509.Certificate{h.intermediate, h.root}
		}

		leaf, err := signCA(csrs[name], parent, parentKey)
		if err != nil {
			return nil, fmt.Errorf("signing %s: %w", name, err)
		}

		der := [][]byte{leaf.Raw}
		for _, c := range chain {
			der = append(der, c.Raw)
		}

		if _, err := client.MergeCertificate(ctx, name, azcertificates.MergeCertificateParameters{X509Certificates: der}, nil); err != nil {
			return nil, fmt.Errorf("merging %s: %w", name, err)
		}
	}

	return h.root, nil
}

// pendingCSR returns the CSR of a pending certificate, or false if the
// certificate is already merged. It retries while the account's role
// assignment propagates.
func pendingCSR(ctx context.Context, client *azcertificates.Client, name string) (*x509.CertificateRequest, bool, error) {
	deadline := time.Now().Add(5 * time.Minute)

	for {
		op, err := client.GetCertificateOperation(ctx, name, nil)

		var respErr *azcore.ResponseError

		switch {
		case err == nil && op.Status != nil && *op.Status == "completed":
			return nil, false, nil // Merged; the operation keeps its CSR.
		case err == nil && len(op.CSR) > 0:
			csr, err := x509.ParseCertificateRequest(op.CSR)
			if err != nil {
				return nil, false, fmt.Errorf("parsing CSR of %s: %w", name, err)
			}

			return csr, true, nil
		case err == nil:
			return nil, false, nil
		case errors.As(err, &respErr) && respErr.StatusCode == http.StatusNotFound:
			return nil, false, nil // Merged: the operation is gone.
		case time.Now().After(deadline) || ctx.Err() != nil:
			return nil, false, fmt.Errorf("reading the pending operation of %s: %w", name, err)
		}

		// Most likely a 403 while the Key Vault Certificates Officer role
		// propagates.
		select {
		case <-ctx.Done():
			return nil, false, ctx.Err()
		case <-time.After(10 * time.Second):
		}
	}
}

func newHierarchy() (rootKey, intKey *ecdsa.PrivateKey, h hierarchy, err error) {
	if rootKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		return nil, nil, hierarchy{}, err
	}

	if intKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		return nil, nil, hierarchy{}, err
	}

	// The root allows two CAs below it (the intermediate and the Key Vault CA).
	h.root, err = issueCA("akvi e2e root", &rootKey.PublicKey, nil, rootKey, 2)
	if err != nil {
		return nil, nil, hierarchy{}, err
	}

	h.intermediate, err = issueCA("akvi e2e intermediate", &intKey.PublicKey, h.root, rootKey, 1)
	if err != nil {
		return nil, nil, hierarchy{}, err
	}

	return rootKey, intKey, h, nil
}

// signCA signs a Key Vault CSR as a CA with path length 0, so the Key Vault CA
// can only issue end-entity certificates.
func signCA(csr *x509.CertificateRequest, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, error) {
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("checking CSR signature: %w", err)
	}

	return issueCA(csr.Subject.CommonName, csr.PublicKey, parent, parentKey, 0)
}

// issueCA creates a CA certificate for pub. A nil parent makes it self-signed.
func issueCA(cn string, pub any, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, pathLen int) (*x509.Certificate, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	if err != nil {
		return nil, err
	}

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(90 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            pathLen,
		MaxPathLenZero:        pathLen == 0,
	}

	if parent == nil {
		parent = tmpl
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, parentKey)
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(der)
}

func saveHierarchy(dir string, h hierarchy, rootKey, intKey *ecdsa.PrivateKey) error {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}

	blocks := map[string]*pem.Block{
		"root.pem":         {Type: "CERTIFICATE", Bytes: h.root.Raw},
		"intermediate.pem": {Type: "CERTIFICATE", Bytes: h.intermediate.Raw},
	}

	for name, key := range map[string]*ecdsa.PrivateKey{"root-key.pem": rootKey, "intermediate-key.pem": intKey} {
		der, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return err
		}

		blocks[name] = &pem.Block{Type: "EC PRIVATE KEY", Bytes: der}
	}

	for name, block := range blocks {
		if err := os.WriteFile(filepath.Join(dir, name), pem.EncodeToMemory(block), 0o600); err != nil {
			return err
		}
	}

	return nil
}

// loadHierarchy reads a hierarchy saved by saveHierarchy, keys included. It
// returns an error wrapping fs.ErrNotExist if no keys were saved.
func loadHierarchy(dir string) (h hierarchy, rootKey, intKey *ecdsa.PrivateKey, err error) {
	for name, dst := range map[string]**ecdsa.PrivateKey{"root-key.pem": &rootKey, "intermediate-key.pem": &intKey} {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return hierarchy{}, nil, nil, err
		}

		block, _ := pem.Decode(raw)
		if block == nil {
			return hierarchy{}, nil, nil, fmt.Errorf("%s holds no key", name)
		}

		if *dst, err = x509.ParseECPrivateKey(block.Bytes); err != nil {
			return hierarchy{}, nil, nil, err
		}
	}

	if h, err = loadCertificates(dir); err != nil {
		return hierarchy{}, nil, nil, err
	}

	return h, rootKey, intKey, nil
}

// loadCertificates reads the root and intermediate saved by saveHierarchy,
// without their keys.
func loadCertificates(dir string) (hierarchy, error) {
	var h hierarchy

	for name, dst := range map[string]**x509.Certificate{"root.pem": &h.root, "intermediate.pem": &h.intermediate} {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return hierarchy{}, fmt.Errorf("the CAs are already merged but %s is missing: run 'make e2e-down' and 'make e2e-up' for a fresh environment: %w", name, err)
		}

		block, _ := pem.Decode(raw)
		if block == nil {
			return hierarchy{}, fmt.Errorf("%s holds no certificate", name)
		}

		if *dst, err = x509.ParseCertificate(block.Bytes); err != nil {
			return hierarchy{}, err
		}
	}

	return h, nil
}
