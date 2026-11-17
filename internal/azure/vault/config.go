package vault

import (
	"fmt"
	"net/url"
	"strings"
)

// Config selects the CA certificate in a Key Vault. The credential and client
// options are passed to NewCertificateAuthority separately.
type Config struct {
	// VaultURL is the vault's URL, e.g. https://myvault.vault.azure.net/.
	VaultURL string

	// CertificateName is the name of the CA certificate in the vault.
	CertificateName string

	// CertificateVersion pins a version. When empty, the current version is
	// resolved once and everything returned is bound to it.
	CertificateVersion string

	// ChainInSecret says the certificate's backing secret holds the
	// intermediates above the CA, which are then loaded into the chain.
	ChainInSecret bool
}

// validate checks VaultURL and CertificateName. CertificateVersion may be empty.
func (c Config) validate() error {
	if err := validateVaultURL(c.VaultURL); err != nil {
		return err
	}

	if strings.TrimSpace(c.CertificateName) == "" {
		return fmt.Errorf("%w: certificateName must not be empty", ErrInvalidConfig)
	}

	return nil
}

// vaultHostSuffix is the DNS suffix of every Key Vault in the Azure public
// cloud, the only cloud supported. The SDK does not validate the vault URL, but
// it decides where credentials are sent, so it is checked here. The API's
// pattern also enforces the vault name's length and characters.
const vaultHostSuffix = ".vault.azure.net"

// validateVaultURL returns an error wrapping ErrInvalidConfig unless raw is an
// https URL for <name>.vault.azure.net, with no port, userinfo, query, fragment
// or path other than "/".
func validateVaultURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%w: vaultURL %q: parsing URL: %w", ErrInvalidConfig, raw, err)
	}

	host := strings.ToLower(u.Hostname())

	switch {
	case u.Scheme != "https":
		return fmt.Errorf("%w: vaultURL %q: scheme must be https", ErrInvalidConfig, raw)
	case !strings.HasSuffix(host, vaultHostSuffix) || host == vaultHostSuffix:
		return fmt.Errorf("%w: vaultURL %q: host must be <name>%s", ErrInvalidConfig, raw, vaultHostSuffix)
	case u.Port() != "" || u.User != nil:
		return fmt.Errorf("%w: vaultURL %q: must not contain a port or userinfo", ErrInvalidConfig, raw)
	case u.Path != "" && u.Path != "/":
		return fmt.Errorf("%w: vaultURL %q: must not contain a path", ErrInvalidConfig, raw)
	case u.RawQuery != "" || u.ForceQuery || u.Fragment != "":
		return fmt.Errorf("%w: vaultURL %q: must not contain a query or fragment", ErrInvalidConfig, raw)
	}

	return nil
}
