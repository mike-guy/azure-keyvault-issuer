package keyvault

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// vaultDomain is the Key Vault DNS suffix in the Azure public cloud, the only
// cloud supported.
const vaultDomain = ".vault.azure.net"

var (
	// ErrInvalidVaultURL reports a vault URL that is not
	// https://<name>.vault.azure.net with a valid vault name.
	ErrInvalidVaultURL = errors.New("invalid Key Vault URL")

	// ErrInvalidObjectID reports a Key Vault object ID (such as a
	// certificate's key ID) that is malformed, names another vault or lacks a
	// version.
	ErrInvalidObjectID = errors.New("invalid Key Vault object ID")
)

var (
	// vaultNameRE matches the CRD pattern: 3-24 characters, starting with a
	// letter and not ending in a hyphen. Consecutive hyphens are checked
	// separately, as in the CRD's CEL rule.
	vaultNameRE     = regexp.MustCompile(`^[a-z][a-z0-9-]{1,22}[a-z0-9]$`)
	objectNameRE    = regexp.MustCompile(`^[0-9a-zA-Z-]{1,127}$`)
	objectVersionRE = regexp.MustCompile(`^[0-9a-f]{32}$`)
)

// VaultURL is a validated Key Vault URL in the Azure public cloud. The zero
// value is not valid; use ParseVaultURL.
type VaultURL struct {
	name string
}

// ParseVaultURL validates s with the same rules as the CRD and returns it in
// its normalised form. The CRD accepts the URL with or without a trailing
// slash, so both are accepted here.
func ParseVaultURL(s string) (VaultURL, error) {
	u, err := url.Parse(s)
	if err != nil {
		return VaultURL{}, fmt.Errorf("%w: %w", ErrInvalidVaultURL, err)
	}

	switch {
	case u.Scheme != "https":
		return VaultURL{}, fmt.Errorf("%w: scheme must be https", ErrInvalidVaultURL)
	case u.Opaque != "" || u.User != nil:
		return VaultURL{}, fmt.Errorf("%w: must not contain user information", ErrInvalidVaultURL)
	case u.Port() != "":
		return VaultURL{}, fmt.Errorf("%w: must not contain a port", ErrInvalidVaultURL)
	case u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(s, "#"):
		return VaultURL{}, fmt.Errorf("%w: must not contain a query or fragment", ErrInvalidVaultURL)
	case u.Path != "" && u.Path != "/", u.RawPath != "":
		return VaultURL{}, fmt.Errorf("%w: must not contain a path", ErrInvalidVaultURL)
	}

	name, ok := strings.CutSuffix(u.Host, vaultDomain)
	if !ok {
		return VaultURL{}, fmt.Errorf("%w: host must end in %s", ErrInvalidVaultURL, vaultDomain)
	}

	if !vaultNameRE.MatchString(name) || strings.Contains(name, "--") {
		return VaultURL{}, fmt.Errorf("%w: %q is not a valid vault name", ErrInvalidVaultURL, name)
	}

	return VaultURL{name: name}, nil
}

// String returns the normalised URL, https://<name>.vault.azure.net/.
func (v VaultURL) String() string {
	return "https://" + v.host() + "/"
}

// host returns <name>.vault.azure.net.
func (v VaultURL) host() string {
	return v.name + vaultDomain
}

// objectKind is the collection a Key Vault object belongs to.
type objectKind string

// The Key Vault collections this issuer reads.
const (
	kindCertificates objectKind = "certificates"
	kindKeys         objectKind = "keys"
	kindSecrets      objectKind = "secrets"
)

// objectID is a parsed Key Vault object ID that always carries a version.
type objectID struct {
	Name    string
	Version string
}

// parseObjectID parses an object ID of the form
// https://<vault>/<kind>/<name>/<version>. The host must be vault's, and the
// version must be present: a key ID without one would sign with whatever key
// version is current, rather than the one behind the CA certificate.
//
// The SDK's own ID.Name and ID.Version helpers check neither, so they are not
// used.
func parseObjectID(raw string, vault VaultURL, kind objectKind) (objectID, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return objectID{}, fmt.Errorf("%w: %w", ErrInvalidObjectID, err)
	}

	if u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawPath != "" {
		return objectID{}, fmt.Errorf("%w: %q is not a plain https URL", ErrInvalidObjectID, raw)
	}

	if !strings.EqualFold(u.Host, vault.host()) {
		return objectID{}, fmt.Errorf("%w: %q is not in vault %s", ErrInvalidObjectID, raw, vault.host())
	}

	parts := strings.Split(strings.TrimPrefix(u.Path, "/"), "/")
	if len(parts) != 3 || parts[0] != string(kind) {
		return objectID{}, fmt.Errorf("%w: %q is not of the form /%s/<name>/<version>", ErrInvalidObjectID, raw, kind)
	}

	id := objectID{Name: parts[1], Version: parts[2]}
	if err := validateObjectName(id.Name); err != nil {
		return objectID{}, fmt.Errorf("%w: %w", ErrInvalidObjectID, err)
	}

	if !objectVersionRE.MatchString(id.Version) {
		return objectID{}, fmt.Errorf("%w: %q has no valid version", ErrInvalidObjectID, raw)
	}

	return id, nil
}

// validateObjectName checks a Key Vault object name, such as a certificate
// name.
func validateObjectName(name string) error {
	if !objectNameRE.MatchString(name) {
		return fmt.Errorf("%q is not a valid Key Vault object name", name)
	}

	return nil
}

// validateObjectVersion checks an optional Key Vault object version. An empty
// version is valid and means the current version.
func validateObjectVersion(version string) error {
	if version != "" && !objectVersionRE.MatchString(version) {
		return fmt.Errorf("%q is not a valid Key Vault object version", version)
	}

	return nil
}
