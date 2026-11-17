package vault

import (
	"errors"
	"strings"
	"testing"
)

func TestConfigValidate(t *testing.T) {
	t.Parallel()

	const (
		validURL  = "https://myvault.vault.azure.net/"
		validName = "ca"
	)

	tests := []struct {
		name      string
		config    Config
		wantErr   error
		wantField string // substring expected in the error message
	}{
		{
			name:      "url and name pass validation",
			config:    Config{VaultURL: validURL, CertificateName: validName, CertificateVersion: "", ChainInSecret: false},
			wantErr:   nil,
			wantField: "",
		},
		{
			name:      "pinned version and chain in secret pass validation",
			config:    Config{VaultURL: validURL, CertificateName: validName, CertificateVersion: "abc123", ChainInSecret: true},
			wantErr:   nil,
			wantField: "",
		},
		{
			name:      "empty vault url fails validation",
			config:    Config{VaultURL: "", CertificateName: validName, CertificateVersion: "", ChainInSecret: false},
			wantErr:   ErrInvalidConfig,
			wantField: "vaultURL",
		},
		{
			name:      "whitespace vault url fails validation",
			config:    Config{VaultURL: " \t\n", CertificateName: validName, CertificateVersion: "", ChainInSecret: false},
			wantErr:   ErrInvalidConfig,
			wantField: "vaultURL",
		},
		{
			name:      "vault url without trailing slash passes validation",
			config:    Config{VaultURL: "https://myvault.vault.azure.net", CertificateName: validName, CertificateVersion: "", ChainInSecret: false},
			wantErr:   nil,
			wantField: "",
		},
		{
			name:      "vault url with uppercase host passes validation",
			config:    Config{VaultURL: "https://MyVault.Vault.Azure.Net/", CertificateName: validName, CertificateVersion: "", ChainInSecret: false},
			wantErr:   nil,
			wantField: "",
		},
		{
			name:      "vault url without scheme fails validation",
			config:    Config{VaultURL: "myvault.vault.azure.net", CertificateName: validName, CertificateVersion: "", ChainInSecret: false},
			wantErr:   ErrInvalidConfig,
			wantField: "vaultURL",
		},
		{
			name:      "http vault url fails validation",
			config:    Config{VaultURL: "http://myvault.vault.azure.net/", CertificateName: validName, CertificateVersion: "", ChainInSecret: false},
			wantErr:   ErrInvalidConfig,
			wantField: "vaultURL",
		},
		{
			name:      "vault url on another domain fails validation",
			config:    Config{VaultURL: "https://evil.example.com/", CertificateName: validName, CertificateVersion: "", ChainInSecret: false},
			wantErr:   ErrInvalidConfig,
			wantField: "vaultURL",
		},
		{
			name:      "vault url with the vault domain as a prefix fails validation",
			config:    Config{VaultURL: "https://myvault.vault.azure.net.evil.com/", CertificateName: validName, CertificateVersion: "", ChainInSecret: false},
			wantErr:   ErrInvalidConfig,
			wantField: "vaultURL",
		},
		{
			name:      "vault url with the vault domain as a userinfo fails validation",
			config:    Config{VaultURL: "https://myvault.vault.azure.net@evil.com/", CertificateName: validName, CertificateVersion: "", ChainInSecret: false},
			wantErr:   ErrInvalidConfig,
			wantField: "vaultURL",
		},
		{
			name:      "vault url with no vault name fails validation",
			config:    Config{VaultURL: "https://.vault.azure.net/", CertificateName: validName, CertificateVersion: "", ChainInSecret: false},
			wantErr:   ErrInvalidConfig,
			wantField: "vaultURL",
		},
		{
			name:      "vault url with only the vault domain fails validation",
			config:    Config{VaultURL: "https://vault.azure.net/", CertificateName: validName, CertificateVersion: "", ChainInSecret: false},
			wantErr:   ErrInvalidConfig,
			wantField: "vaultURL",
		},
		{
			name:      "vault url with userinfo fails validation",
			config:    Config{VaultURL: "https://user@myvault.vault.azure.net/", CertificateName: validName, CertificateVersion: "", ChainInSecret: false},
			wantErr:   ErrInvalidConfig,
			wantField: "vaultURL",
		},
		{
			name:      "vault url with port fails validation",
			config:    Config{VaultURL: "https://myvault.vault.azure.net:8443/", CertificateName: validName, CertificateVersion: "", ChainInSecret: false},
			wantErr:   ErrInvalidConfig,
			wantField: "vaultURL",
		},
		{
			name:      "vault url with path fails validation",
			config:    Config{VaultURL: "https://myvault.vault.azure.net/keys", CertificateName: validName, CertificateVersion: "", ChainInSecret: false},
			wantErr:   ErrInvalidConfig,
			wantField: "vaultURL",
		},
		{
			name:      "vault url with query fails validation",
			config:    Config{VaultURL: "https://myvault.vault.azure.net/?a=b", CertificateName: validName, CertificateVersion: "", ChainInSecret: false},
			wantErr:   ErrInvalidConfig,
			wantField: "vaultURL",
		},
		{
			name:      "vault url with empty query fails validation",
			config:    Config{VaultURL: "https://myvault.vault.azure.net/?", CertificateName: validName, CertificateVersion: "", ChainInSecret: false},
			wantErr:   ErrInvalidConfig,
			wantField: "vaultURL",
		},
		{
			name:      "vault url with fragment fails validation",
			config:    Config{VaultURL: "https://myvault.vault.azure.net/#frag", CertificateName: validName, CertificateVersion: "", ChainInSecret: false},
			wantErr:   ErrInvalidConfig,
			wantField: "vaultURL",
		},
		{
			name:      "unparseable vault url fails validation",
			config:    Config{VaultURL: "https://myvault.vault.azure.net/\x7f", CertificateName: validName, CertificateVersion: "", ChainInSecret: false},
			wantErr:   ErrInvalidConfig,
			wantField: "vaultURL",
		},
		{
			name:      "empty certificate name fails validation",
			config:    Config{VaultURL: validURL, CertificateName: "", CertificateVersion: "", ChainInSecret: false},
			wantErr:   ErrInvalidConfig,
			wantField: "certificateName",
		},
		{
			name:      "whitespace certificate name fails validation",
			config:    Config{VaultURL: validURL, CertificateName: " \t\n", CertificateVersion: "", ChainInSecret: false},
			wantErr:   ErrInvalidConfig,
			wantField: "certificateName",
		},
		{
			name:      "vault url is reported first when both are invalid",
			config:    Config{VaultURL: "", CertificateName: "", CertificateVersion: "", ChainInSecret: false},
			wantErr:   ErrInvalidConfig,
			wantField: "vaultURL",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := tt.config.validate()
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("validate() error = %v, want %v", err, tt.wantErr)
			}

			if err != nil && !strings.Contains(err.Error(), tt.wantField) {
				t.Errorf("validate() error = %q, want it to contain %q", err, tt.wantField)
			}
		})
	}
}
