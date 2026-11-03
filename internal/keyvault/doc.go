// Package keyvault fetches and validates an issuing CA held in Azure Key
// Vault, and signs with its key without the key ever leaving Key Vault.
//
// A CAFetcher reads a Key Vault certificate, and optionally the full chain
// from its backing secret, and returns a CA. The CA's Signer is a
// crypto.Signer whose Sign method calls Key Vault's sign operation with
// exactly the key version behind the CA certificate.
//
// It also parses and validates vault URLs and Key Vault object IDs.
// ParseVaultURL is exported so the controller can parse
// --issuer-allowed-vaults; an issuer's vaultURL is re-checked through
// ParseCASource.
//
// This is the only package that touches the Key Vault SDK modules.
package keyvault
