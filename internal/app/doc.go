// Package app is the composition root. It parses flags, reads the
// environment, sets up logging, builds the credential provider, the Key Vault
// CA fetcher and the issuer, and runs them under a controller-runtime manager
// through issuer-lib.
//
// It is the only package that knows the manager, reads the environment or
// installs process-wide loggers.
package app
