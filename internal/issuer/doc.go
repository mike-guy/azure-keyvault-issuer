// Package issuer is the domain of the controller: it checks issuers, signs
// CertificateRequests and enforces the issuance policy. issuer-lib calls its
// Check and Sign methods, and maps the errors they return onto issuer and
// CertificateRequest conditions.
//
// It depends only on its own small interfaces for credentials and CAs; the
// composition root supplies the concrete credential provider and Key Vault
// CA fetcher.
package issuer
