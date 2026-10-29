package credential

import "errors"

// Errors returned, wrapped with context, by Provider.For and by the
// credentials it returns.
//
// A failed TokenRequest is not among them: azidentity reports it only as
// text, so it surfaces from GetToken as an authentication failure whose
// message names the ServiceAccount and gives the Kubernetes reason. A failed
// Secret read is returned from GetToken as the wrapped Kubernetes error.
var (
	// ErrUnsupportedIssuer reports an issuer type this package does not know.
	ErrUnsupportedIssuer = errors.New("unsupported issuer type")

	// ErrAmbientNotPermitted reports an issuer with no auth method whose kind
	// may not use the controller's ambient credentials.
	ErrAmbientNotPermitted = errors.New("ambient credentials are not permitted for this kind of issuer")

	// ErrAmbientUnavailable reports an issuer with no auth method when the
	// controller has no ambient workload identity configured.
	ErrAmbientUnavailable = errors.New("no ambient workload identity is configured for the controller")

	// ErrNoTenant reports a workload identity with no tenant ID when the
	// controller has no default tenant either.
	ErrNoTenant = errors.New("no tenant ID set and no default tenant configured")

	// ErrInvalidAuth reports a malformed auth method, such as a client ID that
	// is not a GUID.
	ErrInvalidAuth = errors.New("invalid auth")

	// ErrInvalidSecret reports a Secret that cannot be used for the issuer's
	// auth method, such as one missing a key or holding a certificate that
	// does not match its key. Editing the Secret fixes it, not editing the
	// issuer, so it is not an invalid-spec error. It is returned from GetToken,
	// because the Secret is only read when a token is needed.
	ErrInvalidSecret = errors.New("invalid Secret")
)
