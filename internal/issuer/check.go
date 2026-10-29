package issuer

import (
	"context"
	"fmt"

	issuerapi "github.com/cert-manager/issuer-lib/api/v1alpha1"
	"github.com/cert-manager/issuer-lib/controllers/signer"
)

// Check reports whether iss can sign. It gets the issuer's credential, fetches
// its CA and signs a throwaway certificate the way Sign does, which proves the
// sign permission and that the key matches the certificate before the issuer
// shows Ready.
//
// issuer-lib calls it when an issuer is created or its spec changes, when the
// controller starts, and after Sign returns an IssuerError. Check uses the
// cached credential like Sign: a spec change starts a new generation, and
// Sign drops the credential before it returns an IssuerError, so in both
// cases Check builds a new one.
//
// It returns a signer.PermanentError only for a problem with the issuer's own
// spec, which only an edit can fix; issuer-lib does not check a permanently
// failed issuer again until its spec changes. Anything that depends on the
// controller's flags or on Azure, such as a vault outside the allow-list or a
// missing role assignment, is returned as a plain error and retried with
// backoff.
func (i *Issuer) Check(ctx context.Context, iss issuerapi.Issuer) error {
	logger := i.logger.With("issuer", iss.GetName(), "namespace", iss.GetNamespace())

	cfg, err := i.parseConfig(iss)
	if err != nil {
		return i.checkError(err)
	}

	cred, err := i.credential(ctx, iss)
	if err != nil {
		return i.checkError(err)
	}

	ca, err := i.fetcher.Fetch(ctx, cred, cfg.caSource)
	if err != nil {
		return fmt.Errorf("fetching CA %s: %w", cfg.caSource, err)
	}

	i.observeCA(iss, ca, cfg.caSource, "Check")

	if err := testSign(ctx, ca); err != nil {
		return fmt.Errorf("making a test signature with CA %s: %w", cfg.caSource, err)
	}

	logger.InfoContext(ctx, "issuer ready",
		"ca", cfg.caSource.String(), "subject", ca.Certificate().Subject.String(),
		"notAfter", ca.NotAfter(), "chainLength", len(ca.Chain()))

	return nil
}

// checkError marks err permanent when only an edit to the issuer can fix it.
func (i *Issuer) checkError(err error) error {
	if i.permanent(err) {
		return signer.PermanentError{Err: err}
	}

	return err
}
