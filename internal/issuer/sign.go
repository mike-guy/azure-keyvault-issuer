package issuer

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"time"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/pkg/util/pki"
	issuerapi "github.com/cert-manager/issuer-lib/api/v1alpha1"
	"github.com/cert-manager/issuer-lib/controllers/signer"
	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/mike-guy/azure-keyvault-issuer/internal/keyvault"
)

const (
	// reasonCANotAllowed is the reason on the InvalidRequest condition of a
	// refused CA request.
	reasonCANotAllowed = "CANotAllowed"

	// reasonPathLenExceeded is the reason on the InvalidRequest condition of a
	// CA request that the issuing CA's path length constraint refuses.
	reasonPathLenExceeded = "PathLenExceeded"

	// reasonDurationClamped is the reason of the event recorded when a
	// lifetime is clamped.
	reasonDurationClamped = "DurationClamped"
)

// Sign signs the CSR in cr, a cert-manager CertificateRequest or a Kubernetes
// CertificateSigningRequest, with iss's CA and returns the certificate followed by
// the CA chain. The CA is fetched for every request, so a rotated CA is used
// at once.
//
// Its errors tell issuer-lib what to do next:
//   - signer.PermanentError for a request that can never succeed, such as an
//     invalid CSR, a CA request the policy refuses, or one the CA's path
//     length constraint refuses;
//   - signer.IssuerError when the issuer itself is not working, such as a
//     missing permission or a disabled CA. issuer-lib marks the issuer not
//     ready and runs Check again, and the request waits rather than failing;
//   - a plain error for throttling, server errors and timeouts, which
//     issuer-lib retries until its maximum retry duration.
func (i *Issuer) Sign(ctx context.Context, cr signer.CertificateRequestObject, iss issuerapi.Issuer) (signer.PEMBundle, error) {
	// The request is a cert-manager CertificateRequest or, for a ClusterIssuer,
	// a cluster-scoped Kubernetes CertificateSigningRequest.
	logger := i.logger.With("issuer", iss.GetName(), "namespace", iss.GetNamespace(),
		"request", cr.GetName(), "requestKind", requestRef(cr).GetObjectKind().GroupVersionKind().Kind,
		"requestNamespace", cr.GetNamespace())

	tmpl, err := certificateTemplate(cr)
	if err != nil {
		return signer.PEMBundle{}, err
	}

	cfg, err := i.parseConfig(iss)
	if err != nil {
		return signer.PEMBundle{}, signer.IssuerError{Err: err}
	}

	if tmpl.IsCA && !cfg.policy.allowCA {
		logger.InfoContext(ctx, "refused CA request")

		return signer.PEMBundle{}, errCANotAllowed()
	}

	cred, err := i.credential(ctx, iss)
	if err != nil {
		return signer.PEMBundle{}, signer.IssuerError{Err: err}
	}

	ca, err := i.fetcher.Fetch(ctx, cred, cfg.caSource)
	if err != nil {
		return signer.PEMBundle{}, i.signError(iss, fmt.Errorf("fetching CA %s: %w", cfg.caSource, err))
	}

	// Check runs only when the issuer changes, so the CA fetched here is the
	// one that shows a rotation.
	i.observeCA(iss, ca, cfg.caSource, "Sign")

	if err := applyPathLen(tmpl, ca.Certificate()); err != nil {
		logger.InfoContext(ctx, "refused CA request", "error", err)

		return signer.PEMBundle{}, invalidRequest(err, reasonPathLenExceeded)
	}

	requested, clamped := clampNotAfter(tmpl, cfg.policy.maxDuration, ca.NotAfter())

	bundle, err := signTemplate(ctx, ca, tmpl)
	if err != nil {
		return signer.PEMBundle{}, i.signError(iss, fmt.Errorf("signing with CA %s: %w", cfg.caSource, err))
	}

	if clamped {
		i.recordClamp(cr, requested, tmpl.NotAfter)
	}

	logger.InfoContext(ctx, "signed certificate",
		"ca", cfg.caSource.String(), "serial", serialOf(bundle),
		"notAfter", tmpl.NotAfter, "clamped", clamped)

	return signer.PEMBundle(bundle), nil
}

// certificateTemplate reads cr's CSR into a certificate template. This checks
// the CSR's signature and applies the requested SANs, duration, isCA and
// usages. A request that fails here can never succeed, so its errors are
// permanent.
func certificateTemplate(cr signer.CertificateRequestObject) (*x509.Certificate, error) {
	details, err := cr.GetCertificateDetails()
	if err != nil {
		return nil, signer.PermanentError{Err: fmt.Errorf("reading request: %w", err)}
	}

	tmpl, err := details.CertificateTemplate()
	if err != nil {
		return nil, signer.PermanentError{Err: fmt.Errorf("building certificate template: %w", err)}
	}

	return tmpl, nil
}

// errCANotAllowed refuses a CA request permanently, with an InvalidRequest
// condition on the request.
func errCANotAllowed() error {
	return invalidRequest(ErrCANotAllowed, reasonCANotAllowed)
}

// invalidRequest refuses a request permanently, with an InvalidRequest
// condition on the request that gives reason.
func invalidRequest(err error, reason string) error {
	return signer.SetCertificateRequestConditionError{
		Err:           signer.PermanentError{Err: err},
		ConditionType: cmapi.CertificateRequestConditionInvalidRequest,
		Status:        cmmeta.ConditionTrue,
		Reason:        reason,
	}
}

// signTemplate signs tmpl with ca and returns the certificate and chain.
// cert-manager's pki package flattens the signer's error into text, which
// would hide an Azure status code from signError, so a signing failure
// returns the signer's own error instead.
func signTemplate(ctx context.Context, ca *keyvault.CA, tmpl *x509.Certificate) (pki.PEMBundle, error) {
	s := &errorKeepingSigner{Signer: ca.Signer(ctx)}

	bundle, err := pki.SignCSRTemplate(ca.Chain(), s, tmpl)
	if err != nil && s.err != nil {
		return pki.PEMBundle{}, s.err
	}

	return bundle, err
}

// testSign signs a throwaway certificate with ca through signTemplate, the
// path Sign uses, and discards it. It proves, before any request arrives, that
// the caller may sign with the key and that the key matches the CA
// certificate, because x509 checks each signature against that certificate.
// Using the same path as Sign means the two cannot choose different hashes or
// classify errors differently. It costs one Key Vault sign operation.
func testSign(ctx context.Context, ca *keyvault.CA) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generating a test key: %w", err)
	}

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "azure-keyvault-issuer test signature"},
		NotBefore:    now,
		NotAfter:     now.Add(time.Minute),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		PublicKey:    key.Public(),
	}

	_, err = signTemplate(ctx, ca, tmpl)

	return err
}

// serialOf returns the serial number of the certificate in bundle, in hex.
// x509.CreateCertificate chooses the serial number, so it is only on the
// signed certificate, not the template. cert-manager has just encoded the
// bundle, so decoding it cannot fail in practice.
func serialOf(bundle pki.PEMBundle) string {
	leaf, err := pki.DecodeX509CertificateBytes(bundle.ChainPEM)
	if err != nil {
		return ""
	}

	return leaf.SerialNumber.Text(16)
}

// signError classifies a failure after the request itself has been accepted.
// Throttling, server errors and timeouts are retried as they are. Anything
// else means the issuer is not working: its cached credential is dropped and
// an IssuerError makes issuer-lib check the issuer again.
func (i *Issuer) signError(iss issuerapi.Issuer, err error) error {
	if transient(err) {
		return err
	}

	i.cache.forget(iss.GetUID())

	return signer.IssuerError{Err: err}
}

// recordClamp records an event on cr saying its lifetime was shortened.
func (i *Issuer) recordClamp(cr signer.CertificateRequestObject, requested, issued time.Time) {
	if i.events == nil {
		return
	}

	i.events.Eventf(requestRef(cr), nil, corev1.EventTypeNormal, reasonDurationClamped, "Sign",
		"Certificate lifetime shortened: requested expiry %s, issued expiry %s (limited by spec.policy.maxDuration or the CA chain's expiry)",
		requested.UTC().Format(time.RFC3339), issued.UTC().Format(time.RFC3339))
}

// requestRef returns a reference to cr that an event can be recorded on. The
// request reaches Sign as an interface without its type, so the reference is
// built by hand. A Kubernetes CertificateSigningRequest is cluster-scoped and
// a cert-manager CertificateRequest is always namespaced, so the namespace
// tells them apart.
func requestRef(cr signer.CertificateRequestObject) runtime.Object {
	meta := metav1.ObjectMeta{
		Namespace: cr.GetNamespace(), Name: cr.GetName(), UID: cr.GetUID(), ResourceVersion: cr.GetResourceVersion(),
	}

	if cr.GetNamespace() == "" {
		return &certificatesv1.CertificateSigningRequest{
			TypeMeta:   metav1.TypeMeta{APIVersion: certificatesv1.SchemeGroupVersion.String(), Kind: "CertificateSigningRequest"},
			ObjectMeta: meta,
		}
	}

	return &cmapi.CertificateRequest{
		TypeMeta:   metav1.TypeMeta{APIVersion: cmapi.SchemeGroupVersion.String(), Kind: cmapi.CertificateRequestKind},
		ObjectMeta: meta,
	}
}

// errorKeepingSigner remembers the last error from its signer.
type errorKeepingSigner struct {
	crypto.Signer

	err error
}

func (s *errorKeepingSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	sig, err := s.Signer.Sign(rand, digest, opts)
	if err != nil {
		s.err = err
	}

	return sig, err
}
