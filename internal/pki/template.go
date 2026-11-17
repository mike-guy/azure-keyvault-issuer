package pki

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"time"

	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	// defaultLifetime applies when a request does not specify one, matching
	// cert-manager's default certificate duration.
	defaultLifetime = 90 * 24 * time.Hour

	// backdate is subtracted from NotBefore to tolerate clock skew between
	// this controller and the clients validating the certificate.
	backdate = 5 * time.Minute
)

// requestedLifetime is the lifetime that req asks for, which is defaultLifetime
// when it asks for none. It is before any limit by a Policy or a CA.
func requestedLifetime(req CertSigningRequest) time.Duration {
	if req.Duration == 0 {
		return defaultLifetime
	}

	return req.Duration
}

// lifetimeLimits records what limited the lifetime of a certificate, so Sign
// can report it without working it out again.
type lifetimeLimits struct {
	// caExpiry is the earliest expiry among the issuing CA and the certificates
	// above it, which is the latest that anything it issues can expire.
	caExpiry time.Time
	// clampedToCA is true when NotAfter was cut back to caExpiry.
	clampedToCA bool
	// clampedToPolicy is true when the request set a duration that was cut back
	// to the policy's MaxDuration. A request that set none is not reported, as
	// it never asked for a lifetime.
	clampedToPolicy bool
}

// createTemplate builds the certificate to sign from csr and req. Only the
// subject and names come from the CSR, the usages from req, and the requester
// controls nothing else. The lifetime is clamped to policy.MaxDuration, and
// NotAfter to the earliest expiry of ca and chain; the returned lifetimeLimits
// reports each clamp. policy must already be valid, as NewSigner checks. The
// logger in ctx reports each decision that changes what was asked for.
func createTemplate(ctx context.Context, csr *x509.CertificateRequest, req CertSigningRequest, ca *x509.Certificate, chain []*x509.Certificate, policy Policy, now time.Time) (*x509.Certificate, lifetimeLimits, error) {
	if req.IsCA && !policy.AllowCA {
		return nil, lifetimeLimits{}, fmt.Errorf("%w: requests for CA certificates are not allowed by policy", ErrInvalidRequest)
	}

	// Not reachable through NewSigner, which rejects a policy that sets both.
	// A new CA's names are limited only by its own name constraints, which
	// cannot express allowedDomains.
	if req.IsCA && len(policy.AllowedDomains) > 0 {
		return nil, lifetimeLimits{}, fmt.Errorf("%w: CA certificates cannot be issued when allowedDomains is set, as the new CA could not be restricted to those domains", ErrInvalidRequest)
	}

	if req.Duration < 0 {
		return nil, lifetimeLimits{}, fmt.Errorf("%w: duration must not be negative, got %v", ErrInvalidRequest, req.Duration)
	}

	if csr.Subject.String() == "" && len(csr.DNSNames)+len(csr.IPAddresses)+len(csr.URIs)+len(csr.EmailAddresses) == 0 {
		return nil, lifetimeLimits{}, fmt.Errorf("%w: certificate request must have a subject or at least one subject alternative name", ErrInvalidRequest)
	}

	if err := checkAllowedDomains(csr, policy.AllowedDomains); err != nil {
		return nil, lifetimeLimits{}, err
	}

	if err := checkNameConstraints(csr, ca, chain, now); err != nil {
		return nil, lifetimeLimits{}, err
	}

	if req.IsCA {
		if err := checkSubjectUnique(csr, ca, chain); err != nil {
			return nil, lifetimeLimits{}, err
		}
	}

	logger := log.FromContext(ctx)

	lifetime := requestedLifetime(req)
	if req.Duration == 0 {
		logger.V(1).Info("no lifetime requested, using the default", "lifetime", lifetime)
	}

	clampedToPolicy := lifetime > policy.MaxDuration
	if clampedToPolicy {
		logger.V(1).Info("clamping lifetime to the policy maximum", "lifetime", lifetime, "maxDuration", policy.MaxDuration)
		lifetime = policy.MaxDuration
	}

	limiting := earliestExpiry(ca, chain)

	notBefore := now.Add(-backdate)
	if !notBefore.Before(limiting.NotAfter) {
		return nil, lifetimeLimits{}, fmt.Errorf("%w: CA certificate %q expired at %v", ErrAuthorityUnusable, limiting.Subject.String(), limiting.NotAfter)
	}

	notAfter := now.Add(lifetime)

	// Only renewing the CA fixes this, so the caller is told through
	// lifetimeLimits and the log is just a trace.
	clampedToCA := notAfter.After(limiting.NotAfter)
	if clampedToCA {
		logger.V(1).Info("clamping notAfter to the expiry of the CA chain, so issued certificates are shorter than requested",
			"notAfter", notAfter, "caNotAfter", limiting.NotAfter, "subject", limiting.Subject.String())
		notAfter = limiting.NotAfter
	}

	keyUsage, extKeyUsage, err := usagesFor(req, policy.allowedExtKeyUsages())
	if err != nil {
		return nil, lifetimeLimits{}, err
	}

	serial, err := newSerialNumber()
	if err != nil {
		return nil, lifetimeLimits{}, err
	}

	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               csr.Subject,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              keyUsage,
		ExtKeyUsage:           extKeyUsage,
		BasicConstraintsValid: true,
		IsCA:                  req.IsCA,
		DNSNames:              csr.DNSNames,
		IPAddresses:           csr.IPAddresses,
		URIs:                  csr.URIs,
		EmailAddresses:        csr.EmailAddresses,
	}

	if req.IsCA {
		pathLen, ok := subCAPathLen(ca, chain)
		if !ok {
			return nil, lifetimeLimits{}, fmt.Errorf("%w: the path length constraint of the issuing CA chain does not allow issuing a CA certificate", ErrInvalidRequest)
		}

		logger.V(1).Info("limiting the path length of the new CA", "maxPathLen", pathLen)

		tmpl.MaxPathLen = pathLen
		// Without MaxPathLenZero, a MaxPathLen of 0 means unset rather than zero.
		tmpl.MaxPathLenZero = pathLen == 0
	}

	return tmpl, lifetimeLimits{
		caExpiry:        limiting.NotAfter,
		clampedToCA:     clampedToCA,
		clampedToPolicy: clampedToPolicy && req.Duration != 0,
	}, nil
}

// checkSubjectUnique returns an error wrapping ErrInvalidRequest if csr has the
// same subject as ca or a certificate in chain, or as the issuer of any of them.
// A new CA that shares a name with one above it confuses clients that build a
// path by name.
//
// Names are compared by attribute, ignoring case, spacing and order. X.509
// matching ignores the first two and clients differ on how strictly they follow
// it, so this errs towards refusing.
func checkSubjectUnique(csr *x509.CertificateRequest, ca *x509.Certificate, chain []*x509.Certificate) error {
	// CreateCertificate encodes the template's Subject with ToRDNSequence, so
	// this is the sequence the issued certificate will carry.
	requested := canonicalAttributes(csr.Subject.ToRDNSequence())
	if len(requested) == 0 {
		return nil
	}

	// Issuers are checked too, as the chain need not include the root but the
	// topmost certificate still names its issuer.
	for _, c := range append([]*x509.Certificate{ca}, chain...) {
		subject := canonicalAttributes(decodeName(c.RawSubject, c.Subject))
		issuer := canonicalAttributes(decodeName(c.RawIssuer, c.Issuer))

		if slices.Equal(requested, subject) || slices.Equal(requested, issuer) {
			return fmt.Errorf("%w: the subject %q of the requested CA is the same as that of a certificate in the issuing chain, so it needs a distinct subject", ErrInvalidRequest, csr.Subject.String())
		}
	}

	return nil
}

// decodeName returns the name from its raw encoding, which keeps attributes
// that pkix.Name has no field for. It falls back to name when raw is empty or
// does not decode.
func decodeName(raw []byte, name pkix.Name) pkix.RDNSequence {
	var rdns pkix.RDNSequence

	if len(raw) > 0 {
		if rest, err := asn1.Unmarshal(raw, &rdns); err == nil && len(rest) == 0 {
			return rdns
		}
	}

	return name.ToRDNSequence()
}

// canonicalAttributes returns the attributes of rdns as sorted "type=value"
// strings, with each value lower-cased and its spacing collapsed.
func canonicalAttributes(rdns pkix.RDNSequence) []string {
	var attributes []string

	for _, rdn := range rdns {
		for _, attribute := range rdn {
			value := strings.ToLower(strings.Join(strings.Fields(fmt.Sprint(attribute.Value)), " "))
			attributes = append(attributes, attribute.Type.String()+"="+value)
		}
	}

	slices.Sort(attributes)

	return attributes
}

// earliestExpiry returns whichever of ca and the certificates in chain expires
// first, which is the latest that anything issued by ca can expire.
func earliestExpiry(ca *x509.Certificate, chain []*x509.Certificate) *x509.Certificate {
	earliest := ca

	for _, c := range chain {
		if c.NotAfter.Before(earliest.NotAfter) {
			earliest = c
		}
	}

	return earliest
}

// certManagerDefaultKeyUsage is the key usage that cert-manager gives a
// Certificate that sets no usages: digital signature and key encipherment, and
// no extended key usage, which it leaves to the CA to add.
const certManagerDefaultKeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment

// namesNoUsages reports whether req asks for no usages of its own. cert-manager
// fills in its default for a Certificate that sets none before the request
// arrives, so the default cannot be told from asking for exactly it, and is
// taken to ask for nothing. For a CA it also adds cert sign. Anything else that
// has no extended key usage, such as cert sign alone, is not the default.
func namesNoUsages(req CertSigningRequest) bool {
	if len(req.ExtKeyUsage) > 0 {
		return false
	}

	defaults := certManagerDefaultKeyUsage
	if req.IsCA {
		defaults |= x509.KeyUsageCertSign
	}

	return req.KeyUsage == 0 || req.KeyUsage == defaults
}

// usagesFor returns the key and extended key usages for the certificate
// requested by req, every extended one being in allowed. A CA always gets cert
// sign. A request that names no usages, which includes cert-manager's default
// for a Certificate that sets none, gets server auth with digital signature and
// key encipherment, as cert-manager leaves the extended usage to the CA.
//
// Refused, rather than adjusted, are cert sign or crl sign on a non-CA, and
// other key usages with no extended key usage. A certificate without the
// extension is valid for any usage, which would get around the policy, and
// filling it in would issue usages that were never asked for.
func usagesFor(req CertSigningRequest, allowed []x509.ExtKeyUsage) (x509.KeyUsage, []x509.ExtKeyUsage, error) {
	keyUsage, extKeyUsage := req.KeyUsage, req.ExtKeyUsage

	if !req.IsCA && keyUsage&(x509.KeyUsageCertSign|x509.KeyUsageCRLSign) != 0 {
		return 0, nil, fmt.Errorf("%w: cert sign and crl sign usages require a CA certificate", ErrInvalidRequest)
	}

	switch {
	case namesNoUsages(req):
		defaults := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}

		if err := checkExtKeyUsages(defaults, allowed); err != nil {
			return 0, nil, fmt.Errorf("%w, and it is the default for a request with no usages, so request the usages needed", err)
		}

		keyUsage, extKeyUsage = x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment, defaults
	case len(extKeyUsage) == 0:
		return 0, nil, fmt.Errorf("%w: a request that names key usages must also name its extended key usages, as a certificate without them is valid for any usage", ErrInvalidRequest)
	default:
		if err := checkExtKeyUsages(extKeyUsage, allowed); err != nil {
			return 0, nil, err
		}
	}

	if req.IsCA {
		keyUsage |= x509.KeyUsageCertSign
	}

	return keyUsage, extKeyUsage, nil
}

// checkExtKeyUsages returns an error wrapping ErrInvalidRequest if requested
// has an extended key usage that is not in allowed. "any" in allowed permits
// every usage, as it does in a certificate.
func checkExtKeyUsages(requested, allowed []x509.ExtKeyUsage) error {
	if slices.Contains(allowed, x509.ExtKeyUsageAny) {
		return nil
	}

	for _, usage := range requested {
		if !slices.Contains(allowed, usage) {
			return fmt.Errorf("%w: extended key usage %q is not permitted by policy, which allows %q",
				ErrInvalidRequest, apiutil.ExtKeyUsageStrings([]x509.ExtKeyUsage{usage})[0], apiutil.ExtKeyUsageStrings(allowed))
		}
	}

	return nil
}

// newSerialNumber returns a random 128 bit serial number, which must be unique
// per CA and should not be predictable.
func newSerialNumber() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)

	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("generating serial number: %w", err)
	}

	return serial, nil
}
