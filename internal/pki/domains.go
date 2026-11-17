package pki

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"strings"
)

// The rules for Policy.AllowedDomains. Each entry is one of three forms, where
// domain has at least one label for a name and at least two for a wildcard, so
// that "*.com" cannot be written:
//
//	domain      exactly that name
//	*.domain    one label below domain, as in a TLS wildcard
//	**.domain   any number of labels below domain
//
// Nothing permits the bare domain implicitly. A requested wildcard name is
// treated as a label of its own, so "*.example.com" is permitted by
// "*.example.com" and "**.example.com" and by nothing else. Names are compared
// without regard to case.

const (
	oneLabelPrefix = "*."
	anyDepthPrefix = "**."

	// maxLabelLength and maxNameLength are the DNS limits.
	maxLabelLength = 63
	maxNameLength  = 253
)

// patternKind is the form of an allowedDomains entry.
type patternKind int

const (
	exactName patternKind = iota
	oneLabel
	anyDepth
)

// parseDomainPattern splits pattern into its form and the domain after any
// wildcard prefix.
func parseDomainPattern(pattern string) (patternKind, string) {
	switch {
	case strings.HasPrefix(pattern, anyDepthPrefix):
		return anyDepth, strings.TrimPrefix(pattern, anyDepthPrefix)
	case strings.HasPrefix(pattern, oneLabelPrefix):
		return oneLabel, strings.TrimPrefix(pattern, oneLabelPrefix)
	default:
		return exactName, pattern
	}
}

// validateDomainPattern checks that pattern is one of the three forms. The
// error it returns completes a sentence that starts with the pattern.
func validateDomainPattern(pattern string) error {
	kind, domain := parseDomainPattern(pattern)

	labels := strings.Split(domain, ".")

	minLabels := 1
	if kind != exactName {
		minLabels = 2
	}

	switch {
	case len(pattern) > maxNameLength:
		return fmt.Errorf("must be at most %d characters", maxNameLength)
	case len(labels) < minLabels:
		return fmt.Errorf("must have at least %d labels after any wildcard", minLabels)
	}

	for _, label := range labels {
		if !validLabel(label, false) {
			return errors.New(`must be a name, "*.name" or "**.name", whose labels are letters, digits and "-" and do not start or end with "-"`)
		}
	}

	return nil
}

// validLabel reports whether label is a DNS label of letters, digits and "-",
// not starting or ending with "-". Underscores are accepted too when
// allowUnderscore is set, as they appear in names in the wild although they are
// not valid hostnames.
func validLabel(label string, allowUnderscore bool) bool {
	if len(label) == 0 || len(label) > maxLabelLength {
		return false
	}

	for i := 0; i < len(label); i++ {
		c := label[i]

		switch {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9':
		case c == '-' && i != 0 && i != len(label)-1:
		case c == '_' && allowUnderscore:
		default:
			return false
		}
	}

	return true
}

// validRequestedName reports whether name is a DNS name that can be matched. It
// may start with a wildcard label, and must have nothing but valid labels
// otherwise, so that a name with odd syntax cannot slip past a pattern.
func validRequestedName(name string) bool {
	if len(name) > maxNameLength {
		return false
	}

	for i, label := range strings.Split(name, ".") {
		if i == 0 && label == "*" {
			continue
		}

		if !validLabel(label, true) {
			return false
		}
	}

	return true
}

// matchesDomainPattern reports whether name, which validRequestedName has
// accepted, is permitted by pattern, which validateDomainPattern has accepted.
func matchesDomainPattern(name, pattern string) bool {
	kind, domain := parseDomainPattern(pattern)

	switch kind {
	case exactName:
		return strings.EqualFold(name, domain)
	case oneLabel:
		first, rest, found := strings.Cut(name, ".")

		return found && first != "" && strings.EqualFold(rest, domain)
	case anyDepth:
		// A name is ASCII by now, so slicing it by bytes is safe.
		suffix := "." + domain

		return len(name) > len(suffix) && strings.EqualFold(name[len(name)-len(suffix):], suffix)
	}

	return false
}

// checkAllowedDomains returns an error wrapping ErrInvalidRequest if csr has a
// name that none of allowed permits. With no entries nothing is checked. With
// any, a list of domains cannot restrict IP addresses, email addresses, URIs or
// subject attributes other than a common name, so a request for one is refused,
// and the request must have a DNS name or a common name.
func checkAllowedDomains(csr *x509.CertificateRequest, allowed []string) error {
	if len(allowed) == 0 {
		return nil
	}

	if len(csr.IPAddresses)+len(csr.EmailAddresses)+len(csr.URIs) > 0 {
		return fmt.Errorf("%w: IP addresses, email addresses and URIs are not permitted when allowedDomains is set", ErrInvalidRequest)
	}

	commonName := csr.Subject.CommonName
	if len(csr.DNSNames) == 0 && commonName == "" {
		return fmt.Errorf("%w: a DNS name or a common name is required when allowedDomains is set", ErrInvalidRequest)
	}

	if hasOtherSubjectAttributes(csr.Subject) {
		return fmt.Errorf("%w: subject attributes other than the common name are not permitted when allowedDomains is set", ErrInvalidRequest)
	}

	for _, name := range csr.DNSNames {
		if !domainAllowed(name, allowed) {
			return fmt.Errorf("%w: DNS name %q is not permitted by allowedDomains", ErrInvalidRequest, name)
		}
	}

	if commonName != "" && !domainAllowed(commonName, allowed) {
		return fmt.Errorf("%w: common name %q is not permitted by allowedDomains", ErrInvalidRequest, commonName)
	}

	return nil
}

// oidCommonName is the attribute type of a common name.
var oidCommonName = asn1.ObjectIdentifier{2, 5, 4, 3}

// hasOtherSubjectAttributes reports whether name holds anything but a single
// common name. A parsed subject lists every attribute in Names, including those
// with no field of their own and a second common name. A subject built in code
// has no Names, so ToRDNSequence covers its fields and ExtraNames.
func hasOtherSubjectAttributes(name pkix.Name) bool {
	commonNames := 0

	for _, attribute := range name.Names {
		if !attribute.Type.Equal(oidCommonName) {
			return true
		}

		commonNames++
	}

	if commonNames > 1 {
		return true
	}

	name.CommonName = ""

	return len(name.ToRDNSequence()) > 0
}

// domainAllowed reports whether any entry of allowed permits name.
func domainAllowed(name string, allowed []string) bool {
	if !validRequestedName(name) {
		return false
	}

	for _, pattern := range allowed {
		if matchesDomainPattern(name, pattern) {
			return true
		}
	}

	return false
}
