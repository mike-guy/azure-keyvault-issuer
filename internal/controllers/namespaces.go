package controllers

import (
	"fmt"
	"slices"
	"strings"

	"k8s.io/apimachinery/pkg/util/validation"
)

// validateAllowedNamespaces returns an error wrapping ErrInvalidConfig unless
// each entry is a valid namespace name, an RFC 1123 label. The CRD enforces the
// same rule, so this covers an issuer stored before it existed, and reports a
// bad entry on the issuer's Ready condition.
func validateAllowedNamespaces(allowed []string) error {
	for i, namespace := range allowed {
		if problems := validation.IsDNS1123Label(namespace); len(problems) > 0 {
			return fmt.Errorf("%w: allowedNamespaces[%d] %q must be a valid namespace name: %s", ErrInvalidConfig, i, namespace, strings.Join(problems, "; "))
		}
	}

	return nil
}

// checkNamespaceAllowed returns an error wrapping ErrNamespaceNotAllowed unless
// a request from namespace may use the issuer. Each entry of allowed is an exact
// name, and an empty list permits every namespace.
func checkNamespaceAllowed(allowed []string, namespace string, issuerName string) error {
	if len(allowed) == 0 {
		return nil
	}

	if slices.Contains(allowed, namespace) {
		return nil
	}

	return fmt.Errorf("%w: namespace %q cannot use clusterIssuer %q", ErrNamespaceNotAllowed, namespace, issuerName)
}
