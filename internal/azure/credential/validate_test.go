package credential

import (
	"errors"
	"strings"
	"testing"

	"github.com/mike-guy/azure-keyvault-issuer/api/v1alpha1"
)

const nilGUID = "00000000-0000-0000-0000-000000000000"

func TestValidateAuthMethods(t *testing.T) {
	t.Parallel()

	wi := &v1alpha1.WorkloadIdentity{
		TenantID:          "",
		ClientID:          "",
		ServiceAccountRef: v1alpha1.ServiceAccountRef{Name: ""},
	}
	cs := &v1alpha1.ClientSecret{
		TenantID:  "",
		ClientID:  "",
		SecretRef: v1alpha1.SecretKeySelector{Name: "", Key: ""},
	}
	cc := &v1alpha1.ClientCertificate{
		TenantID:  "",
		ClientID:  "",
		SecretRef: v1alpha1.SecretSelector{Name: ""},
	}

	tests := []struct {
		name    string
		auth    *v1alpha1.Auth
		wantErr error
	}{
		{
			name:    "no auth method fails validation",
			auth:    &v1alpha1.Auth{WorkloadIdentity: nil, ClientSecret: nil, ClientCertificate: nil},
			wantErr: ErrInvalidConfig,
		},
		{
			name:    "workload identity only passes validation",
			auth:    &v1alpha1.Auth{WorkloadIdentity: wi, ClientSecret: nil, ClientCertificate: nil},
			wantErr: nil,
		},
		{
			name:    "client secret only passes validation",
			auth:    &v1alpha1.Auth{WorkloadIdentity: nil, ClientSecret: cs, ClientCertificate: nil},
			wantErr: nil,
		},
		{
			name:    "client certificate only passes validation",
			auth:    &v1alpha1.Auth{WorkloadIdentity: nil, ClientSecret: nil, ClientCertificate: cc},
			wantErr: nil,
		},
		{
			name:    "workload identity and client secret fails validation",
			auth:    &v1alpha1.Auth{WorkloadIdentity: wi, ClientSecret: cs, ClientCertificate: nil},
			wantErr: ErrInvalidConfig,
		},
		{
			name:    "workload identity and client certificate fails validation",
			auth:    &v1alpha1.Auth{WorkloadIdentity: wi, ClientSecret: nil, ClientCertificate: cc},
			wantErr: ErrInvalidConfig,
		},
		{
			name:    "client secret and client certificate fails validation",
			auth:    &v1alpha1.Auth{WorkloadIdentity: nil, ClientSecret: cs, ClientCertificate: cc},
			wantErr: ErrInvalidConfig,
		},
		{
			name:    "all auth methods fails validation",
			auth:    &v1alpha1.Auth{WorkloadIdentity: wi, ClientSecret: cs, ClientCertificate: cc},
			wantErr: ErrInvalidConfig,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := validateAuthMethods(tt.auth)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("validateAuthMethods() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateIDs(t *testing.T) {
	t.Parallel()

	const method = "testing"

	tests := []struct {
		name      string
		tenantID  string
		clientID  string
		wantErr   error
		wantField string // substring expected in the error message
	}{
		{
			name:      "valid ids pass validation",
			tenantID:  validGUID,
			clientID:  validGUID,
			wantErr:   nil,
			wantField: "",
		},
		{
			name:      "invalid tenant id is reported by field",
			tenantID:  "test",
			clientID:  validGUID,
			wantErr:   ErrInvalidConfig,
			wantField: method + ".tenantID",
		},
		{
			name:      "invalid client id is reported by field",
			tenantID:  validGUID,
			clientID:  "test",
			wantErr:   ErrInvalidConfig,
			wantField: method + ".clientID",
		},
		{
			name:      "tenant id is reported first when both are invalid",
			tenantID:  "test",
			clientID:  "test",
			wantErr:   ErrInvalidConfig,
			wantField: method + ".tenantID",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := validateIDs(method, tt.tenantID, tt.clientID)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("validateIDs() error = %v, want %v", err, tt.wantErr)
			}

			if err != nil && !strings.Contains(err.Error(), tt.wantField) {
				t.Errorf("validateIDs() error = %q, want it to contain %q", err, tt.wantField)
			}
		})
	}
}

func TestValidateID(t *testing.T) {
	t.Parallel()

	const field = "testing.id"

	tests := []struct {
		name    string
		id      string
		wantErr error
	}{
		{
			name:    "valid guid passes validation",
			id:      validGUID,
			wantErr: nil,
		},
		{
			name:    "empty string fails validation",
			id:      "",
			wantErr: ErrInvalidConfig,
		},
		{
			name:    "non guid string fails validation",
			id:      "test",
			wantErr: ErrInvalidConfig,
		},
		{
			name:    "nil guid fails validation",
			id:      nilGUID,
			wantErr: ErrInvalidConfig,
		},
		{
			name:    "truncated guid fails validation",
			id:      "00000000-1111-2222-3333-44444444444",
			wantErr: ErrInvalidConfig,
		},
		{
			name:    "guid with non hex characters fails validation",
			id:      "0000000g-1111-2222-3333-444444444444",
			wantErr: ErrInvalidConfig,
		},
		{
			name:    "guid with surrounding whitespace fails validation",
			id:      " " + validGUID + " ",
			wantErr: ErrInvalidConfig,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := validateID(field, tt.id)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("validateID(%q) error = %v, want %v", tt.id, err, tt.wantErr)
			}

			if err != nil && !strings.Contains(err.Error(), field) {
				t.Errorf("validateID(%q) error = %q, want it to contain %q", tt.id, err, field)
			}
		})
	}
}
