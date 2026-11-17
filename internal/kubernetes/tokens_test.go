package kubernetes

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

// recordedTokenCall holds what the fake API server was asked for.
type recordedTokenCall struct {
	called       bool
	subResource  string
	saName       types.NamespacedName
	audiences    []string
	expirationFn *int64
}

// newTokenClient returns a client whose TokenRequest create calls are recorded
// in the returned recordedTokenCall. The call then sets token on the request
// status and returns err.
func newTokenClient(token string, err error) (client.Client, *recordedTokenCall) {
	rec := &recordedTokenCall{
		called:       false,
		subResource:  "",
		saName:       types.NamespacedName{Namespace: "", Name: ""},
		audiences:    nil,
		expirationFn: nil,
	}

	funcs := interceptor.Funcs{
		SubResourceCreate: func(_ context.Context, _ client.Client, subResourceName string, obj client.Object, subResource client.Object, _ ...client.SubResourceCreateOption) error {
			rec.called = true
			rec.subResource = subResourceName
			rec.saName = client.ObjectKeyFromObject(obj)

			if req, ok := subResource.(*authenticationv1.TokenRequest); ok {
				rec.audiences = req.Spec.Audiences
				rec.expirationFn = req.Spec.ExpirationSeconds
				req.Status.Token = token
			}

			return err
		},
	}

	return fake.NewClientBuilder().WithInterceptorFuncs(funcs).Build(), rec
}

func TestNewTokenRequester(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		client  client.SubResourceClientConstructor
		wantErr bool
	}{
		{
			name:    "nil client is rejected",
			client:  nil,
			wantErr: true,
		},
		{
			name:    "usable client is accepted",
			client:  fake.NewClientBuilder().Build(),
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := NewTokenRequester(tt.client)
			if (err != nil) != tt.wantErr {
				t.Fatalf("NewTokenRequester() error = %v, wantErr %v", err, tt.wantErr)
			}

			if tt.wantErr && got != nil {
				t.Errorf("NewTokenRequester() = %v, want nil on error", got)
			}

			if !tt.wantErr && got == nil {
				t.Error("NewTokenRequester() = nil, want non-nil")
			}
		})
	}
}

func TestTokenRequesterCreateToken(t *testing.T) {
	t.Parallel()

	errAPI := errors.New("api server unavailable")
	sa := types.NamespacedName{Namespace: "ns", Name: "sa"}
	audience := "api://AzureADTokenExchange"
	expiry := 10 * time.Minute

	tests := []struct {
		name      string
		apiToken  string
		apiErr    error
		wantToken string
		wantErr   error
		wantMsg   string // substring expected in the error message, empty means success
	}{
		{
			name:      "token from the API server is returned",
			apiToken:  "jwt",
			apiErr:    nil,
			wantToken: "jwt",
			wantErr:   nil,
			wantMsg:   "",
		},
		{
			name:      "API error is wrapped and no token returned",
			apiToken:  "",
			apiErr:    errAPI,
			wantToken: "",
			wantErr:   errAPI,
			wantMsg:   "requesting token for service account ns/sa",
		},
		{
			name:      "API error never leaks a token that was set",
			apiToken:  "jwt",
			apiErr:    errAPI,
			wantToken: "",
			wantErr:   errAPI,
			wantMsg:   "requesting token for service account ns/sa",
		},
		{
			name:      "empty token in the response is an error",
			apiToken:  "",
			apiErr:    nil,
			wantToken: "",
			wantErr:   nil,
			wantMsg:   "returned no token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			c, rec := newTokenClient(tt.apiToken, tt.apiErr)

			r, err := NewTokenRequester(c)
			if err != nil {
				t.Fatalf("NewTokenRequester() error = %v", err)
			}

			got, err := r.CreateToken(context.Background(), sa, audience, expiry)

			if tt.wantMsg == "" {
				if err != nil {
					t.Fatalf("CreateToken() error = %v, want nil", err)
				}
			} else {
				if err == nil {
					t.Fatalf("CreateToken() error = nil, want error containing %q", tt.wantMsg)
				}

				if !strings.Contains(err.Error(), tt.wantMsg) {
					t.Errorf("CreateToken() error = %q, want it to contain %q", err, tt.wantMsg)
				}

				if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
					t.Errorf("CreateToken() error = %v, want it to wrap %v", err, tt.wantErr)
				}

				if strings.Contains(err.Error(), "jwt") {
					t.Errorf("CreateToken() error = %q, must not contain the token", err)
				}
			}

			if got != tt.wantToken {
				t.Errorf("CreateToken() token = %q, want %q", got, tt.wantToken)
			}

			if !rec.called {
				t.Fatal("CreateToken() did not call the API server")
			}

			if rec.subResource != "token" {
				t.Errorf("subresource = %q, want %q", rec.subResource, "token")
			}

			if rec.saName != sa {
				t.Errorf("service account = %+v, want %+v", rec.saName, sa)
			}

			if len(rec.audiences) != 1 || rec.audiences[0] != audience {
				t.Errorf("audiences = %v, want [%q]", rec.audiences, audience)
			}

			if rec.expirationFn == nil {
				t.Fatal("expirationSeconds = nil, want it set")
			}

			if want := int64(expiry.Seconds()); *rec.expirationFn != want {
				t.Errorf("expirationSeconds = %d, want %d", *rec.expirationFn, want)
			}
		})
	}
}

// The request is sent for a ServiceAccount object, so the type must be the one
// the TokenRequest API expects.
func TestTokenRequesterCreateTokenTargetsServiceAccount(t *testing.T) {
	t.Parallel()

	var gotType client.Object

	funcs := interceptor.Funcs{
		SubResourceCreate: func(_ context.Context, _ client.Client, _ string, obj client.Object, subResource client.Object, _ ...client.SubResourceCreateOption) error {
			gotType = obj

			if req, ok := subResource.(*authenticationv1.TokenRequest); ok {
				req.Status.Token = "jwt"
			}

			return nil
		},
	}

	r, err := NewTokenRequester(fake.NewClientBuilder().WithInterceptorFuncs(funcs).Build())
	if err != nil {
		t.Fatalf("NewTokenRequester() error = %v", err)
	}

	sa := types.NamespacedName{Namespace: "ns", Name: "sa"}
	if _, err := r.CreateToken(context.Background(), sa, "aud", 10*time.Minute); err != nil {
		t.Fatalf("CreateToken() error = %v", err)
	}

	if _, ok := gotType.(*corev1.ServiceAccount); !ok {
		t.Errorf("object type = %T, want *corev1.ServiceAccount", gotType)
	}
}
