package templates

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/hadrian/pkg/model"
)

func TestBuildRequest_AnonymousAuthHeaderStripping(t *testing.T) {
	tests := []struct {
		name          string
		authInfo      *AuthInfo
		customHeaders map[string]string
		wantHeaders   map[string]string // header name -> expected value
		absentHeaders []string
	}{
		{
			name:     "anonymous strips Authorization and Cookie",
			authInfo: nil,
			customHeaders: map[string]string{
				"Authorization":  "Bearer operator-secret",
				"Cookie":         "session=operator-secret",
				"X-Custom-Trace": "trace-123",
			},
			wantHeaders:   map[string]string{"X-Custom-Trace": "trace-123"},
			absentHeaders: []string{"Authorization", "Cookie"},
		},
		{
			name:     "authenticated keeps all custom headers",
			authInfo: &AuthInfo{Method: "bearer", Value: "Bearer tok"},
			customHeaders: map[string]string{
				"Authorization":  "Bearer custom",
				"Cookie":         "session=custom",
				"X-Custom-Trace": "trace-123",
			},
			wantHeaders: map[string]string{
				// bearer auth is applied after custom headers and takes precedence
				"Authorization":  "Bearer tok",
				"Cookie":         "session=custom",
				"X-Custom-Trace": "trace-123",
			},
		},
		{
			name:     "anonymous case-insensitive stripping",
			authInfo: nil,
			customHeaders: map[string]string{
				"AUTHORIZATION": "Bearer operator-secret",
				"cookie":        "session=operator-secret",
			},
			absentHeaders: []string{"Authorization", "Cookie"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			test := HTTPTest{Method: "GET", Path: "/test"}
			operation := &model.Operation{Method: "GET", Path: "/test"}
			variables := map[string]string{"baseURL": "http://localhost"}

			req, err := buildRequest(context.Background(), test, operation, tc.authInfo, variables, tc.customHeaders)
			require.NoError(t, err)

			for name, want := range tc.wantHeaders {
				assert.Equal(t, want, req.Header.Get(name), "header %s", name)
			}
			for _, name := range tc.absentHeaders {
				assert.Empty(t, req.Header.Values(name), "header %s must not be set", name)
			}
		})
	}
}
