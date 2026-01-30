package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name          string
		headers       http.Header
		expectedKey   string
		expectedError error
		errorContains string
	}{
		{
			name:          "no authorization header",
			headers:       http.Header{},
			expectedKey:   "",
			expectedError: ErrNoAuthHeaderIncluded,
		},
		{
			name: "empty authorization header",
			headers: http.Header{
				"Authorization": {""},
			},
			expectedKey:   "",
			expectedError: ErrNoAuthHeaderIncluded,
		},
		{
			name: "valid ApiKey header",
			headers: http.Header{
				"Authorization": {"ApiKey my-secret-api-key"},
			},
			expectedKey:   "my-secret-api-key",
			expectedError: nil,
		},
		{
			name: "wrong auth scheme - Bearer instead of ApiKey",
			headers: http.Header{
				"Authorization": {"Bearer some-token"},
			},
			expectedKey:   "",
			errorContains: "malformed authorization header",
		},
		{
			name: "wrong auth scheme - Basic instead of ApiKey",
			headers: http.Header{
				"Authorization": {"Basic dXNlcjpwYXNz"},
			},
			expectedKey:   "",
			errorContains: "malformed authorization header",
		},
		{
			name: "malformed header - only ApiKey no value",
			headers: http.Header{
				"Authorization": {"ApiKey"},
			},
			expectedKey:   "",
			errorContains: "malformed authorization header",
		},
		{
			name: "malformed header - single random word",
			headers: http.Header{
				"Authorization": {"randomstring"},
			},
			expectedKey:   "",
			errorContains: "malformed authorization header",
		},
		{
			name: "case sensitive - lowercase apikey",
			headers: http.Header{
				"Authorization": {"apikey my-secret-api-key"},
			},
			expectedKey:   "",
			errorContains: "malformed authorization header",
		},
		{
			name: "case sensitive - uppercase APIKEY",
			headers: http.Header{
				"Authorization": {"APIKEY my-secret-api-key"},
			},
			expectedKey:   "",
			errorContains: "malformed authorization header",
		},
		{
			name: "ApiKey with multiple spaces in value",
			headers: http.Header{
				"Authorization": {"ApiKey key-with extra-parts"},
			},
			expectedKey:   "key-with",
			expectedError: nil,
		},
		{
			name: "ApiKey with empty key after space",
			headers: http.Header{
				"Authorization": {"ApiKey "},
			},
			expectedKey:   "",
			expectedError: nil,
		},
		{
			name: "ApiKey with special characters in key",
			headers: http.Header{
				"Authorization": {"ApiKey abc123!@#$%^&*()_+-="},
			},
			expectedKey:   "abc123!@#$%^&*()_+-=",
			expectedError: nil,
		},
		{
			name: "ApiKey with UUID format",
			headers: http.Header{
				"Authorization": {"ApiKey 550e8400-e29b-41d4-a716-446655440000"},
			},
			expectedKey:   "550e8400-e29b-41d4-a716-446655440000",
			expectedError: nil,
		},
		{
			name: "whitespace only authorization header",
			headers: http.Header{
				"Authorization": {"   "},
			},
			expectedKey:   "",
			errorContains: "malformed authorization header",
		},
		{
			name: "ApiKey with leading spaces",
			headers: http.Header{
				"Authorization": {"  ApiKey my-key"},
			},
			expectedKey:   "",
			errorContains: "malformed authorization header",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GetAPIKey(tt.headers)

			if key != tt.expectedKey {
				t.Errorf("expected key %q, got %q", tt.expectedKey, key)
			}

			if tt.expectedError != nil {
				if err != tt.expectedError {
					t.Errorf("expected error %v, got %v", tt.expectedError, err)
				}
			} else if tt.errorContains != "" {
				if err == nil {
					t.Errorf("expected error containing %q, got nil", tt.errorContains)
				} else if !contains(err.Error(), tt.errorContains) {
					t.Errorf("expected error containing %q, got %v", tt.errorContains, err)
				}
			} else if err != nil {
				t.Errorf("expected no error, got %v", err)
			}
		})
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && searchSubstring(s, substr)))
}

func searchSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
