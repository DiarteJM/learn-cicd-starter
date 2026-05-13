package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := map[string]struct {
		headers http.Header
		wantKey string
		wantErr string
	}{
		"no authorization header": {
			headers: http.Header{},
			wantErr: "no authorization header included",
		},
		"malformed header missing prefix": {
			headers: http.Header{
				"Authorization": []string{"Bearer some-key"},
			},
			wantErr: "malformed authorization header",
		},
		"malformed header no space": {
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			wantErr: "malformed authorization header",
		},
		"valid api key": {
			headers: http.Header{
				"Authorization": []string{"ApiKey my-secret-key"},
			},
			wantKey: "my-secret-key",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			key, err := GetAPIKey(tc.headers)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error %q, got nil", tc.wantErr)
				}
				if err.Error() != tc.wantErr {
					t.Fatalf("expected error %q, got %q", tc.wantErr, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if key != tc.wantKey {
				t.Fatalf("expected key %q, got %q", tc.wantKey, key)
			}
		})
	}
}
