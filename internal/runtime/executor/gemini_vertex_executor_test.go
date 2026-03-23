package executor

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	vertexauth "github.com/router-for-me/CLIProxyAPI/v6/internal/auth/vertex"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v6/sdk/translator"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func testAmbientExecutorAuth() *cliproxyauth.Auth {
	return &cliproxyauth.Auth{
		ID:       "runtime:vertex:gce",
		Provider: "vertex",
		Status:   cliproxyauth.StatusActive,
		Attributes: map[string]string{
			"runtime_only": "true",
			"auth_kind":    "oauth",
		},
		Metadata: map[string]any{
			"project_id":        "test-project",
			"location":          "europe-west4",
			"email":             "vm@example.com",
			"credential_source": vertexauth.AmbientCredentialSource,
		},
	}
}

func TestPrepareRequestUsesAmbientBearerToken(t *testing.T) {
	origTokenFunc := vertexAmbientAccessTokenFunc
	t.Cleanup(func() {
		vertexAmbientAccessTokenFunc = origTokenFunc
	})
	vertexAmbientAccessTokenFunc = func(context.Context) (string, error) {
		return "ambient-token", nil
	}

	exec := NewGeminiVertexExecutor(nil)
	req, err := http.NewRequest(http.MethodPost, "https://example.com", nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}

	if err := exec.PrepareRequest(req, testAmbientExecutorAuth()); err != nil {
		t.Fatalf("PrepareRequest() error = %v", err)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer ambient-token" {
		t.Fatalf("Authorization = %q, want %q", got, "Bearer ambient-token")
	}
	if got := req.Header.Get("x-goog-api-key"); got != "" {
		t.Fatalf("x-goog-api-key = %q, want empty", got)
	}
}

func TestPrepareRequestMalformedExplicitVertexAuthDoesNotUseAmbient(t *testing.T) {
	calledAmbient := false
	origTokenFunc := vertexAmbientAccessTokenFunc
	t.Cleanup(func() {
		vertexAmbientAccessTokenFunc = origTokenFunc
	})
	vertexAmbientAccessTokenFunc = func(context.Context) (string, error) {
		calledAmbient = true
		return "ambient-token", nil
	}

	exec := NewGeminiVertexExecutor(nil)
	req, err := http.NewRequest(http.MethodPost, "https://example.com", nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}

	err = exec.PrepareRequest(req, &cliproxyauth.Auth{
		ID:       "vertex-explicit",
		Provider: "vertex",
		Status:   cliproxyauth.StatusActive,
		Metadata: map[string]any{
			"project_id": "explicit-project",
			"location":   "us-central1",
		},
	})
	if err == nil {
		t.Fatal("PrepareRequest() error = nil, want error")
	}
	if !strings.Contains(err.Error(), "missing service_account") {
		t.Fatalf("PrepareRequest() error = %v, want missing service_account", err)
	}
	if calledAmbient {
		t.Fatal("expected malformed explicit vertex auth not to fall back to ambient credentials")
	}
}

func TestVertexAmbientCredsDefaultLocation(t *testing.T) {
	projectID, location, err := vertexAmbientCreds(&cliproxyauth.Auth{
		ID:       "runtime:vertex:gce",
		Provider: "vertex",
		Metadata: map[string]any{
			"project_id":        "ambient-project",
			"credential_source": vertexauth.AmbientCredentialSource,
		},
	})
	if err != nil {
		t.Fatalf("vertexAmbientCreds() error = %v", err)
	}
	if projectID != "ambient-project" {
		t.Fatalf("projectID = %q, want %q", projectID, "ambient-project")
	}
	if location != vertexauth.DefaultAmbientLocation {
		t.Fatalf("location = %q, want %q", location, vertexauth.DefaultAmbientLocation)
	}
}

func TestCountTokensWithAmbientCredentialsUsesRegionalProjectURLAndBearerToken(t *testing.T) {
	origTokenFunc := vertexAmbientAccessTokenFunc
	t.Cleanup(func() {
		vertexAmbientAccessTokenFunc = origTokenFunc
	})
	vertexAmbientAccessTokenFunc = func(context.Context) (string, error) {
		return "ambient-token", nil
	}

	var gotURL string
	var gotAuthHeader string
	ctx := context.WithValue(context.Background(), "cliproxy.roundtripper", roundTripFunc(func(req *http.Request) (*http.Response, error) {
		gotURL = req.URL.String()
		gotAuthHeader = req.Header.Get("Authorization")
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(`{"totalTokens":7}`)),
		}, nil
	}))

	exec := NewGeminiVertexExecutor(nil)
	resp, err := exec.CountTokens(ctx, testAmbientExecutorAuth(), cliproxyexecutor.Request{
		Model:   "gemini-2.5-pro",
		Payload: []byte(`{"contents":[{"parts":[{"text":"hi"}]}]}`),
	}, cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FromString("gemini"),
	})
	if err != nil {
		t.Fatalf("CountTokens() error = %v", err)
	}
	if gotAuthHeader != "Bearer ambient-token" {
		t.Fatalf("Authorization = %q, want %q", gotAuthHeader, "Bearer ambient-token")
	}
	wantURL := "https://europe-west4-aiplatform.googleapis.com/v1/projects/test-project/locations/europe-west4/publishers/google/models/gemini-2.5-pro:countTokens"
	if gotURL != wantURL {
		t.Fatalf("request URL = %q, want %q", gotURL, wantURL)
	}
	if !strings.Contains(string(resp.Payload), "7") {
		t.Fatalf("response payload = %s, want translated token count containing 7", resp.Payload)
	}
}
