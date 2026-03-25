package auth

import (
	"context"
	"net/http"
	"testing"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/executor"
)

type mutatingRequestPreparerExecutor struct{}

func (mutatingRequestPreparerExecutor) Identifier() string { return "claude" }

func (mutatingRequestPreparerExecutor) Execute(ctx context.Context, auth *Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return cliproxyexecutor.Response{}, nil
}

func (mutatingRequestPreparerExecutor) ExecuteStream(ctx context.Context, auth *Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	return nil, nil
}

func (mutatingRequestPreparerExecutor) Refresh(ctx context.Context, auth *Auth) (*Auth, error) {
	return auth, nil
}

func (mutatingRequestPreparerExecutor) CountTokens(ctx context.Context, auth *Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return cliproxyexecutor.Response{}, nil
}

func (mutatingRequestPreparerExecutor) HttpRequest(ctx context.Context, auth *Auth, req *http.Request) (*http.Response, error) {
	return nil, nil
}

func (mutatingRequestPreparerExecutor) PrepareRequest(req *http.Request, auth *Auth) error {
	if auth.Metadata == nil {
		auth.Metadata = make(map[string]any)
	}
	auth.Metadata["access_token"] = "mutated-token"
	req.Header.Set("Authorization", "Bearer mutated-token")
	return nil
}

func TestManagerPrepareHttpRequest_UsesAuthCloneForPreparer(t *testing.T) {
	ctx := context.Background()
	manager := NewManager(nil, &RoundRobinSelector{}, nil)
	manager.RegisterExecutor(mutatingRequestPreparerExecutor{})

	auth := &Auth{
		ID:       "claude-auth",
		Provider: "claude",
		Metadata: map[string]any{
			"access_token": "original-token",
		},
	}
	if _, err := manager.Register(ctx, auth); err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	manager.mu.RLock()
	stored := manager.auths[auth.ID]
	manager.mu.RUnlock()

	req, err := http.NewRequest(http.MethodGet, "https://example.com", nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}

	if err := manager.PrepareHttpRequest(ctx, stored, req); err != nil {
		t.Fatalf("PrepareHttpRequest() error = %v", err)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer mutated-token" {
		t.Fatalf("Authorization = %q, want %q", got, "Bearer mutated-token")
	}

	manager.mu.RLock()
	defer manager.mu.RUnlock()
	if got := manager.auths[auth.ID].Metadata["access_token"]; got != "original-token" {
		t.Fatalf("stored access_token = %v, want %q", got, "original-token")
	}
}

func TestManagerInjectCredentials_UsesAuthCloneForPreparer(t *testing.T) {
	ctx := context.Background()
	manager := NewManager(nil, &RoundRobinSelector{}, nil)
	manager.RegisterExecutor(mutatingRequestPreparerExecutor{})

	auth := &Auth{
		ID:       "claude-auth",
		Provider: "claude",
		Metadata: map[string]any{
			"access_token": "original-token",
		},
	}
	if _, err := manager.Register(ctx, auth); err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	req, err := http.NewRequest(http.MethodGet, "https://example.com", nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}

	if err := manager.InjectCredentials(req, auth.ID); err != nil {
		t.Fatalf("InjectCredentials() error = %v", err)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer mutated-token" {
		t.Fatalf("Authorization = %q, want %q", got, "Bearer mutated-token")
	}

	manager.mu.RLock()
	defer manager.mu.RUnlock()
	if got := manager.auths[auth.ID].Metadata["access_token"]; got != "original-token" {
		t.Fatalf("stored access_token = %v, want %q", got, "original-token")
	}
}
