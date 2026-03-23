package cliproxy

import (
	"context"
	"strings"
	"testing"

	vertexauth "github.com/router-for-me/CLIProxyAPI/v6/internal/auth/vertex"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/watcher"
	coreauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v6/sdk/config"
)

func testAmbientVertexAuth(id string) *coreauth.Auth {
	if strings.TrimSpace(id) == "" {
		id = ambientVertexAuthID
	}
	return &coreauth.Auth{
		ID:       id,
		Provider: "vertex",
		Label:    "vm@example.com",
		Status:   coreauth.StatusActive,
		Attributes: map[string]string{
			"runtime_only": "true",
			"auth_kind":    "oauth",
			"source":       ambientVertexAuthID,
		},
		Metadata: map[string]any{
			"type":              "vertex",
			"project_id":        "ambient-project",
			"location":          "us-central1",
			"email":             "vm@example.com",
			"credential_source": vertexauth.AmbientCredentialSource,
		},
	}
}

func testExplicitVertexAuth(id string) *coreauth.Auth {
	return &coreauth.Auth{
		ID:       id,
		Provider: "vertex",
		Label:    "explicit-project",
		Status:   coreauth.StatusActive,
		Metadata: map[string]any{
			"type":       "vertex",
			"project_id": "explicit-project",
		},
	}
}

func newAmbientVertexTestService(cfg *config.Config) *Service {
	if cfg == nil {
		cfg = &config.Config{}
	}
	manager := coreauth.NewManager(nil, nil, nil)
	manager.SetConfig(cfg)
	return &Service{
		cfg:         cfg,
		coreManager: manager,
	}
}

func activeAmbientAuthCount(service *Service) int {
	count := 0
	for _, auth := range service.coreManager.List() {
		if auth != nil && auth.ID == ambientVertexAuthID && !auth.Disabled {
			count++
		}
	}
	return count
}

func TestSyncAmbientVertexAuthAddsWhenNoExplicitVertexAuth(t *testing.T) {
	origBuilder := buildAmbientVertexRuntimeAuth
	t.Cleanup(func() {
		buildAmbientVertexRuntimeAuth = origBuilder
	})
	buildAmbientVertexRuntimeAuth = func(context.Context) (*coreauth.Auth, error) {
		return testAmbientVertexAuth(ambientVertexAuthID), nil
	}

	service := newAmbientVertexTestService(&config.Config{})
	GlobalModelRegistry().UnregisterClient(ambientVertexAuthID)
	t.Cleanup(func() {
		GlobalModelRegistry().UnregisterClient(ambientVertexAuthID)
	})

	service.syncAmbientVertexAuth(context.Background())

	auth, ok := service.coreManager.GetByID(ambientVertexAuthID)
	if !ok || auth == nil {
		t.Fatal("expected ambient vertex auth to be registered")
	}
	if auth.Disabled {
		t.Fatal("expected ambient vertex auth to remain active")
	}
	if auth.Attributes["runtime_only"] != "true" {
		t.Fatalf("runtime_only = %q, want %q", auth.Attributes["runtime_only"], "true")
	}
	if auth.Attributes["auth_kind"] != "oauth" {
		t.Fatalf("auth_kind = %q, want %q", auth.Attributes["auth_kind"], "oauth")
	}
	if auth.Metadata["credential_source"] != vertexauth.AmbientCredentialSource {
		t.Fatalf("credential_source = %v, want %q", auth.Metadata["credential_source"], vertexauth.AmbientCredentialSource)
	}
}

func TestHandleAuthUpdateExplicitVertexSuppressesAndDeleteRecreatesAmbient(t *testing.T) {
	origBuilder := buildAmbientVertexRuntimeAuth
	t.Cleanup(func() {
		buildAmbientVertexRuntimeAuth = origBuilder
	})
	buildAmbientVertexRuntimeAuth = func(context.Context) (*coreauth.Auth, error) {
		return testAmbientVertexAuth(ambientVertexAuthID), nil
	}

	service := newAmbientVertexTestService(&config.Config{})
	GlobalModelRegistry().UnregisterClient(ambientVertexAuthID)
	GlobalModelRegistry().UnregisterClient("vertex-explicit")
	t.Cleanup(func() {
		GlobalModelRegistry().UnregisterClient(ambientVertexAuthID)
		GlobalModelRegistry().UnregisterClient("vertex-explicit")
	})

	service.syncAmbientVertexAuth(context.Background())

	ambient, ok := service.coreManager.GetByID(ambientVertexAuthID)
	if !ok || ambient == nil || ambient.Disabled {
		t.Fatal("expected initial ambient auth to be active")
	}

	explicit := testExplicitVertexAuth("vertex-explicit")
	service.handleAuthUpdate(context.Background(), watcher.AuthUpdate{
		Action: watcher.AuthUpdateActionAdd,
		ID:     explicit.ID,
		Auth:   explicit,
	})

	ambient, ok = service.coreManager.GetByID(ambientVertexAuthID)
	if !ok || ambient == nil {
		t.Fatal("expected ambient auth record to remain addressable after suppression")
	}
	if !ambient.Disabled {
		t.Fatal("expected ambient auth to be disabled when explicit vertex auth is present")
	}

	service.handleAuthUpdate(context.Background(), watcher.AuthUpdate{
		Action: watcher.AuthUpdateActionDelete,
		ID:     explicit.ID,
	})

	ambient, ok = service.coreManager.GetByID(ambientVertexAuthID)
	if !ok || ambient == nil {
		t.Fatal("expected ambient auth to be recreated after explicit vertex auth deletion")
	}
	if ambient.Disabled {
		t.Fatal("expected recreated ambient auth to be active")
	}
}

func TestSyncAmbientVertexAuthUsesWatcherSnapshotToSuppressStartupRace(t *testing.T) {
	origBuilder := buildAmbientVertexRuntimeAuth
	t.Cleanup(func() {
		buildAmbientVertexRuntimeAuth = origBuilder
	})
	buildAmbientVertexRuntimeAuth = func(context.Context) (*coreauth.Auth, error) {
		return testAmbientVertexAuth(ambientVertexAuthID), nil
	}

	service := newAmbientVertexTestService(&config.Config{})
	service.watcher = &WatcherWrapper{
		snapshotAuths: func() []*coreauth.Auth {
			return []*coreauth.Auth{testExplicitVertexAuth("vertex-config")}
		},
	}
	GlobalModelRegistry().UnregisterClient(ambientVertexAuthID)
	t.Cleanup(func() {
		GlobalModelRegistry().UnregisterClient(ambientVertexAuthID)
	})

	service.syncAmbientVertexAuth(context.Background())

	if _, ok := service.coreManager.GetByID(ambientVertexAuthID); ok {
		t.Fatal("expected watcher snapshot explicit vertex auth to suppress ambient registration")
	}
}

func TestHandleAuthUpdateNonVertexDoesNotDuplicateAmbient(t *testing.T) {
	origBuilder := buildAmbientVertexRuntimeAuth
	t.Cleanup(func() {
		buildAmbientVertexRuntimeAuth = origBuilder
	})
	buildAmbientVertexRuntimeAuth = func(context.Context) (*coreauth.Auth, error) {
		return testAmbientVertexAuth(ambientVertexAuthID), nil
	}

	service := newAmbientVertexTestService(&config.Config{})
	GlobalModelRegistry().UnregisterClient(ambientVertexAuthID)
	GlobalModelRegistry().UnregisterClient("gemini-auth")
	t.Cleanup(func() {
		GlobalModelRegistry().UnregisterClient(ambientVertexAuthID)
		GlobalModelRegistry().UnregisterClient("gemini-auth")
	})

	service.syncAmbientVertexAuth(context.Background())
	service.handleAuthUpdate(context.Background(), watcher.AuthUpdate{
		Action: watcher.AuthUpdateActionAdd,
		ID:     "gemini-auth",
		Auth: &coreauth.Auth{
			ID:       "gemini-auth",
			Provider: "gemini",
			Status:   coreauth.StatusActive,
			Attributes: map[string]string{
				"auth_kind": "oauth",
			},
			Metadata: map[string]any{
				"email": "gemini@example.com",
			},
		},
	})

	if got := activeAmbientAuthCount(service); got != 1 {
		t.Fatalf("active ambient auth count = %d, want 1", got)
	}
}

func TestRegisterModelsForAmbientVertexAuthUsesOAuthAliasesAndExclusions(t *testing.T) {
	service := newAmbientVertexTestService(&config.Config{
		OAuthExcludedModels: map[string][]string{
			"vertex": {"gemini-2.5-flash"},
		},
		OAuthModelAlias: map[string][]config.OAuthModelAlias{
			"vertex": {
				{Name: "gemini-2.5-pro", Alias: "ambient-pro", Fork: true},
			},
		},
	})
	auth := testAmbientVertexAuth("ambient-models")
	registry := GlobalModelRegistry()
	registry.UnregisterClient(auth.ID)
	t.Cleanup(func() {
		registry.UnregisterClient(auth.ID)
	})

	service.registerModelsForAuth(auth)

	models := registry.GetAvailableModelsByProvider("vertex")
	if len(models) == 0 {
		t.Fatal("expected vertex models to be registered")
	}

	seenAlias := false
	for _, model := range models {
		if model == nil {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(model.ID), "ambient-pro") {
			seenAlias = true
		}
		if strings.EqualFold(strings.TrimSpace(model.ID), "gemini-2.5-flash") {
			t.Fatal("expected OAuth excluded vertex model to be filtered out")
		}
	}
	if !seenAlias {
		t.Fatal("expected OAuth model alias to be registered for ambient vertex auth")
	}
}
