package cliproxy

import (
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v6/internal/registry"
	coreauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v6/sdk/config"
)

func modelIDs(models []*registry.ModelInfo) map[string]struct{} {
	out := make(map[string]struct{}, len(models))
	for _, model := range models {
		if model == nil {
			continue
		}
		out[model.ID] = struct{}{}
	}
	return out
}

func assertModelSetEqual(t *testing.T, got, want []*registry.ModelInfo) {
	t.Helper()

	gotIDs := modelIDs(got)
	wantIDs := modelIDs(want)
	if len(gotIDs) != len(wantIDs) {
		t.Fatalf("model count = %d, want %d", len(gotIDs), len(wantIDs))
	}
	for id := range wantIDs {
		if _, ok := gotIDs[id]; !ok {
			t.Fatalf("expected model %q to be registered", id)
		}
	}
}

func TestRegisterModelsForAuth_CodexPlanTypeAttributeSelectsTier(t *testing.T) {
	testCases := []struct {
		name     string
		planType string
		want     []*registry.ModelInfo
	}{
		{name: "plus", planType: "plus", want: registry.GetCodexPlusModels()},
		{name: "team", planType: "team", want: registry.GetCodexTeamModels()},
		{name: "free", planType: "free", want: registry.GetCodexFreeModels()},
	}

	reg := registry.GetGlobalRegistry()
	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			authID := "codex-" + tt.name
			reg.UnregisterClient(authID)
			t.Cleanup(func() { reg.UnregisterClient(authID) })

			service := &Service{cfg: &config.Config{}}
			auth := &coreauth.Auth{
				ID:       authID,
				Provider: "codex",
				Status:   coreauth.StatusActive,
				Attributes: map[string]string{
					"plan_type": tt.planType,
				},
				Metadata: map[string]any{
					"id_token": "conflicting-jwt-value",
				},
			}

			service.registerModelsForAuth(auth)

			assertModelSetEqual(t, reg.GetModelsForClient(authID), tt.want)
		})
	}
}
