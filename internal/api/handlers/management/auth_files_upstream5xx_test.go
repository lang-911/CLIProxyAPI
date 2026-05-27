package management

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

func mark500(manager *coreauth.Manager, authID, model string) {
	manager.MarkResult(context.Background(), coreauth.Result{
		AuthID:   authID,
		Provider: "claude",
		Model:    model,
		Success:  false,
		Error:    &coreauth.Error{HTTPStatus: 500, Message: "boom"},
	})
}

func registerManagementUpstream5xxAuth(t *testing.T, manager *coreauth.Manager) {
	t.Helper()
	record := &coreauth.Auth{
		ID:         "x.json",
		FileName:   "x.json",
		Provider:   "claude",
		Attributes: map[string]string{"path": "/tmp/x.json"},
		Metadata:   map[string]any{"type": "claude"},
	}
	if _, errRegister := manager.Register(context.Background(), record); errRegister != nil {
		t.Fatalf("failed to register auth record: %v", errRegister)
	}
}

func getManagementUpstream5xxAuth(t *testing.T, manager *coreauth.Manager) *coreauth.Auth {
	t.Helper()
	updated, ok := manager.GetByID("x.json")
	if !ok || updated == nil {
		t.Fatalf("expected auth record to exist")
	}
	return updated
}

func patchAuthFileDisabled(t *testing.T, h *Handler, disabled bool) {
	t.Helper()
	body := `{"name":"x.json","disabled":false}`
	if disabled {
		body = `{"name":"x.json","disabled":true}`
	}
	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	req := httptest.NewRequest(http.MethodPatch, "/v0/management/auth-files/status", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	ctx.Request = req
	h.PatchAuthFileStatus(ctx)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestPatchAuthFileStatus_ResetsCounterOnReenable(t *testing.T) {
	gin.SetMode(gin.TestMode)
	coreauth.SetUpstream5xxSuspendThreshold(2)
	t.Cleanup(func() { coreauth.SetUpstream5xxSuspendThreshold(5) })

	store := &memoryAuthStore{}
	manager := coreauth.NewManager(store, nil, nil)
	registerManagementUpstream5xxAuth(t, manager)
	mark500(manager, "x.json", "m")
	mark500(manager, "x.json", "m")
	updated := getManagementUpstream5xxAuth(t, manager)
	if !updated.Disabled || updated.ConsecutiveUpstream5xxCount() != 2 {
		t.Fatalf("auth disabled=%v count=%d, want true 2", updated.Disabled, updated.ConsecutiveUpstream5xxCount())
	}

	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: t.TempDir()}, manager)
	patchAuthFileDisabled(t, h, false)
	updated = getManagementUpstream5xxAuth(t, manager)
	if updated.Disabled || updated.ConsecutiveUpstream5xxCount() != 0 {
		t.Fatalf("after re-enable disabled=%v count=%d, want false 0", updated.Disabled, updated.ConsecutiveUpstream5xxCount())
	}
	mark500(manager, "x.json", "m")
	updated = getManagementUpstream5xxAuth(t, manager)
	if updated.Disabled || updated.ConsecutiveUpstream5xxCount() != 1 {
		t.Fatalf("after one more 500 disabled=%v count=%d, want false 1", updated.Disabled, updated.ConsecutiveUpstream5xxCount())
	}
}

func TestPatchAuthFileStatus_NoResetWhenStillEnabled(t *testing.T) {
	gin.SetMode(gin.TestMode)
	coreauth.SetUpstream5xxSuspendThreshold(3)
	t.Cleanup(func() { coreauth.SetUpstream5xxSuspendThreshold(5) })

	store := &memoryAuthStore{}
	manager := coreauth.NewManager(store, nil, nil)
	registerManagementUpstream5xxAuth(t, manager)
	mark500(manager, "x.json", "m")
	updated := getManagementUpstream5xxAuth(t, manager)
	if updated.Disabled || updated.ConsecutiveUpstream5xxCount() != 1 {
		t.Fatalf("before patch disabled=%v count=%d, want false 1", updated.Disabled, updated.ConsecutiveUpstream5xxCount())
	}

	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: t.TempDir()}, manager)
	patchAuthFileDisabled(t, h, false)
	updated = getManagementUpstream5xxAuth(t, manager)
	if updated.ConsecutiveUpstream5xxCount() != 1 {
		t.Fatalf("after false->false count=%d, want 1", updated.ConsecutiveUpstream5xxCount())
	}
	mark500(manager, "x.json", "m")
	mark500(manager, "x.json", "m")
	updated = getManagementUpstream5xxAuth(t, manager)
	if !updated.Disabled || updated.ConsecutiveUpstream5xxCount() != 3 {
		t.Fatalf("after threshold disabled=%v count=%d, want true 3", updated.Disabled, updated.ConsecutiveUpstream5xxCount())
	}
}

func TestPatchAuthFileStatus_NoResetWhenDisablingOnly(t *testing.T) {
	gin.SetMode(gin.TestMode)
	coreauth.SetUpstream5xxSuspendThreshold(2)
	t.Cleanup(func() { coreauth.SetUpstream5xxSuspendThreshold(5) })

	store := &memoryAuthStore{}
	manager := coreauth.NewManager(store, nil, nil)
	registerManagementUpstream5xxAuth(t, manager)
	mark500(manager, "x.json", "m")
	updated := getManagementUpstream5xxAuth(t, manager)
	if updated.Disabled || updated.ConsecutiveUpstream5xxCount() != 1 {
		t.Fatalf("before patch disabled=%v count=%d, want false 1", updated.Disabled, updated.ConsecutiveUpstream5xxCount())
	}

	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: t.TempDir()}, manager)
	patchAuthFileDisabled(t, h, true)
	updated = getManagementUpstream5xxAuth(t, manager)
	if !updated.Disabled || updated.ConsecutiveUpstream5xxCount() != 1 {
		t.Fatalf("after disable disabled=%v count=%d, want true 1", updated.Disabled, updated.ConsecutiveUpstream5xxCount())
	}
	patchAuthFileDisabled(t, h, false)
	updated = getManagementUpstream5xxAuth(t, manager)
	if updated.Disabled || updated.ConsecutiveUpstream5xxCount() != 0 {
		t.Fatalf("after re-enable disabled=%v count=%d, want false 0", updated.Disabled, updated.ConsecutiveUpstream5xxCount())
	}
	mark500(manager, "x.json", "m")
	updated = getManagementUpstream5xxAuth(t, manager)
	if updated.Disabled || updated.ConsecutiveUpstream5xxCount() != 1 {
		t.Fatalf("after one more 500 disabled=%v count=%d, want false 1", updated.Disabled, updated.ConsecutiveUpstream5xxCount())
	}
}
