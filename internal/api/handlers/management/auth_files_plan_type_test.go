package management

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
)

func testManagementJWTWithPlanType(t *testing.T, planType string) string {
	t.Helper()

	header, err := json.Marshal(map[string]any{"alg": "none", "typ": "JWT"})
	if err != nil {
		t.Fatalf("marshal jwt header: %v", err)
	}
	payload, err := json.Marshal(map[string]any{
		"https://api.openai.com/auth": map[string]any{
			"chatgpt_plan_type": planType,
		},
	})
	if err != nil {
		t.Fatalf("marshal jwt payload: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(header) + "." +
		base64.RawURLEncoding.EncodeToString(payload) + "."
}

func TestUploadAuthFile_CodexPlanTypeOverrideRegisteredAndListed(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "")
	gin.SetMode(gin.TestMode)

	authDir := t.TempDir()
	manager := coreauth.NewManager(nil, nil, nil)
	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: authDir}, manager)

	body, err := json.Marshal(map[string]any{
		"type":      "codex",
		"email":     "codex@example.com",
		"plan_type": "plus",
		"id_token":  testManagementJWTWithPlanType(t, "team"),
	})
	if err != nil {
		t.Fatalf("marshal upload body: %v", err)
	}

	uploadRec := httptest.NewRecorder()
	uploadCtx, _ := gin.CreateTestContext(uploadRec)
	uploadReq := httptest.NewRequest(http.MethodPost, "/v0/management/auth-files?name="+url.QueryEscape("codex-plan.json"), strings.NewReader(string(body)))
	uploadCtx.Request = uploadReq
	h.UploadAuthFile(uploadCtx)

	if uploadRec.Code != http.StatusOK {
		t.Fatalf("expected upload status %d, got %d with body %s", http.StatusOK, uploadRec.Code, uploadRec.Body.String())
	}

	auth, ok := manager.GetByID("codex-plan.json")
	if !ok || auth == nil {
		t.Fatal("expected uploaded auth to be registered immediately")
	}
	if got := strings.TrimSpace(auth.Attributes["plan_type"]); got != "plus" {
		t.Fatalf("registered plan_type = %q, want %q", got, "plus")
	}

	listRec := httptest.NewRecorder()
	listCtx, _ := gin.CreateTestContext(listRec)
	listReq := httptest.NewRequest(http.MethodGet, "/v0/management/auth-files", nil)
	listCtx.Request = listReq
	h.ListAuthFiles(listCtx)

	if listRec.Code != http.StatusOK {
		t.Fatalf("expected list status %d, got %d with body %s", http.StatusOK, listRec.Code, listRec.Body.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(listRec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode list response: %v", err)
	}
	files, ok := payload["files"].([]any)
	if !ok || len(files) != 1 {
		t.Fatalf("expected one file in list response, got %#v", payload["files"])
	}
	entry, ok := files[0].(map[string]any)
	if !ok {
		t.Fatalf("expected auth entry object, got %#v", files[0])
	}
	if got := strings.TrimSpace(entry["plan_type"].(string)); got != "plus" {
		t.Fatalf("list plan_type = %q, want %q", got, "plus")
	}
	idToken, ok := entry["id_token"].(map[string]any)
	if !ok {
		t.Fatalf("expected id_token claims in response, got %#v", entry["id_token"])
	}
	if got := strings.TrimSpace(idToken["plan_type"].(string)); got != "team" {
		t.Fatalf("raw jwt plan_type = %q, want %q", got, "team")
	}
}
