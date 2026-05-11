package claude

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/tidwall/gjson"
)

func TestClaudeMessagesEndsWithAssistant(t *testing.T) {
	cases := []struct {
		name string
		body string
		want bool
	}{
		{
			name: "ends with assistant",
			body: `{"messages":[{"role":"user","content":"hi"},{"role":"assistant","content":"hello"}]}`,
			want: true,
		},
		{
			name: "ends with user",
			body: `{"messages":[{"role":"assistant","content":"hi"},{"role":"user","content":"ok"}]}`,
			want: false,
		},
		{
			name: "ends with assistant (tool_use + text)",
			body: `{"messages":[{"role":"user","content":[{"type":"text","text":"hi"}]},{"role":"assistant","content":[{"type":"text","text":"done"},{"type":"thinking","thinking":"","signature":"sig"}]}]}`,
			want: true,
		},
		{
			name: "single user message",
			body: `{"messages":[{"role":"user","content":"hi"}]}`,
			want: false,
		},
		{
			name: "empty messages",
			body: `{"messages":[]}`,
			want: false,
		},
		{
			name: "missing messages",
			body: `{"model":"claude-opus-4-7"}`,
			want: false,
		},
		{
			name: "messages not array",
			body: `{"messages":"oops"}`,
			want: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := claudeMessagesEndsWithAssistant([]byte(tc.body)); got != tc.want {
				t.Errorf("claudeMessagesEndsWithAssistant(%q) = %v, want %v", tc.body, got, tc.want)
			}
		})
	}
}

// newPreflightTestRouter builds a router whose ClaudeMessages handler runs the
// pre-flight guard. The BaseAPIHandler is left nil; any path that proceeds past
// the guard will nil-panic inside handleNonStreamingResponse, which gin.Recovery
// turns into a 500. That is the intended signal for "guard did NOT fire" cases -
// we only assert on the guard-specific 400 here.
func newPreflightTestRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	h := &ClaudeCodeAPIHandler{}
	router := gin.New()
	router.Use(gin.Recovery())
	router.POST("/v1/messages", h.ClaudeMessages)
	return router
}

func TestClaudeMessages_PreflightRejectsTrailingAssistant(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{
			name: "opus 4.7 (the original report)",
			body: `{
				"model": "claude-opus-4-7",
				"max_tokens": 1024,
				"messages": [
					{"role":"user","content":[{"type":"text","text":"hi"}]},
					{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_1","content":"out"}]},
					{"role":"assistant","content":[{"type":"text","text":"done"},{"type":"thinking","thinking":"","signature":"sig"}]}
				]
			}`,
		},
		{
			name: "opus 4.7 with thinking suffix",
			body: `{
				"model": "claude-opus-4-7(16384)",
				"max_tokens": 1024,
				"messages": [
					{"role":"user","content":"hi"},
					{"role":"assistant","content":"prefill"}
				]
			}`,
		},
		{
			name: "claude-3-5-sonnet (universally guarded, even if upstream accepts prefill)",
			body: `{
				"model": "claude-3-5-sonnet-20241022",
				"max_tokens": 1024,
				"messages": [
					{"role":"user","content":"hi"},
					{"role":"assistant","content":"prefill"}
				]
			}`,
		},
		{
			name: "claude-sonnet-4-5",
			body: `{
				"model": "claude-sonnet-4-5",
				"max_tokens": 1024,
				"messages": [
					{"role":"user","content":"hi"},
					{"role":"assistant","content":"prefill"}
				]
			}`,
		},
		{
			name: "claude-haiku-4-5",
			body: `{
				"model": "claude-haiku-4-5",
				"max_tokens": 1024,
				"messages": [
					{"role":"user","content":"hi"},
					{"role":"assistant","content":"prefill"}
				]
			}`,
		},
		{
			name: "model field absent (still rejected on structure)",
			body: `{
				"max_tokens": 1024,
				"messages": [
					{"role":"user","content":"hi"},
					{"role":"assistant","content":"prefill"}
				]
			}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/v1/messages", bytes.NewReader([]byte(tc.body)))
			req.Header.Set("Content-Type", "application/json")
			resp := httptest.NewRecorder()
			newPreflightTestRouter().ServeHTTP(resp, req)

			if resp.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d. body=%s", resp.Code, http.StatusBadRequest, resp.Body.String())
			}
			if got := gjson.GetBytes(resp.Body.Bytes(), "error.message").String(); got != assistantPrefillRejectionMessage {
				t.Fatalf("error.message = %q, want %q", got, assistantPrefillRejectionMessage)
			}
			if got := gjson.GetBytes(resp.Body.Bytes(), "error.type").String(); got != "invalid_request_error" {
				t.Fatalf("error.type = %q, want invalid_request_error", got)
			}
		})
	}
}

func TestClaudeMessages_PreflightDoesNotFireWhenConversationEndsWithUser(t *testing.T) {
	body := []byte(`{
		"model": "claude-opus-4-7",
		"max_tokens": 1024,
		"messages": [
			{"role":"user","content":"hi"},
			{"role":"assistant","content":"prior"},
			{"role":"user","content":"now answer"}
		]
	}`)

	req := httptest.NewRequest(http.MethodPost, "/v1/messages", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()
	newPreflightTestRouter().ServeHTTP(resp, req)

	if resp.Code == http.StatusBadRequest {
		if got := gjson.GetBytes(resp.Body.Bytes(), "error.message").String(); got == assistantPrefillRejectionMessage {
			t.Fatalf("guard fired on conversation that correctly ends with user: %s", resp.Body.String())
		}
	}
}
