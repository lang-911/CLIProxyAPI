package executor

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/klauspost/compress/zstd"
	xxHash64 "github.com/pierrec/xxHash/xxHash64"
	claudeauth "github.com/router-for-me/CLIProxyAPI/v6/internal/auth/claude"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/logging"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/runtime/executor/helps"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v6/sdk/translator"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

func resetClaudeDeviceProfileCache() {
	helps.ResetClaudeDeviceProfileCache()
}

func newClaudeHeaderTestRequest(t *testing.T, incoming http.Header) *http.Request {
	t.Helper()

	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	ginCtx, _ := gin.CreateTestContext(recorder)
	ginReq := httptest.NewRequest(http.MethodPost, "http://localhost/v1/messages", nil)
	ginReq.Header = incoming.Clone()
	ginCtx.Request = ginReq

	req := httptest.NewRequest(http.MethodPost, "https://api.anthropic.com/v1/messages", nil)
	return req.WithContext(context.WithValue(req.Context(), "gin", ginCtx))
}

func stubClaudeRefreshTokens(t *testing.T, fn func(context.Context, *config.Config, string) (*claudeauth.ClaudeTokenData, error)) {
	t.Helper()
	original := claudeRefreshTokensFunc
	claudeRefreshTokensFunc = fn
	t.Cleanup(func() {
		claudeRefreshTokensFunc = original
	})
}

func newClaudeOAuthTestAuth(accessToken, refreshToken, baseURL string, expiry time.Time) *cliproxyauth.Auth {
	attributes := map[string]string{}
	if strings.TrimSpace(baseURL) != "" {
		attributes["base_url"] = baseURL
	}
	return &cliproxyauth.Auth{
		Provider:   "claude",
		Attributes: attributes,
		Metadata: map[string]any{
			"access_token":  accessToken,
			"refresh_token": refreshToken,
			"expired":       expiry.Format(time.RFC3339),
			"email":         "user@example.com",
			"type":          "claude",
		},
	}
}

func assertClaudeFingerprint(t *testing.T, headers http.Header, userAgent, pkgVersion, runtimeVersion, osName, arch string) {
	t.Helper()

	if got := headers.Get("User-Agent"); got != userAgent {
		t.Fatalf("User-Agent = %q, want %q", got, userAgent)
	}
	if got := headers.Get("X-Stainless-Package-Version"); got != pkgVersion {
		t.Fatalf("X-Stainless-Package-Version = %q, want %q", got, pkgVersion)
	}
	if got := headers.Get("X-Stainless-Runtime-Version"); got != runtimeVersion {
		t.Fatalf("X-Stainless-Runtime-Version = %q, want %q", got, runtimeVersion)
	}
	if got := headers.Get("X-Stainless-Os"); got != osName {
		t.Fatalf("X-Stainless-Os = %q, want %q", got, osName)
	}
	if got := headers.Get("X-Stainless-Arch"); got != arch {
		t.Fatalf("X-Stainless-Arch = %q, want %q", got, arch)
	}
}

func assertBillingHeaderVersion(t *testing.T, billingHeader, version string) {
	t.Helper()

	want := "cc_version=" + version + "."
	if !strings.Contains(billingHeader, want) {
		t.Fatalf("billing header = %q, want substring %q", billingHeader, want)
	}
}

func assertStructuredClaudeUserID(t *testing.T, raw, deviceID, sessionID string) {
	t.Helper()

	if !gjson.ValidBytes([]byte(raw)) {
		t.Fatalf("metadata.user_id should be valid JSON, got %q", raw)
	}

	parsed := gjson.Parse(raw)
	if got := parsed.Get("device_id").String(); got != deviceID {
		t.Fatalf("metadata.user_id.device_id = %q, want %q", got, deviceID)
	}
	if got := parsed.Get("account_uuid").String(); got != "" {
		t.Fatalf("metadata.user_id.account_uuid = %q, want empty", got)
	}
	if got := parsed.Get("session_id").String(); got != sessionID {
		t.Fatalf("metadata.user_id.session_id = %q, want %q", got, sessionID)
	}
}

func TestApplyClaudeHeaders_UsesConfiguredBaselineFingerprint(t *testing.T) {
	resetClaudeDeviceProfileCache()
	stabilize := true

	cfg := &config.Config{
		ClaudeHeaderDefaults: config.ClaudeHeaderDefaults{
			UserAgent:              "claude-cli/2.1.70 (external, cli)",
			PackageVersion:         "0.80.0",
			RuntimeVersion:         "v24.5.0",
			OS:                     "MacOS",
			Arch:                   "arm64",
			Timeout:                "900",
			StabilizeDeviceProfile: &stabilize,
		},
	}
	auth := &cliproxyauth.Auth{
		ID: "auth-baseline",
		Attributes: map[string]string{
			"api_key":                            "key-baseline",
			"header:User-Agent":                  "evil-client/9.9",
			"header:X-Stainless-Os":              "Linux",
			"header:X-Stainless-Arch":            "x64",
			"header:X-Stainless-Package-Version": "9.9.9",
		},
	}
	incoming := http.Header{
		"User-Agent":                  []string{"curl/8.7.1"},
		"X-Stainless-Package-Version": []string{"0.10.0"},
		"X-Stainless-Runtime-Version": []string{"v18.0.0"},
		"X-Stainless-Os":              []string{"Linux"},
		"X-Stainless-Arch":            []string{"x64"},
	}

	req := newClaudeHeaderTestRequest(t, incoming)
	applyClaudeHeaders(req, "", auth, "key-baseline", false, nil, cfg)

	assertClaudeFingerprint(t, req.Header, "evil-client/9.9", "9.9.9", "v24.5.0", "Linux", "x64")
	if got := req.Header.Get("X-Stainless-Timeout"); got != "900" {
		t.Fatalf("X-Stainless-Timeout = %q, want %q", got, "900")
	}
}

func TestApplyClaudeHeaders_UsesIncomingClaudeSessionID(t *testing.T) {
	req := newClaudeHeaderTestRequest(t, http.Header{
		"X-Claude-Code-Session-Id": []string{"incoming-session-id"},
	})
	auth := &cliproxyauth.Auth{
		ID: "auth-session-id",
		Attributes: map[string]string{
			"api_key":                         "key-session-id",
			"header:X-Claude-Code-Session-Id": "overridden-by-proxy",
		},
	}

	applyClaudeHeaders(req, "", auth, "key-session-id", false, nil, nil)

	if got := req.Header.Get("X-Claude-Code-Session-Id"); got != "incoming-session-id" {
		t.Fatalf("X-Claude-Code-Session-Id = %q, want %q", got, "incoming-session-id")
	}
}

func TestApplyClaudeHeaders_TracksHighestClaudeCLIFingerprint(t *testing.T) {
	resetClaudeDeviceProfileCache()
	stabilize := true

	cfg := &config.Config{
		ClaudeHeaderDefaults: config.ClaudeHeaderDefaults{
			UserAgent:              "claude-cli/2.1.60 (external, cli)",
			PackageVersion:         "0.70.0",
			RuntimeVersion:         "v22.0.0",
			OS:                     "MacOS",
			Arch:                   "arm64",
			StabilizeDeviceProfile: &stabilize,
		},
	}
	auth := &cliproxyauth.Auth{
		ID: "auth-upgrade",
		Attributes: map[string]string{
			"api_key": "key-upgrade",
		},
	}

	firstReq := newClaudeHeaderTestRequest(t, http.Header{
		"User-Agent":                  []string{"claude-cli/2.1.62 (external, cli)"},
		"X-Stainless-Package-Version": []string{"0.74.0"},
		"X-Stainless-Runtime-Version": []string{"v24.3.0"},
		"X-Stainless-Os":              []string{"Linux"},
		"X-Stainless-Arch":            []string{"x64"},
	})
	applyClaudeHeaders(firstReq, "", auth, "key-upgrade", false, nil, cfg)
	assertClaudeFingerprint(t, firstReq.Header, "claude-cli/2.1.62 (external, cli)", "0.74.0", "v24.3.0", "MacOS", "arm64")

	thirdPartyReq := newClaudeHeaderTestRequest(t, http.Header{
		"User-Agent":                  []string{"lobe-chat/1.0"},
		"X-Stainless-Package-Version": []string{"0.10.0"},
		"X-Stainless-Runtime-Version": []string{"v18.0.0"},
		"X-Stainless-Os":              []string{"Windows"},
		"X-Stainless-Arch":            []string{"x64"},
	})
	applyClaudeHeaders(thirdPartyReq, "", auth, "key-upgrade", false, nil, cfg)
	assertClaudeFingerprint(t, thirdPartyReq.Header, "claude-cli/2.1.62 (external, cli)", "0.74.0", "v24.3.0", "MacOS", "arm64")

	higherReq := newClaudeHeaderTestRequest(t, http.Header{
		"User-Agent":                  []string{"claude-cli/2.1.63 (external, cli)"},
		"X-Stainless-Package-Version": []string{"0.75.0"},
		"X-Stainless-Runtime-Version": []string{"v24.4.0"},
		"X-Stainless-Os":              []string{"MacOS"},
		"X-Stainless-Arch":            []string{"arm64"},
	})
	applyClaudeHeaders(higherReq, "", auth, "key-upgrade", false, nil, cfg)
	assertClaudeFingerprint(t, higherReq.Header, "claude-cli/2.1.63 (external, cli)", "0.75.0", "v24.4.0", "MacOS", "arm64")

	lowerReq := newClaudeHeaderTestRequest(t, http.Header{
		"User-Agent":                  []string{"claude-cli/2.1.61 (external, cli)"},
		"X-Stainless-Package-Version": []string{"0.73.0"},
		"X-Stainless-Runtime-Version": []string{"v24.2.0"},
		"X-Stainless-Os":              []string{"Windows"},
		"X-Stainless-Arch":            []string{"x64"},
	})
	applyClaudeHeaders(lowerReq, "", auth, "key-upgrade", false, nil, cfg)
	assertClaudeFingerprint(t, lowerReq.Header, "claude-cli/2.1.63 (external, cli)", "0.75.0", "v24.4.0", "MacOS", "arm64")
}

func TestApplyClaudeHeaders_DoesNotDowngradeConfiguredBaselineOnFirstClaudeClient(t *testing.T) {
	resetClaudeDeviceProfileCache()
	stabilize := true

	cfg := &config.Config{
		ClaudeHeaderDefaults: config.ClaudeHeaderDefaults{
			UserAgent:              "claude-cli/2.1.70 (external, cli)",
			PackageVersion:         "0.80.0",
			RuntimeVersion:         "v24.5.0",
			OS:                     "MacOS",
			Arch:                   "arm64",
			StabilizeDeviceProfile: &stabilize,
		},
	}
	auth := &cliproxyauth.Auth{
		ID: "auth-baseline-floor",
		Attributes: map[string]string{
			"api_key": "key-baseline-floor",
		},
	}

	olderClaudeReq := newClaudeHeaderTestRequest(t, http.Header{
		"User-Agent":                  []string{"claude-cli/2.1.62 (external, cli)"},
		"X-Stainless-Package-Version": []string{"0.74.0"},
		"X-Stainless-Runtime-Version": []string{"v24.3.0"},
		"X-Stainless-Os":              []string{"Linux"},
		"X-Stainless-Arch":            []string{"x64"},
	})
	applyClaudeHeaders(olderClaudeReq, "", auth, "key-baseline-floor", false, nil, cfg)
	assertClaudeFingerprint(t, olderClaudeReq.Header, "claude-cli/2.1.70 (external, cli)", "0.80.0", "v24.5.0", "MacOS", "arm64")

	newerClaudeReq := newClaudeHeaderTestRequest(t, http.Header{
		"User-Agent":                  []string{"claude-cli/2.1.71 (external, cli)"},
		"X-Stainless-Package-Version": []string{"0.81.0"},
		"X-Stainless-Runtime-Version": []string{"v24.6.0"},
		"X-Stainless-Os":              []string{"Linux"},
		"X-Stainless-Arch":            []string{"x64"},
	})
	applyClaudeHeaders(newerClaudeReq, "", auth, "key-baseline-floor", false, nil, cfg)
	assertClaudeFingerprint(t, newerClaudeReq.Header, "claude-cli/2.1.71 (external, cli)", "0.81.0", "v24.6.0", "MacOS", "arm64")
}

func TestApplyClaudeHeaders_UpgradesCachedSoftwareFingerprintWhenBaselineAdvances(t *testing.T) {
	resetClaudeDeviceProfileCache()
	stabilize := true

	oldCfg := &config.Config{
		ClaudeHeaderDefaults: config.ClaudeHeaderDefaults{
			UserAgent:              "claude-cli/2.1.70 (external, cli)",
			PackageVersion:         "0.80.0",
			RuntimeVersion:         "v24.5.0",
			OS:                     "MacOS",
			Arch:                   "arm64",
			StabilizeDeviceProfile: &stabilize,
		},
	}
	newCfg := &config.Config{
		ClaudeHeaderDefaults: config.ClaudeHeaderDefaults{
			UserAgent:              "claude-cli/2.1.77 (external, cli)",
			PackageVersion:         "0.87.0",
			RuntimeVersion:         "v24.8.0",
			OS:                     "MacOS",
			Arch:                   "arm64",
			StabilizeDeviceProfile: &stabilize,
		},
	}
	auth := &cliproxyauth.Auth{
		ID: "auth-baseline-reload",
		Attributes: map[string]string{
			"api_key": "key-baseline-reload",
		},
	}

	officialReq := newClaudeHeaderTestRequest(t, http.Header{
		"User-Agent":                  []string{"claude-cli/2.1.71 (external, cli)"},
		"X-Stainless-Package-Version": []string{"0.81.0"},
		"X-Stainless-Runtime-Version": []string{"v24.6.0"},
		"X-Stainless-Os":              []string{"Linux"},
		"X-Stainless-Arch":            []string{"x64"},
	})
	applyClaudeHeaders(officialReq, "", auth, "key-baseline-reload", false, nil, oldCfg)
	assertClaudeFingerprint(t, officialReq.Header, "claude-cli/2.1.71 (external, cli)", "0.81.0", "v24.6.0", "MacOS", "arm64")

	thirdPartyReq := newClaudeHeaderTestRequest(t, http.Header{
		"User-Agent":                  []string{"curl/8.7.1"},
		"X-Stainless-Package-Version": []string{"0.10.0"},
		"X-Stainless-Runtime-Version": []string{"v18.0.0"},
		"X-Stainless-Os":              []string{"Linux"},
		"X-Stainless-Arch":            []string{"x64"},
	})
	applyClaudeHeaders(thirdPartyReq, "", auth, "key-baseline-reload", false, nil, newCfg)
	assertClaudeFingerprint(t, thirdPartyReq.Header, "claude-cli/2.1.77 (external, cli)", "0.87.0", "v24.8.0", "MacOS", "arm64")
}

func TestClaudeExecutor_Execute_RefreshesOAuthTokenAtExpiryBoundary(t *testing.T) {
	refreshCalls := 0
	stubClaudeRefreshTokens(t, func(ctx context.Context, cfg *config.Config, refreshToken string) (*claudeauth.ClaudeTokenData, error) {
		refreshCalls++
		if refreshToken != "refresh-now" {
			t.Fatalf("refreshToken = %q, want %q", refreshToken, "refresh-now")
		}
		return &claudeauth.ClaudeTokenData{
			AccessToken:  "refreshed-now-token",
			RefreshToken: "refresh-now-2",
			Email:        "user@example.com",
			Expire:       time.Now().Add(2 * time.Hour).Format(time.RFC3339),
		}, nil
	})

	var gotAuthorization string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuthorization = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","model":"claude-3-5-sonnet-20241022","role":"assistant","content":[{"type":"text","text":"hi"}],"usage":{"input_tokens":1,"output_tokens":1}}`))
	}))
	defer server.Close()

	executor := NewClaudeExecutor(&config.Config{})
	auth := newClaudeOAuthTestAuth("expired-token", "refresh-now", server.URL, time.Now())

	_, err := executor.Execute(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "claude-3-5-sonnet-20241022",
		Payload: []byte(`{"messages":[{"role":"user","content":[{"type":"text","text":"hi"}]}]}`),
	}, cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FromString("claude"),
	})
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if refreshCalls != 1 {
		t.Fatalf("refreshCalls = %d, want %d", refreshCalls, 1)
	}
	if gotAuthorization != "Bearer refreshed-now-token" {
		t.Fatalf("Authorization = %q, want %q", gotAuthorization, "Bearer refreshed-now-token")
	}
	if got := auth.Metadata["access_token"]; got != "expired-token" {
		t.Fatalf("original access_token = %v, want %q", got, "expired-token")
	}
}

func TestClaudeExecutor_PrepareRequest_RefreshesOAuthTokenWithinSafetyWindow(t *testing.T) {
	refreshCalls := 0
	stubClaudeRefreshTokens(t, func(ctx context.Context, cfg *config.Config, refreshToken string) (*claudeauth.ClaudeTokenData, error) {
		refreshCalls++
		if refreshToken != "refresh-soon" {
			t.Fatalf("refreshToken = %q, want %q", refreshToken, "refresh-soon")
		}
		return &claudeauth.ClaudeTokenData{
			AccessToken:  "refreshed-soon-token",
			RefreshToken: "refresh-soon-2",
			Email:        "user@example.com",
			Expire:       time.Now().Add(2 * time.Hour).Format(time.RFC3339),
		}, nil
	})

	executor := NewClaudeExecutor(&config.Config{})
	auth := newClaudeOAuthTestAuth("soon-expiring-token", "refresh-soon", "", time.Now().Add(45*time.Second))
	req, err := http.NewRequest(http.MethodPost, "https://api.anthropic.com/v1/messages", nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}

	if err := executor.PrepareRequest(req, auth); err != nil {
		t.Fatalf("PrepareRequest() error = %v", err)
	}
	if refreshCalls != 1 {
		t.Fatalf("refreshCalls = %d, want %d", refreshCalls, 1)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer refreshed-soon-token" {
		t.Fatalf("Authorization = %q, want %q", got, "Bearer refreshed-soon-token")
	}
	if got := req.Header.Get("x-api-key"); got != "" {
		t.Fatalf("x-api-key = %q, want empty", got)
	}
	if got := auth.Metadata["access_token"]; got != "soon-expiring-token" {
		t.Fatalf("original access_token = %v, want %q", got, "soon-expiring-token")
	}
}

func TestClaudeExecutor_HttpRequest_RefreshesOAuthTokenBeforeSending(t *testing.T) {
	refreshCalls := 0
	stubClaudeRefreshTokens(t, func(ctx context.Context, cfg *config.Config, refreshToken string) (*claudeauth.ClaudeTokenData, error) {
		refreshCalls++
		if refreshToken != "refresh-http" {
			t.Fatalf("refreshToken = %q, want %q", refreshToken, "refresh-http")
		}
		return &claudeauth.ClaudeTokenData{
			AccessToken:  "refreshed-http-token",
			RefreshToken: "refresh-http-2",
			Email:        "user@example.com",
			Expire:       time.Now().Add(2 * time.Hour).Format(time.RFC3339),
		}, nil
	})

	var gotAuthorization string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuthorization = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	executor := NewClaudeExecutor(&config.Config{})
	auth := newClaudeOAuthTestAuth("http-expiring-token", "refresh-http", "", time.Now().Add(30*time.Second))
	req, err := http.NewRequest(http.MethodGet, server.URL+"/v1/messages", nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}

	resp, err := executor.HttpRequest(context.Background(), auth, req)
	if err != nil {
		t.Fatalf("HttpRequest() error = %v", err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatalf("response close error = %v", err)
	}
	if refreshCalls != 1 {
		t.Fatalf("refreshCalls = %d, want %d", refreshCalls, 1)
	}
	if gotAuthorization != "Bearer refreshed-http-token" {
		t.Fatalf("Authorization = %q, want %q", gotAuthorization, "Bearer refreshed-http-token")
	}
}

func TestClaudeExecutor_PrepareRequest_DoesNotRefreshAPIKeyAuth(t *testing.T) {
	refreshCalls := 0
	stubClaudeRefreshTokens(t, func(ctx context.Context, cfg *config.Config, refreshToken string) (*claudeauth.ClaudeTokenData, error) {
		refreshCalls++
		return nil, nil
	})

	executor := NewClaudeExecutor(&config.Config{})
	auth := &cliproxyauth.Auth{
		Provider: "claude",
		Attributes: map[string]string{
			"api_key": "api-key-123",
		},
		Metadata: map[string]any{
			"refresh_token": "refresh-ignored",
			"expired":       time.Now().Format(time.RFC3339),
			"email":         "user@example.com",
		},
	}
	req, err := http.NewRequest(http.MethodPost, "https://api.anthropic.com/v1/messages", nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}

	if err := executor.PrepareRequest(req, auth); err != nil {
		t.Fatalf("PrepareRequest() error = %v", err)
	}
	if refreshCalls != 0 {
		t.Fatalf("refreshCalls = %d, want %d", refreshCalls, 0)
	}
	if got := req.Header.Get("x-api-key"); got != "api-key-123" {
		t.Fatalf("x-api-key = %q, want %q", got, "api-key-123")
	}
	if got := req.Header.Get("Authorization"); got != "" {
		t.Fatalf("Authorization = %q, want empty", got)
	}
}

func TestApplyClaudeHeaders_LearnsOfficialFingerprintAfterCustomBaselineFallback(t *testing.T) {
	resetClaudeDeviceProfileCache()
	stabilize := true

	cfg := &config.Config{
		ClaudeHeaderDefaults: config.ClaudeHeaderDefaults{
			UserAgent:              "my-gateway/1.0",
			PackageVersion:         "custom-pkg",
			RuntimeVersion:         "custom-runtime",
			OS:                     "MacOS",
			Arch:                   "arm64",
			StabilizeDeviceProfile: &stabilize,
		},
	}
	auth := &cliproxyauth.Auth{
		ID: "auth-custom-baseline-learning",
		Attributes: map[string]string{
			"api_key": "key-custom-baseline-learning",
		},
	}

	thirdPartyReq := newClaudeHeaderTestRequest(t, http.Header{
		"User-Agent":                  []string{"curl/8.7.1"},
		"X-Stainless-Package-Version": []string{"0.10.0"},
		"X-Stainless-Runtime-Version": []string{"v18.0.0"},
		"X-Stainless-Os":              []string{"Linux"},
		"X-Stainless-Arch":            []string{"x64"},
	})
	applyClaudeHeaders(thirdPartyReq, "", auth, "key-custom-baseline-learning", false, nil, cfg)
	assertClaudeFingerprint(t, thirdPartyReq.Header, "my-gateway/1.0", "custom-pkg", "custom-runtime", "MacOS", "arm64")

	officialReq := newClaudeHeaderTestRequest(t, http.Header{
		"User-Agent":                  []string{"claude-cli/2.1.77 (external, cli)"},
		"X-Stainless-Package-Version": []string{"0.87.0"},
		"X-Stainless-Runtime-Version": []string{"v24.8.0"},
		"X-Stainless-Os":              []string{"Linux"},
		"X-Stainless-Arch":            []string{"x64"},
	})
	applyClaudeHeaders(officialReq, "", auth, "key-custom-baseline-learning", false, nil, cfg)
	assertClaudeFingerprint(t, officialReq.Header, "claude-cli/2.1.77 (external, cli)", "0.87.0", "v24.8.0", "MacOS", "arm64")

	postLearningThirdPartyReq := newClaudeHeaderTestRequest(t, http.Header{
		"User-Agent":                  []string{"curl/8.7.1"},
		"X-Stainless-Package-Version": []string{"0.10.0"},
		"X-Stainless-Runtime-Version": []string{"v18.0.0"},
		"X-Stainless-Os":              []string{"Linux"},
		"X-Stainless-Arch":            []string{"x64"},
	})
	applyClaudeHeaders(postLearningThirdPartyReq, "", auth, "key-custom-baseline-learning", false, nil, cfg)
	assertClaudeFingerprint(t, postLearningThirdPartyReq.Header, "claude-cli/2.1.77 (external, cli)", "0.87.0", "v24.8.0", "MacOS", "arm64")
}

func TestResolveClaudeDeviceProfile_RechecksCacheBeforeStoringCandidate(t *testing.T) {
	resetClaudeDeviceProfileCache()
	stabilize := true

	cfg := &config.Config{
		ClaudeHeaderDefaults: config.ClaudeHeaderDefaults{
			UserAgent:              "claude-cli/2.1.60 (external, cli)",
			PackageVersion:         "0.70.0",
			RuntimeVersion:         "v22.0.0",
			OS:                     "MacOS",
			Arch:                   "arm64",
			StabilizeDeviceProfile: &stabilize,
		},
	}
	auth := &cliproxyauth.Auth{
		ID: "auth-racy-upgrade",
		Attributes: map[string]string{
			"api_key": "key-racy-upgrade",
		},
	}

	lowPaused := make(chan struct{})
	releaseLow := make(chan struct{})
	var pauseOnce sync.Once
	var releaseOnce sync.Once

	helps.ClaudeDeviceProfileBeforeCandidateStore = func(candidate helps.ClaudeDeviceProfile) {
		if candidate.UserAgent != "claude-cli/2.1.62 (external, cli)" {
			return
		}
		pauseOnce.Do(func() { close(lowPaused) })
		<-releaseLow
	}
	t.Cleanup(func() {
		helps.ClaudeDeviceProfileBeforeCandidateStore = nil
		releaseOnce.Do(func() { close(releaseLow) })
	})

	lowResultCh := make(chan helps.ClaudeDeviceProfile, 1)
	go func() {
		lowResultCh <- helps.ResolveClaudeDeviceProfile(auth, "key-racy-upgrade", http.Header{
			"User-Agent":                  []string{"claude-cli/2.1.62 (external, cli)"},
			"X-Stainless-Package-Version": []string{"0.74.0"},
			"X-Stainless-Runtime-Version": []string{"v24.3.0"},
			"X-Stainless-Os":              []string{"Linux"},
			"X-Stainless-Arch":            []string{"x64"},
		}, cfg)
	}()

	select {
	case <-lowPaused:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for lower candidate to pause before storing")
	}

	highResult := helps.ResolveClaudeDeviceProfile(auth, "key-racy-upgrade", http.Header{
		"User-Agent":                  []string{"claude-cli/2.1.63 (external, cli)"},
		"X-Stainless-Package-Version": []string{"0.75.0"},
		"X-Stainless-Runtime-Version": []string{"v24.4.0"},
		"X-Stainless-Os":              []string{"MacOS"},
		"X-Stainless-Arch":            []string{"arm64"},
	}, cfg)
	releaseOnce.Do(func() { close(releaseLow) })

	select {
	case lowResult := <-lowResultCh:
		if lowResult.UserAgent != "claude-cli/2.1.63 (external, cli)" {
			t.Fatalf("lowResult.UserAgent = %q, want %q", lowResult.UserAgent, "claude-cli/2.1.63 (external, cli)")
		}
		if lowResult.PackageVersion != "0.75.0" {
			t.Fatalf("lowResult.PackageVersion = %q, want %q", lowResult.PackageVersion, "0.75.0")
		}
		if lowResult.OS != "MacOS" || lowResult.Arch != "arm64" {
			t.Fatalf("lowResult platform = %s/%s, want %s/%s", lowResult.OS, lowResult.Arch, "MacOS", "arm64")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for lower candidate result")
	}

	if highResult.UserAgent != "claude-cli/2.1.63 (external, cli)" {
		t.Fatalf("highResult.UserAgent = %q, want %q", highResult.UserAgent, "claude-cli/2.1.63 (external, cli)")
	}
	if highResult.OS != "MacOS" || highResult.Arch != "arm64" {
		t.Fatalf("highResult platform = %s/%s, want %s/%s", highResult.OS, highResult.Arch, "MacOS", "arm64")
	}

	cached := helps.ResolveClaudeDeviceProfile(auth, "key-racy-upgrade", http.Header{
		"User-Agent": []string{"curl/8.7.1"},
	}, cfg)
	if cached.UserAgent != "claude-cli/2.1.63 (external, cli)" {
		t.Fatalf("cached.UserAgent = %q, want %q", cached.UserAgent, "claude-cli/2.1.63 (external, cli)")
	}
	if cached.PackageVersion != "0.75.0" {
		t.Fatalf("cached.PackageVersion = %q, want %q", cached.PackageVersion, "0.75.0")
	}
	if cached.OS != "MacOS" || cached.Arch != "arm64" {
		t.Fatalf("cached platform = %s/%s, want %s/%s", cached.OS, cached.Arch, "MacOS", "arm64")
	}
}

func TestApplyClaudeHeaders_ThirdPartyBaselineThenOfficialUpgradeKeepsPinnedPlatform(t *testing.T) {
	resetClaudeDeviceProfileCache()
	stabilize := true

	cfg := &config.Config{
		ClaudeHeaderDefaults: config.ClaudeHeaderDefaults{
			UserAgent:              "claude-cli/2.1.70 (external, cli)",
			PackageVersion:         "0.80.0",
			RuntimeVersion:         "v24.5.0",
			OS:                     "MacOS",
			Arch:                   "arm64",
			StabilizeDeviceProfile: &stabilize,
		},
	}
	auth := &cliproxyauth.Auth{
		ID: "auth-third-party-then-official",
		Attributes: map[string]string{
			"api_key": "key-third-party-then-official",
		},
	}

	thirdPartyReq := newClaudeHeaderTestRequest(t, http.Header{
		"User-Agent":                  []string{"curl/8.7.1"},
		"X-Stainless-Package-Version": []string{"0.10.0"},
		"X-Stainless-Runtime-Version": []string{"v18.0.0"},
		"X-Stainless-Os":              []string{"Linux"},
		"X-Stainless-Arch":            []string{"x64"},
	})
	applyClaudeHeaders(thirdPartyReq, "", auth, "key-third-party-then-official", false, nil, cfg)
	assertClaudeFingerprint(t, thirdPartyReq.Header, "claude-cli/2.1.70 (external, cli)", "0.80.0", "v24.5.0", "MacOS", "arm64")

	officialReq := newClaudeHeaderTestRequest(t, http.Header{
		"User-Agent":                  []string{"claude-cli/2.1.77 (external, cli)"},
		"X-Stainless-Package-Version": []string{"0.87.0"},
		"X-Stainless-Runtime-Version": []string{"v24.8.0"},
		"X-Stainless-Os":              []string{"Linux"},
		"X-Stainless-Arch":            []string{"x64"},
	})
	applyClaudeHeaders(officialReq, "", auth, "key-third-party-then-official", false, nil, cfg)
	assertClaudeFingerprint(t, officialReq.Header, "claude-cli/2.1.77 (external, cli)", "0.87.0", "v24.8.0", "MacOS", "arm64")
}

func TestApplyClaudeHeaders_DisableDeviceProfileStabilization(t *testing.T) {
	resetClaudeDeviceProfileCache()

	stabilize := false
	cfg := &config.Config{
		ClaudeHeaderDefaults: config.ClaudeHeaderDefaults{
			UserAgent:              "claude-cli/2.1.60 (external, cli)",
			PackageVersion:         "0.70.0",
			RuntimeVersion:         "v22.0.0",
			OS:                     "MacOS",
			Arch:                   "arm64",
			StabilizeDeviceProfile: &stabilize,
		},
	}
	auth := &cliproxyauth.Auth{
		ID: "auth-disable-stability",
		Attributes: map[string]string{
			"api_key": "key-disable-stability",
		},
	}

	firstReq := newClaudeHeaderTestRequest(t, http.Header{
		"User-Agent":                  []string{"claude-cli/2.1.62 (external, cli)"},
		"X-Stainless-Package-Version": []string{"0.74.0"},
		"X-Stainless-Runtime-Version": []string{"v24.3.0"},
		"X-Stainless-Os":              []string{"Linux"},
		"X-Stainless-Arch":            []string{"x64"},
	})
	applyClaudeHeaders(firstReq, "", auth, "key-disable-stability", false, nil, cfg)
	assertClaudeFingerprint(t, firstReq.Header, "claude-cli/2.1.62 (external, cli)", "0.74.0", "v24.3.0", "Linux", "x64")

	thirdPartyReq := newClaudeHeaderTestRequest(t, http.Header{
		"User-Agent":                  []string{"lobe-chat/1.0"},
		"X-Stainless-Package-Version": []string{"0.10.0"},
		"X-Stainless-Runtime-Version": []string{"v18.0.0"},
		"X-Stainless-Os":              []string{"Windows"},
		"X-Stainless-Arch":            []string{"x64"},
	})
	applyClaudeHeaders(thirdPartyReq, "", auth, "key-disable-stability", false, nil, cfg)
	assertClaudeFingerprint(t, thirdPartyReq.Header, "claude-cli/2.1.60 (external, cli)", "0.10.0", "v18.0.0", "Windows", "x64")

	lowerReq := newClaudeHeaderTestRequest(t, http.Header{
		"User-Agent":                  []string{"claude-cli/2.1.61 (external, cli)"},
		"X-Stainless-Package-Version": []string{"0.73.0"},
		"X-Stainless-Runtime-Version": []string{"v24.2.0"},
		"X-Stainless-Os":              []string{"Windows"},
		"X-Stainless-Arch":            []string{"x64"},
	})
	applyClaudeHeaders(lowerReq, "", auth, "key-disable-stability", false, nil, cfg)
	assertClaudeFingerprint(t, lowerReq.Header, "claude-cli/2.1.61 (external, cli)", "0.73.0", "v24.2.0", "Windows", "x64")
}

func TestApplyClaudeHeaders_LegacyModePreservesConfiguredUserAgentOverrideForClaudeClients(t *testing.T) {
	resetClaudeDeviceProfileCache()

	stabilize := false
	cfg := &config.Config{
		ClaudeHeaderDefaults: config.ClaudeHeaderDefaults{
			UserAgent:              "claude-cli/2.1.60 (external, cli)",
			PackageVersion:         "0.70.0",
			RuntimeVersion:         "v22.0.0",
			StabilizeDeviceProfile: &stabilize,
		},
	}
	auth := &cliproxyauth.Auth{
		ID: "auth-legacy-ua-override",
		Attributes: map[string]string{
			"api_key":           "key-legacy-ua-override",
			"header:User-Agent": "config-ua/1.0",
		},
	}

	req := newClaudeHeaderTestRequest(t, http.Header{
		"User-Agent":                  []string{"claude-cli/2.1.62 (external, cli)"},
		"X-Stainless-Package-Version": []string{"0.74.0"},
		"X-Stainless-Runtime-Version": []string{"v24.3.0"},
		"X-Stainless-Os":              []string{"Linux"},
		"X-Stainless-Arch":            []string{"x64"},
	})
	applyClaudeHeaders(req, "", auth, "key-legacy-ua-override", false, nil, cfg)

	assertClaudeFingerprint(t, req.Header, "config-ua/1.0", "0.74.0", "v24.3.0", "Linux", "x64")
}

func TestApplyClaudeHeaders_LegacyModeFallsBackToRuntimeOSArchWhenMissing(t *testing.T) {
	resetClaudeDeviceProfileCache()

	stabilize := false
	cfg := &config.Config{
		ClaudeHeaderDefaults: config.ClaudeHeaderDefaults{
			UserAgent:              "claude-cli/2.1.60 (external, cli)",
			PackageVersion:         "0.70.0",
			RuntimeVersion:         "v22.0.0",
			OS:                     "MacOS",
			Arch:                   "arm64",
			StabilizeDeviceProfile: &stabilize,
		},
	}
	auth := &cliproxyauth.Auth{
		ID: "auth-legacy-runtime-os-arch",
		Attributes: map[string]string{
			"api_key": "key-legacy-runtime-os-arch",
		},
	}

	req := newClaudeHeaderTestRequest(t, http.Header{
		"User-Agent": []string{"curl/8.7.1"},
	})
	applyClaudeHeaders(req, "", auth, "key-legacy-runtime-os-arch", false, nil, cfg)

	assertClaudeFingerprint(t, req.Header, "claude-cli/2.1.60 (external, cli)", "0.70.0", "v22.0.0", helps.MapStainlessOS(), helps.MapStainlessArch())
}

func TestApplyClaudeHeaders_UnsetStabilizationAlsoUsesLegacyRuntimeOSArchFallback(t *testing.T) {
	resetClaudeDeviceProfileCache()

	cfg := &config.Config{
		ClaudeHeaderDefaults: config.ClaudeHeaderDefaults{
			UserAgent:      "claude-cli/2.1.60 (external, cli)",
			PackageVersion: "0.70.0",
			RuntimeVersion: "v22.0.0",
			OS:             "MacOS",
			Arch:           "arm64",
		},
	}
	auth := &cliproxyauth.Auth{
		ID: "auth-unset-runtime-os-arch",
		Attributes: map[string]string{
			"api_key": "key-unset-runtime-os-arch",
		},
	}

	req := newClaudeHeaderTestRequest(t, http.Header{
		"User-Agent": []string{"curl/8.7.1"},
	})
	applyClaudeHeaders(req, "", auth, "key-unset-runtime-os-arch", false, nil, cfg)

	assertClaudeFingerprint(t, req.Header, "claude-cli/2.1.60 (external, cli)", "0.70.0", "v22.0.0", helps.MapStainlessOS(), helps.MapStainlessArch())
}

func TestClaudeDeviceProfileStabilizationEnabled_DefaultFalse(t *testing.T) {
	if helps.ClaudeDeviceProfileStabilizationEnabled(nil) {
		t.Fatal("expected nil config to default to disabled stabilization")
	}
	if helps.ClaudeDeviceProfileStabilizationEnabled(&config.Config{}) {
		t.Fatal("expected unset stabilize-device-profile to default to disabled stabilization")
	}
}

func contextWithClaudeGinHeaders(headers map[string]string) context.Context {
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	ginCtx, _ := gin.CreateTestContext(recorder)
	ginCtx.Request = httptest.NewRequest(http.MethodPost, "/", nil)
	ginCtx.Request.Header = make(http.Header, len(headers))
	for key, value := range headers {
		ginCtx.Request.Header.Set(key, value)
	}
	return context.WithValue(context.Background(), "gin", ginCtx)
}

func sanitizeClaudeToolTransformationsForTest(t *testing.T, rules []config.ClaudeToolNameTransformation) []config.ClaudeToolNameTransformation {
	t.Helper()

	cfg := &config.Config{
		Claude: config.ClaudeProviderConfig{
			ToolNameTransformations: rules,
		},
	}
	cfg.SanitizeClaudeProviderConfig()
	return cfg.Claude.ToolNameTransformations
}

func sanitizeClaudeSystemPromptTransformationsForTest(t *testing.T, rules []config.ClaudeSystemPromptTransformation) []config.ClaudeSystemPromptTransformation {
	t.Helper()

	cfg := &config.Config{
		Claude: config.ClaudeProviderConfig{
			SystemPromptTransformations: rules,
		},
	}
	cfg.SanitizeClaudeProviderConfig()
	return cfg.Claude.SystemPromptTransformations
}

func captureClaudeUpstreamBodyForMethod(t *testing.T, method string, cfg *config.Config, auth *cliproxyauth.Auth, payload []byte) []byte {
	t.Helper()

	var seenBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("failed to read request body: %v", err)
		}
		seenBody = bytes.Clone(body)

		switch method {
		case "Execute":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","model":"claude-3-5-sonnet","role":"assistant","content":[{"type":"text","text":"ok"}],"usage":{"input_tokens":1,"output_tokens":1}}`))
		case "ExecuteStream":
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = w.Write([]byte("event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"type\":\"message\",\"role\":\"assistant\",\"content\":[],\"model\":\"claude-3-5-sonnet\",\"stop_reason\":null,\"stop_sequence\":null,\"usage\":{\"input_tokens\":1,\"output_tokens\":0}}}\n\n"))
			_, _ = w.Write([]byte("event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"))
		case "CountTokens":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"input_tokens":42}`))
		default:
			t.Fatalf("unsupported capture method %q", method)
		}
	}))
	defer server.Close()

	clonedAuth := auth.Clone()
	if clonedAuth == nil {
		clonedAuth = &cliproxyauth.Auth{}
	}
	if clonedAuth.Attributes == nil {
		clonedAuth.Attributes = make(map[string]string)
	}
	clonedAuth.Attributes["base_url"] = server.URL

	executor := NewClaudeExecutor(cfg)
	ctx := contextWithClaudeGinHeaders(nil)

	switch method {
	case "Execute":
		_, err := executor.Execute(ctx, clonedAuth, cliproxyexecutor.Request{
			Model:   "claude-3-5-sonnet-20241022",
			Payload: payload,
		}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FromString("claude")})
		if err != nil {
			t.Fatalf("Execute() error = %v", err)
		}
	case "ExecuteStream":
		result, err := executor.ExecuteStream(ctx, clonedAuth, cliproxyexecutor.Request{
			Model:   "claude-3-5-sonnet-20241022",
			Payload: payload,
		}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FromString("claude")})
		if err != nil {
			t.Fatalf("ExecuteStream() error = %v", err)
		}
		for chunk := range result.Chunks {
			if chunk.Err != nil {
				t.Fatalf("ExecuteStream chunk error = %v", chunk.Err)
			}
		}
	case "CountTokens":
		_, err := executor.CountTokens(ctx, clonedAuth, cliproxyexecutor.Request{
			Model:   "claude-3-5-sonnet-20241022",
			Payload: payload,
		}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FromString("claude")})
		if err != nil {
			t.Fatalf("CountTokens() error = %v", err)
		}
	default:
		t.Fatalf("unsupported capture method %q", method)
	}

	if len(seenBody) == 0 {
		t.Fatalf("expected upstream request body to be captured for %s", method)
	}
	return seenBody
}

func TestApplyClaudeToolNameTransformations_RewritesMatchingFields(t *testing.T) {
	input := []byte(`{"tools":[{"name":"alpha"},{"name":"mcp__serena__bravo"}],"tool_choice":{"type":"tool","name":"charlie"},"messages":[{"role":"assistant","content":[{"type":"tool_use","name":"delta","id":"t1","input":{}},{"type":"tool_reference","tool_name":"echo"}]}]}`)
	rules := sanitizeClaudeToolTransformationsForTest(t, []config.ClaudeToolNameTransformation{
		{Pattern: "^.+$", Server: "serena"},
	})

	out, restoreMap := applyClaudeToolNameTransformations(input, rules)

	if got := gjson.GetBytes(out, "tools.0.name").String(); got != "mcp__serena__alpha" {
		t.Fatalf("tools.0.name = %q, want %q", got, "mcp__serena__alpha")
	}
	if got := gjson.GetBytes(out, "tools.1.name").String(); got != "mcp__serena__bravo" {
		t.Fatalf("tools.1.name = %q, want %q", got, "mcp__serena__bravo")
	}
	if got := gjson.GetBytes(out, "tool_choice.name").String(); got != "mcp__serena__charlie" {
		t.Fatalf("tool_choice.name = %q, want %q", got, "mcp__serena__charlie")
	}
	if got := gjson.GetBytes(out, "messages.0.content.0.name").String(); got != "mcp__serena__delta" {
		t.Fatalf("messages.0.content.0.name = %q, want %q", got, "mcp__serena__delta")
	}
	if got := gjson.GetBytes(out, "messages.0.content.1.tool_name").String(); got != "mcp__serena__echo" {
		t.Fatalf("messages.0.content.1.tool_name = %q, want %q", got, "mcp__serena__echo")
	}
	if got := restoreMap["mcp__serena__alpha"]; got != "alpha" {
		t.Fatalf("restoreMap[mcp__serena__alpha] = %q, want %q", got, "alpha")
	}
	if got := restoreMap["mcp__serena__bravo"]; got != "" {
		t.Fatalf("restoreMap should not include already transformed names, got %q", got)
	}
}

func TestApplyClaudeToolNameTransformations_SkipsBuiltinTools(t *testing.T) {
	body := []byte(`{
		"tools": [
			{"type": "web_search_20250305", "name": "web_search", "max_uses": 5},
			{"name": "Read"}
		],
		"messages": [
			{"role": "user", "content": [
				{"type": "tool_use", "name": "web_search", "id": "ws1", "input": {}},
				{"type": "tool_use", "name": "Read", "id": "r1", "input": {}}
			]}
		]
	}`)
	rules := sanitizeClaudeToolTransformationsForTest(t, []config.ClaudeToolNameTransformation{
		{Pattern: "^.+$", Server: "serena"},
	})

	out, restoreMap := applyClaudeToolNameTransformations(body, rules)

	if got := gjson.GetBytes(out, "tools.0.name").String(); got != "web_search" {
		t.Fatalf("tools.0.name = %q, want %q", got, "web_search")
	}
	if got := gjson.GetBytes(out, "messages.0.content.0.name").String(); got != "web_search" {
		t.Fatalf("messages.0.content.0.name = %q, want %q", got, "web_search")
	}
	if got := gjson.GetBytes(out, "tools.1.name").String(); got != "mcp__serena__Read" {
		t.Fatalf("tools.1.name = %q, want %q", got, "mcp__serena__Read")
	}
	if got := gjson.GetBytes(out, "messages.0.content.1.name").String(); got != "mcp__serena__Read" {
		t.Fatalf("messages.0.content.1.name = %q, want %q", got, "mcp__serena__Read")
	}
	if got := restoreMap["mcp__serena__Read"]; got != "Read" {
		t.Fatalf("restoreMap[mcp__serena__Read] = %q, want %q", got, "Read")
	}
}

func TestApplyClaudeSystemPromptTransformations_AppliesInOrderAndPreservesNonTextBlocks(t *testing.T) {
	rules := sanitizeClaudeSystemPromptTransformationsForTest(t, []config.ClaudeSystemPromptTransformation{
		{Pattern: "alpha", Replace: "beta"},
		{Pattern: "beta", Replace: "gamma"},
	})
	input := []byte(`{"system":[{"type":"text","text":"alpha"},{"type":"tool_result","tool_use_id":"t1","content":"keep"}],"messages":[{"role":"user","content":"hi"}]}`)

	out := applyClaudeSystemPromptTransformations(input, rules)

	if got := gjson.GetBytes(out, "system.0.text").String(); got != "gamma" {
		t.Fatalf("system.0.text = %q, want %q", got, "gamma")
	}
	if got := gjson.GetBytes(out, "system.1.type").String(); got != "tool_result" {
		t.Fatalf("system.1.type = %q, want %q", got, "tool_result")
	}
	if got := gjson.GetBytes(out, "system.1.tool_use_id").String(); got != "t1" {
		t.Fatalf("system.1.tool_use_id = %q, want %q", got, "t1")
	}
}

func TestApplyClaudeSystemPromptTransformations_RemovesEmptySystemAndSkipsInjectedBlocks(t *testing.T) {
	rules := sanitizeClaudeSystemPromptTransformationsForTest(t, []config.ClaudeSystemPromptTransformation{
		{Pattern: `<directories>\n  \n</directories>`},
	})

	plain := []byte("{\"system\":\"<directories>\\n  \\n</directories>\",\"messages\":[{\"role\":\"user\",\"content\":\"hi\"}]}")
	plainOut := applyClaudeSystemPromptTransformations(plain, rules)
	if gjson.GetBytes(plainOut, "system").Exists() {
		t.Fatalf("expected plain system to be removed, got %s", gjson.GetBytes(plainOut, "system").Raw)
	}

	cloaked := checkSystemInstructionsWithMode(plain, false, nil)
	cloakedOut := applyClaudeSystemPromptTransformations(cloaked, rules)
	blocks := gjson.GetBytes(cloakedOut, "system").Array()
	if len(blocks) != 2 {
		t.Fatalf("expected cloaked system to keep only injected blocks, got %d", len(blocks))
	}
	if !strings.HasPrefix(blocks[0].Get("text").String(), claudeBillingHeaderPrefix) {
		t.Fatalf("system.0.text = %q, want billing header", blocks[0].Get("text").String())
	}
	if blocks[1].Get("text").String() != claudeCodeAgentIdentifierText {
		t.Fatalf("system.1.text = %q, want %q", blocks[1].Get("text").String(), claudeCodeAgentIdentifierText)
	}
}

func TestClaudeExecutor_SystemPromptTransformations_ApplyAcrossRequestPaths(t *testing.T) {
	cfg := &config.Config{
		Claude: config.ClaudeProviderConfig{
			SystemPromptTransformations: []config.ClaudeSystemPromptTransformation{
				{Pattern: `<directories>\n  \n</directories>`},
			},
		},
	}
	cfg.SanitizeClaudeProviderConfig()

	auth := &cliproxyauth.Auth{
		Provider: "claude",
		Metadata: map[string]any{
			"access_token": "sk-ant-oat-system-transform",
		},
	}
	payload := []byte("{\"system\":\"Before <directories>\\n  \\n</directories> after\",\"messages\":[{\"role\":\"user\",\"content\":\"hi\"}]}")

	for _, method := range []string{"Execute", "ExecuteStream", "CountTokens"} {
		body := captureClaudeUpstreamBodyForMethod(t, method, cfg, auth, payload)
		if got := gjson.GetBytes(body, "system.2.text").String(); got != "Before  after" {
			t.Fatalf("%s system.2.text = %q, want %q", method, got, "Before  after")
		}
	}
}

func TestClaudeExecutor_SystemPromptTransformations_DoNotAffectClaudeAPIKeys(t *testing.T) {
	cfg := &config.Config{
		Claude: config.ClaudeProviderConfig{
			SystemPromptTransformations: []config.ClaudeSystemPromptTransformation{
				{Pattern: `<directories>\n  \n</directories>`},
			},
		},
	}
	cfg.SanitizeClaudeProviderConfig()

	auth := &cliproxyauth.Auth{
		Provider: "claude",
		Attributes: map[string]string{
			"api_key": "sk-ant-api-system-transform",
		},
	}
	payload := []byte("{\"system\":\"Before <directories>\\n  \\n</directories> after\",\"messages\":[{\"role\":\"user\",\"content\":\"hi\"}]}")

	body := captureClaudeUpstreamBodyForMethod(t, "Execute", cfg, auth, payload)
	if got := gjson.GetBytes(body, "system.2.text").String(); got != "Before <directories>\n  \n</directories> after" {
		t.Fatalf("system.2.text = %q, want original system prompt", got)
	}
}

func TestClaudeExecutor_SystemPromptTransformations_PreserveLiteralAngleBrackets(t *testing.T) {
	cfg := &config.Config{
		Claude: config.ClaudeProviderConfig{
			SystemPromptTransformations: []config.ClaudeSystemPromptTransformation{
				{Pattern: "alpha", Replace: "beta"},
			},
		},
	}
	cfg.SanitizeClaudeProviderConfig()

	auth := &cliproxyauth.Auth{
		Provider: "claude",
		Metadata: map[string]any{
			"access_token": "sk-ant-oat-system-transform",
		},
	}
	payload := []byte(`{"system":"<Role> alpha","messages":[{"role":"user","content":"hi"}]}`)

	body := captureClaudeUpstreamBodyForMethod(t, "Execute", cfg, auth, payload)
	if !bytes.Contains(body, []byte(`<Role> beta`)) {
		t.Fatalf("expected literal angle brackets in upstream body, got %s", string(body))
	}
	if bytes.Contains(body, []byte(`\u003cRole\u003e beta`)) {
		t.Fatalf("expected upstream body to avoid HTML escaping, got %s", string(body))
	}
}

func TestApplyClaudeToolNameTransformations_FirstMatchingRuleWins(t *testing.T) {
	input := []byte(`{"tools":[{"name":"list_dir"}]}`)
	rules := sanitizeClaudeToolTransformationsForTest(t, []config.ClaudeToolNameTransformation{
		{Pattern: "^list_.*$", Server: "serena"},
		{Pattern: "^.+$", Server: "fallback"},
	})

	out, restoreMap := applyClaudeToolNameTransformations(input, rules)

	if got := gjson.GetBytes(out, "tools.0.name").String(); got != "mcp__serena__list_dir" {
		t.Fatalf("tools.0.name = %q, want %q", got, "mcp__serena__list_dir")
	}
	if got := restoreMap["mcp__serena__list_dir"]; got != "list_dir" {
		t.Fatalf("restoreMap[mcp__serena__list_dir] = %q, want %q", got, "list_dir")
	}
	if got := restoreMap["mcp__fallback__list_dir"]; got != "" {
		t.Fatalf("unexpected fallback restore mapping = %q", got)
	}
}

func TestApplyClaudeToolNameTransformations_NestedToolReference(t *testing.T) {
	input := []byte(`{"messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_123","content":[{"type":"tool_reference","tool_name":"manage_resource"}]}]}]}`)
	rules := sanitizeClaudeToolTransformationsForTest(t, []config.ClaudeToolNameTransformation{
		{Pattern: "^manage_resource$", Server: "nia"},
	})

	out, restoreMap := applyClaudeToolNameTransformations(input, rules)
	got := gjson.GetBytes(out, "messages.0.content.0.content.0.tool_name").String()
	if got != "mcp__nia__manage_resource" {
		t.Fatalf("nested tool_reference tool_name = %q, want %q", got, "mcp__nia__manage_resource")
	}
	if got := restoreMap["mcp__nia__manage_resource"]; got != "manage_resource" {
		t.Fatalf("restoreMap[mcp__nia__manage_resource] = %q, want %q", got, "manage_resource")
	}
}

func TestRestoreClaudeToolNamesInResponse(t *testing.T) {
	input := []byte(`{"content":[{"type":"tool_use","name":"mcp__serena__alpha","id":"t1","input":{}},{"type":"tool_reference","tool_name":"mcp__serena__beta"},{"type":"tool_result","tool_use_id":"toolu_1","content":[{"type":"tool_reference","tool_name":"mcp__serena__gamma"}]},{"type":"tool_use","name":"bravo","id":"t2","input":{}}]}`)
	out := restoreClaudeToolNamesInResponse(input, map[string]string{
		"mcp__serena__alpha": "alpha",
		"mcp__serena__beta":  "beta",
		"mcp__serena__gamma": "gamma",
	})

	if got := gjson.GetBytes(out, "content.0.name").String(); got != "alpha" {
		t.Fatalf("content.0.name = %q, want %q", got, "alpha")
	}
	if got := gjson.GetBytes(out, "content.1.tool_name").String(); got != "beta" {
		t.Fatalf("content.1.tool_name = %q, want %q", got, "beta")
	}
	if got := gjson.GetBytes(out, "content.2.content.0.tool_name").String(); got != "gamma" {
		t.Fatalf("content.2.content.0.tool_name = %q, want %q", got, "gamma")
	}
	if got := gjson.GetBytes(out, "content.3.name").String(); got != "bravo" {
		t.Fatalf("content.3.name = %q, want %q", got, "bravo")
	}
}

func TestRestoreClaudeToolNamesInStreamLine(t *testing.T) {
	line := []byte(`data: {"type":"content_block_start","content_block":{"type":"tool_use","name":"mcp__serena__alpha","id":"t1"},"index":0}`)
	out := restoreClaudeToolNamesInStreamLine(line, map[string]string{
		"mcp__serena__alpha": "alpha",
	})

	payload := bytes.TrimSpace(out)
	if bytes.HasPrefix(payload, []byte("data:")) {
		payload = bytes.TrimSpace(payload[len("data:"):])
	}
	if got := gjson.GetBytes(payload, "content_block.name").String(); got != "alpha" {
		t.Fatalf("content_block.name = %q, want %q", got, "alpha")
	}
}

func TestClaudeExecutor_Execute_AppliesToolNameTransformationsForOAuthOnly(t *testing.T) {
	tests := []struct {
		name         string
		authFactory  func(string) *cliproxyauth.Auth
		wantUpstream string
		wantClient   string
	}{
		{
			name: "oauth auth transforms and restores",
			authFactory: func(baseURL string) *cliproxyauth.Auth {
				return newClaudeOAuthTestAuth("sk-ant-oat-test", "refresh-token", baseURL, time.Now().Add(2*time.Hour))
			},
			wantUpstream: "mcp__serena__Read",
			wantClient:   "Read",
		},
		{
			name: "api key auth stays unchanged",
			authFactory: func(baseURL string) *cliproxyauth.Auth {
				return &cliproxyauth.Auth{
					Provider: "claude",
					Attributes: map[string]string{
						"api_key":  "sk-atSM-api-key",
						"base_url": baseURL,
					},
				}
			},
			wantUpstream: "Read",
			wantClient:   "Read",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var upstreamBody []byte
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				defer func() {
					if err := r.Body.Close(); err != nil {
						t.Fatalf("request body close error: %v", err)
					}
				}()
				var err error
				upstreamBody, err = io.ReadAll(r.Body)
				if err != nil {
					t.Fatalf("failed to read request body: %v", err)
				}

				toolName := gjson.GetBytes(upstreamBody, "tools.0.name").String()
				resp := []byte(`{"id":"msg_test","type":"message","role":"assistant","model":"claude-3-5-sonnet-20241022","content":[{"type":"tool_use","id":"toolu_1","name":"","input":{}}],"stop_reason":"tool_use","stop_sequence":null,"usage":{"input_tokens":1,"output_tokens":1}}`)
				resp, _ = sjson.SetBytes(resp, "content.0.name", toolName)
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write(resp)
			}))
			defer server.Close()

			cfg := &config.Config{
				Claude: config.ClaudeProviderConfig{
					ToolNameTransformations: []config.ClaudeToolNameTransformation{
						{Pattern: "^Read$", Server: "serena"},
					},
				},
			}
			cfg.SanitizeClaudeProviderConfig()
			executor := NewClaudeExecutor(cfg)

			resp, err := executor.Execute(context.Background(), tt.authFactory(server.URL), cliproxyexecutor.Request{
				Model: "claude-3-5-sonnet-20241022",
				Payload: []byte(`{
					"messages":[{"role":"user","content":[{"type":"text","text":"hi"}]}],
					"tools":[{"name":"Read","input_schema":{"type":"object","properties":{}}}]
				}`),
			}, cliproxyexecutor.Options{
				SourceFormat: sdktranslator.FromString("claude"),
			})
			if err != nil {
				t.Fatalf("Execute() error = %v", err)
			}

			if got := gjson.GetBytes(upstreamBody, "tools.0.name").String(); got != tt.wantUpstream {
				t.Fatalf("upstream tools.0.name = %q, want %q", got, tt.wantUpstream)
			}
			if got := gjson.GetBytes(resp.Payload, "content.0.name").String(); got != tt.wantClient {
				t.Fatalf("client content.0.name = %q, want %q", got, tt.wantClient)
			}
		})
	}
}

func TestClaudeExecutor_CountTokens_AppliesToolNameTransformationsForOAuthOnly(t *testing.T) {
	tests := []struct {
		name         string
		authFactory  func(string) *cliproxyauth.Auth
		wantUpstream string
	}{
		{
			name: "oauth auth transforms",
			authFactory: func(baseURL string) *cliproxyauth.Auth {
				return newClaudeOAuthTestAuth("sk-ant-oat-test", "refresh-token", baseURL, time.Now().Add(2*time.Hour))
			},
			wantUpstream: "mcp__serena__Read",
		},
		{
			name: "api key auth stays unchanged",
			authFactory: func(baseURL string) *cliproxyauth.Auth {
				return &cliproxyauth.Auth{
					Provider: "claude",
					Attributes: map[string]string{
						"api_key":  "sk-atSM-api-key",
						"base_url": baseURL,
					},
				}
			},
			wantUpstream: "Read",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var upstreamBody []byte
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				defer func() {
					if err := r.Body.Close(); err != nil {
						t.Fatalf("request body close error: %v", err)
					}
				}()
				var err error
				upstreamBody, err = io.ReadAll(r.Body)
				if err != nil {
					t.Fatalf("failed to read request body: %v", err)
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"input_tokens":1}`))
			}))
			defer server.Close()

			cfg := &config.Config{
				Claude: config.ClaudeProviderConfig{
					ToolNameTransformations: []config.ClaudeToolNameTransformation{
						{Pattern: "^Read$", Server: "serena"},
					},
				},
			}
			cfg.SanitizeClaudeProviderConfig()
			executor := NewClaudeExecutor(cfg)

			_, err := executor.CountTokens(context.Background(), tt.authFactory(server.URL), cliproxyexecutor.Request{
				Model: "claude-3-5-sonnet-20241022",
				Payload: []byte(`{
					"messages":[{"role":"user","content":[{"type":"text","text":"hi"}]}],
					"tools":[{"name":"Read","input_schema":{"type":"object","properties":{}}}]
				}`),
			}, cliproxyexecutor.Options{
				SourceFormat: sdktranslator.FromString("claude"),
			})
			if err != nil {
				t.Fatalf("CountTokens() error = %v", err)
			}

			if got := gjson.GetBytes(upstreamBody, "tools.0.name").String(); got != tt.wantUpstream {
				t.Fatalf("upstream tools.0.name = %q, want %q", got, tt.wantUpstream)
			}
		})
	}
}

func TestApplyClaudeHeaders_Claude1MHeaderModelGating(t *testing.T) {
	t.Parallel()

	auth := &cliproxyauth.Auth{Attributes: map[string]string{"api_key": "key-123"}}
	testBeta := "test-beta-2026-01-01"
	tests := []struct {
		name       string
		baseModel  string
		headers    map[string]string
		extraBetas []string
		want1M     bool
		wantCount  int
		wantExtra  string
	}{
		{
			name:      "adds beta for known 1m claude model",
			baseModel: "claude-opus-4-6",
			headers:   map[string]string{"X-CPA-CLAUDE-1M": "1"},
			want1M:    true,
			wantCount: 1,
		},
		{
			name:       "skips beta for haiku but preserves extra betas",
			baseModel:  "claude-haiku-4-5-20251001",
			headers:    map[string]string{"X-CPA-CLAUDE-1M": "1"},
			extraBetas: []string{testBeta},
			want1M:     false,
			wantCount:  0,
			wantExtra:  testBeta,
		},
		{
			name:      "skips beta for unknown model",
			baseModel: "claude-does-not-exist",
			headers:   map[string]string{"X-CPA-CLAUDE-1M": "1"},
			want1M:    false,
			wantCount: 0,
		},
		{
			name:      "does not duplicate existing 1m beta",
			baseModel: "claude-opus-4-6",
			headers: map[string]string{
				"X-CPA-CLAUDE-1M": "1",
				"Anthropic-Beta":  "fine-grained-tool-streaming-2025-05-14,context-1m-2025-08-07",
			},
			want1M:    true,
			wantCount: 1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "https://api.anthropic.com/v1/messages", nil)
			req = req.WithContext(contextWithClaudeGinHeaders(tc.headers))

			applyClaudeHeaders(req, tc.baseModel, auth, "key-123", false, tc.extraBetas, nil)

			got := req.Header.Get("Anthropic-Beta")
			if has := strings.Contains(got, "context-1m-2025-08-07"); has != tc.want1M {
				t.Fatalf("Anthropic-Beta contains context-1m = %v, want %v; header=%q", has, tc.want1M, got)
			}
			if count := strings.Count(got, "context-1m-2025-08-07"); count != tc.wantCount {
				t.Fatalf("context-1m count = %d, want %d; header=%q", count, tc.wantCount, got)
			}
			if tc.wantExtra != "" && !strings.Contains(got, tc.wantExtra) {
				t.Fatalf("Anthropic-Beta = %q, want it to contain %q", got, tc.wantExtra)
			}
		})
	}
}

func TestClaudeExecutor_Claude1MHeaderUsesBaseModelAcrossPaths(t *testing.T) {
	t.Parallel()

	payload := []byte(`{"messages":[{"role":"user","content":[{"type":"text","text":"hi"}]}]}`)
	tests := []struct {
		name     string
		wantPath string
		invoke   func(context.Context, *ClaudeExecutor, *cliproxyauth.Auth, []byte) error
	}{
		{
			name:     "Execute",
			wantPath: "/v1/messages",
			invoke: func(ctx context.Context, executor *ClaudeExecutor, auth *cliproxyauth.Auth, payload []byte) error {
				_, err := executor.Execute(ctx, auth, cliproxyexecutor.Request{
					Model:   "claude-opus-4-6(high)",
					Payload: payload,
				}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FromString("claude")})
				return err
			},
		},
		{
			name:     "ExecuteStream",
			wantPath: "/v1/messages",
			invoke: func(ctx context.Context, executor *ClaudeExecutor, auth *cliproxyauth.Auth, payload []byte) error {
				result, err := executor.ExecuteStream(ctx, auth, cliproxyexecutor.Request{
					Model:   "claude-opus-4-6(high)",
					Payload: payload,
				}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FromString("claude")})
				if err != nil {
					return err
				}
				for chunk := range result.Chunks {
					if chunk.Err != nil {
						return chunk.Err
					}
				}
				return nil
			},
		},
		{
			name:     "CountTokens",
			wantPath: "/v1/messages/count_tokens",
			invoke: func(ctx context.Context, executor *ClaudeExecutor, auth *cliproxyauth.Auth, payload []byte) error {
				_, err := executor.CountTokens(ctx, auth, cliproxyexecutor.Request{
					Model:   "claude-opus-4-6(high)",
					Payload: payload,
				}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FromString("claude")})
				return err
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var gotPath string
			var gotBeta string
			var gotModel string

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotPath = r.URL.Path
				gotBeta = r.Header.Get("Anthropic-Beta")
				body, _ := io.ReadAll(r.Body)
				gotModel = gjson.GetBytes(body, "model").String()

				switch tc.name {
				case "Execute":
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","model":"claude-opus-4-6","role":"assistant","content":[{"type":"text","text":"ok"}],"usage":{"input_tokens":1,"output_tokens":1}}`))
				case "ExecuteStream":
					w.Header().Set("Content-Type", "text/event-stream")
					_, _ = w.Write([]byte("data: {\"type\":\"message_stop\"}\n\n"))
				case "CountTokens":
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write([]byte(`{"input_tokens":42}`))
				}
			}))
			defer server.Close()

			executor := NewClaudeExecutor(&config.Config{})
			auth := &cliproxyauth.Auth{Attributes: map[string]string{
				"api_key":  "key-123",
				"base_url": server.URL,
			}}

			err := tc.invoke(contextWithClaudeGinHeaders(map[string]string{"X-CPA-CLAUDE-1M": "1"}), executor, auth, payload)
			if err != nil {
				t.Fatalf("%s error: %v", tc.name, err)
			}
			if gotPath != tc.wantPath {
				t.Fatalf("path = %q, want %q", gotPath, tc.wantPath)
			}
			if gotModel != "claude-opus-4-6" {
				t.Fatalf("upstream model = %q, want %q", gotModel, "claude-opus-4-6")
			}
			if !strings.Contains(gotBeta, "context-1m-2025-08-07") {
				t.Fatalf("Anthropic-Beta = %q, want it to contain context-1m-2025-08-07", gotBeta)
			}
		})
	}
}

func TestClaudeExecutor_DryRunNonStreamSkipsUpstreamAndIncludesHint(t *testing.T) {
	var called bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	executor := NewClaudeExecutor(&config.Config{})
	auth := &cliproxyauth.Auth{
		Attributes: map[string]string{
			"api_key":  "sk-ant-oat-dry-run",
			"base_url": server.URL,
			"dry_run":  "true",
		},
	}
	ctx := logging.WithRequestID(contextWithClaudeGinHeaders(nil), "req-dryrun-nonstream")

	resp, err := executor.Execute(ctx, auth, cliproxyexecutor.Request{
		Model:   "claude-sonnet-4-5-20250929",
		Payload: []byte(`{"model":"claude-sonnet-4-5-20250929","messages":[{"role":"user","content":"hi"}]}`),
	}, cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FromString("claude"),
	})
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if called {
		t.Fatal("expected dry-run to skip upstream call")
	}
	if got := resp.Headers.Get(claudeDryRunHeader); got != "true" {
		t.Fatalf("%s = %q, want %q", claudeDryRunHeader, got, "true")
	}
	if got := gjson.GetBytes(resp.Payload, "content.0.text").String(); !strings.Contains(got, "request_id=req-dryrun-nonstream") {
		t.Fatalf("content hint = %q, want request id", got)
	}
}

func TestClaudeExecutor_DryRunStreamSkipsUpstreamAndIncludesHint(t *testing.T) {
	var called bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	executor := NewClaudeExecutor(&config.Config{})
	auth := &cliproxyauth.Auth{
		Attributes: map[string]string{
			"api_key":  "sk-ant-oat-dry-run",
			"base_url": server.URL,
			"dry_run":  "true",
		},
	}
	ctx := logging.WithRequestID(contextWithClaudeGinHeaders(nil), "req-dryrun-stream")

	result, err := executor.ExecuteStream(ctx, auth, cliproxyexecutor.Request{
		Model:   "claude-sonnet-4-5-20250929",
		Payload: []byte(`{"model":"claude-sonnet-4-5-20250929","messages":[{"role":"user","content":"hi"}],"stream":true}`),
	}, cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FromString("claude"),
	})
	if err != nil {
		t.Fatalf("ExecuteStream() error = %v", err)
	}
	if called {
		t.Fatal("expected dry-run to skip upstream call")
	}
	if got := result.Headers.Get(claudeDryRunHeader); got != "true" {
		t.Fatalf("%s = %q, want %q", claudeDryRunHeader, got, "true")
	}

	var chunks [][]byte
	for chunk := range result.Chunks {
		if chunk.Err != nil {
			t.Fatalf("stream chunk error = %v", chunk.Err)
		}
		chunks = append(chunks, chunk.Payload)
	}
	streamPayload := string(bytes.Join(chunks, nil))
	if !strings.Contains(streamPayload, "event: message_start") {
		t.Fatalf("stream payload = %q, want message_start event", streamPayload)
	}
	if !strings.Contains(streamPayload, "request_id=req-dryrun-stream") {
		t.Fatalf("stream payload = %q, want request id hint", streamPayload)
	}
}

func TestClaudeExecutor_DryRunCountTokensSkipsUpstreamAndIncludesHint(t *testing.T) {
	var called bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	executor := NewClaudeExecutor(&config.Config{})
	auth := &cliproxyauth.Auth{
		Attributes: map[string]string{
			"api_key":  "sk-ant-oat-dry-run",
			"base_url": server.URL,
			"dry_run":  "true",
		},
	}
	ctx := logging.WithRequestID(contextWithClaudeGinHeaders(nil), "req-dryrun-count")

	resp, err := executor.CountTokens(ctx, auth, cliproxyexecutor.Request{
		Model:   "claude-sonnet-4-5-20250929",
		Payload: []byte(`{"model":"claude-sonnet-4-5-20250929","messages":[{"role":"user","content":"hi"}]}`),
	}, cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FromString("claude"),
	})
	if err != nil {
		t.Fatalf("CountTokens() error = %v", err)
	}
	if called {
		t.Fatal("expected dry-run to skip upstream call")
	}
	if got := resp.Headers.Get(claudeDryRunHeader); got != "true" {
		t.Fatalf("%s = %q, want %q", claudeDryRunHeader, got, "true")
	}
	if got := gjson.GetBytes(resp.Payload, "input_tokens").Int(); got != 0 {
		t.Fatalf("input_tokens = %d, want 0", got)
	}
	if !gjson.GetBytes(resp.Payload, "dry_run").Bool() {
		t.Fatalf("dry_run = %v, want true", gjson.GetBytes(resp.Payload, "dry_run").Bool())
	}
	if got := gjson.GetBytes(resp.Payload, "dry_run_hint").String(); !strings.Contains(got, "request_id=req-dryrun-count") {
		t.Fatalf("dry_run_hint = %q, want request id", got)
	}
}

func TestClaudeExecutor_ReusesUserIDAcrossModelsWhenCacheEnabled(t *testing.T) {
	var userIDs []string
	var requestModels []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		userID := gjson.GetBytes(body, "metadata.user_id").String()
		model := gjson.GetBytes(body, "model").String()
		userIDs = append(userIDs, userID)
		requestModels = append(requestModels, model)
		t.Logf("HTTP Server received request: model=%s, user_id=%s, url=%s", model, userID, r.URL.String())
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","model":"claude-3-5-sonnet","role":"assistant","content":[{"type":"text","text":"ok"}],"usage":{"input_tokens":1,"output_tokens":1}}`))
	}))
	defer server.Close()

	t.Logf("End-to-end test: Fake HTTP server started at %s", server.URL)

	cacheEnabled := true
	executor := NewClaudeExecutor(&config.Config{
		ClaudeKey: []config.ClaudeKey{
			{
				APIKey:  "key-123",
				BaseURL: server.URL,
				Cloak: &config.CloakConfig{
					CacheUserID: &cacheEnabled,
				},
			},
		},
	})
	auth := &cliproxyauth.Auth{Attributes: map[string]string{
		"api_key":  "key-123",
		"base_url": server.URL,
	}}

	payload := []byte(`{"messages":[{"role":"user","content":[{"type":"text","text":"hi"}]}]}`)
	models := []string{"claude-3-5-sonnet", "claude-3-5-haiku"}
	for _, model := range models {
		t.Logf("Sending request for model: %s", model)
		modelPayload, _ := sjson.SetBytes(payload, "model", model)
		if _, err := executor.Execute(context.Background(), auth, cliproxyexecutor.Request{
			Model:   model,
			Payload: modelPayload,
		}, cliproxyexecutor.Options{
			SourceFormat: sdktranslator.FromString("claude"),
		}); err != nil {
			t.Fatalf("Execute(%s) error: %v", model, err)
		}
	}

	if len(userIDs) != 2 {
		t.Fatalf("expected 2 requests, got %d", len(userIDs))
	}
	if userIDs[0] == "" || userIDs[1] == "" {
		t.Fatal("expected user_id to be populated")
	}
	t.Logf("user_id[0] (model=%s): %s", requestModels[0], userIDs[0])
	t.Logf("user_id[1] (model=%s): %s", requestModels[1], userIDs[1])
	if userIDs[0] != userIDs[1] {
		t.Fatalf("expected user_id to be reused across models, got %q and %q", userIDs[0], userIDs[1])
	}
	if !helps.IsValidUserID(userIDs[0]) {
		t.Fatalf("user_id %q is not valid", userIDs[0])
	}
	t.Logf("✓ End-to-end test passed: Same user_id (%s) was used for both models", userIDs[0])
}

func TestClaudeExecutor_GeneratesNewUserIDByDefault(t *testing.T) {
	var userIDs []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		userIDs = append(userIDs, gjson.GetBytes(body, "metadata.user_id").String())
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","model":"claude-3-5-sonnet","role":"assistant","content":[{"type":"text","text":"ok"}],"usage":{"input_tokens":1,"output_tokens":1}}`))
	}))
	defer server.Close()

	executor := NewClaudeExecutor(&config.Config{})
	auth := &cliproxyauth.Auth{Attributes: map[string]string{
		"api_key":  "key-123",
		"base_url": server.URL,
	}}

	payload := []byte(`{"messages":[{"role":"user","content":[{"type":"text","text":"hi"}]}]}`)

	for i := 0; i < 2; i++ {
		if _, err := executor.Execute(context.Background(), auth, cliproxyexecutor.Request{
			Model:   "claude-3-5-sonnet",
			Payload: payload,
		}, cliproxyexecutor.Options{
			SourceFormat: sdktranslator.FromString("claude"),
		}); err != nil {
			t.Fatalf("Execute call %d error: %v", i, err)
		}
	}

	if len(userIDs) != 2 {
		t.Fatalf("expected 2 requests, got %d", len(userIDs))
	}
	if userIDs[0] == "" || userIDs[1] == "" {
		t.Fatal("expected user_id to be populated")
	}
	if userIDs[0] == userIDs[1] {
		t.Fatalf("expected user_id to change when caching is not enabled, got identical values %q", userIDs[0])
	}
	if !helps.IsValidUserID(userIDs[0]) || !helps.IsValidUserID(userIDs[1]) {
		t.Fatalf("user_ids should be valid, got %q and %q", userIDs[0], userIDs[1])
	}
}

func TestClaudeExecutor_UsesStructuredUserIDForClaude2178Plus(t *testing.T) {
	var userID string
	var sessionHeader string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		userID = gjson.GetBytes(body, "metadata.user_id").String()
		sessionHeader = r.Header.Get("X-Claude-Code-Session-Id")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","model":"claude-3-5-sonnet","role":"assistant","content":[{"type":"text","text":"ok"}],"usage":{"input_tokens":1,"output_tokens":1}}`))
	}))
	defer server.Close()

	executor := NewClaudeExecutor(&config.Config{
		ClaudeHeaderDefaults: config.ClaudeHeaderDefaults{
			UserAgent: "claude-cli/2.1.89 (external, cli)",
			DeviceID:  "configured-device-id",
		},
	})
	auth := &cliproxyauth.Auth{Attributes: map[string]string{
		"api_key":  "key-structured",
		"base_url": server.URL,
	}}

	incoming := http.Header{
		"X-Claude-Code-Session-Id": []string{"incoming-session-id"},
	}
	ctx := newClaudeHeaderTestRequest(t, incoming).Context()
	legacyUserID := helps.GenerateFakeUserID()
	payload := []byte(fmt.Sprintf(`{"messages":[{"role":"user","content":[{"type":"text","text":"hi"}]}],"metadata":{"user_id":"%s"}}`, legacyUserID))

	if _, err := executor.Execute(ctx, auth, cliproxyexecutor.Request{
		Model:   "claude-3-5-sonnet",
		Payload: payload,
	}, cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FromString("claude"),
	}); err != nil {
		t.Fatalf("Execute() error: %v", err)
	}

	if sessionHeader != "incoming-session-id" {
		t.Fatalf("X-Claude-Code-Session-Id = %q, want %q", sessionHeader, "incoming-session-id")
	}
	if userID == legacyUserID {
		t.Fatalf("expected structured metadata.user_id to replace legacy value %q", legacyUserID)
	}
	assertStructuredClaudeUserID(t, userID, "configured-device-id", sessionHeader)
}

func TestClaudeExecutor_KeepsLegacyUserIDBeforeClaude2178(t *testing.T) {
	var userID string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		userID = gjson.GetBytes(body, "metadata.user_id").String()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","model":"claude-3-5-sonnet","role":"assistant","content":[{"type":"text","text":"ok"}],"usage":{"input_tokens":1,"output_tokens":1}}`))
	}))
	defer server.Close()

	executor := NewClaudeExecutor(&config.Config{
		ClaudeHeaderDefaults: config.ClaudeHeaderDefaults{
			UserAgent: "claude-cli/2.1.77 (external, cli)",
		},
	})
	auth := &cliproxyauth.Auth{Attributes: map[string]string{
		"api_key":  "key-legacy-threshold",
		"base_url": server.URL,
	}}

	payload := []byte(`{"messages":[{"role":"user","content":[{"type":"text","text":"hi"}]}]}`)

	if _, err := executor.Execute(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "claude-3-5-sonnet",
		Payload: payload,
	}, cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FromString("claude"),
	}); err != nil {
		t.Fatalf("Execute() error: %v", err)
	}

	if userID == "" {
		t.Fatal("expected metadata.user_id to be populated")
	}
	if gjson.ValidBytes([]byte(userID)) {
		t.Fatalf("metadata.user_id = %q, want legacy non-JSON string", userID)
	}
	if !helps.IsValidUserID(userID) {
		t.Fatalf("metadata.user_id = %q, want legacy Claude user_id format", userID)
	}
}

func TestRestoreClaudeToolNamesInResponse_NestedToolReference(t *testing.T) {
	input := []byte(`{"content":[{"type":"tool_result","tool_use_id":"toolu_123","content":[{"type":"tool_reference","tool_name":"mcp__nia__manage_resource"}]}]}`)
	out := restoreClaudeToolNamesInResponse(input, map[string]string{
		"mcp__nia__manage_resource": "manage_resource",
	})
	got := gjson.GetBytes(out, "content.0.content.0.tool_name").String()
	if got != "manage_resource" {
		t.Fatalf("nested tool_reference tool_name = %q, want %q", got, "manage_resource")
	}
}

func TestApplyClaudeToolNameTransformations_NestedToolReferenceWithStringContent(t *testing.T) {
	// tool_result.content can be a string - should not be processed
	input := []byte(`{"messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_123","content":"plain string result"}]}]}`)
	rules := sanitizeClaudeToolTransformationsForTest(t, []config.ClaudeToolNameTransformation{
		{Pattern: "^.+$", Server: "serena"},
	})
	out, restoreMap := applyClaudeToolNameTransformations(input, rules)
	got := gjson.GetBytes(out, "messages.0.content.0.content").String()
	if got != "plain string result" {
		t.Fatalf("string content should remain unchanged = %q", got)
	}
	if len(restoreMap) != 0 {
		t.Fatalf("restoreMap len = %d, want 0", len(restoreMap))
	}
}

func TestApplyClaudeToolNameTransformations_SkipsBuiltinToolReference(t *testing.T) {
	input := []byte(`{"tools":[{"type":"web_search_20250305","name":"web_search"}],"messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"t1","content":[{"type":"tool_reference","tool_name":"web_search"}]}]}]}`)
	rules := sanitizeClaudeToolTransformationsForTest(t, []config.ClaudeToolNameTransformation{
		{Pattern: "^.+$", Server: "serena"},
	})
	out, restoreMap := applyClaudeToolNameTransformations(input, rules)
	got := gjson.GetBytes(out, "messages.0.content.0.content.0.tool_name").String()
	if got != "web_search" {
		t.Fatalf("built-in tool_reference should not be transformed, got %q", got)
	}
	if len(restoreMap) != 0 {
		t.Fatalf("restoreMap len = %d, want 0", len(restoreMap))
	}
}

func TestNormalizeCacheControlTTL_DowngradesLaterOneHourBlocks(t *testing.T) {
	payload := []byte(`{
		"tools": [{"name":"t1","cache_control":{"type":"ephemeral","ttl":"1h"}}],
		"system": [{"type":"text","text":"s1","cache_control":{"type":"ephemeral"}}],
		"messages": [{"role":"user","content":[{"type":"text","text":"u1","cache_control":{"type":"ephemeral","ttl":"1h"}}]}]
	}`)

	out := normalizeCacheControlTTL(payload)

	if got := gjson.GetBytes(out, "tools.0.cache_control.ttl").String(); got != "1h" {
		t.Fatalf("tools.0.cache_control.ttl = %q, want %q", got, "1h")
	}
	if gjson.GetBytes(out, "messages.0.content.0.cache_control.ttl").Exists() {
		t.Fatalf("messages.0.content.0.cache_control.ttl should be removed after a default-5m block")
	}
}

func TestNormalizeCacheControlTTL_PreservesOriginalBytesWhenNoChange(t *testing.T) {
	// Payload where no TTL normalization is needed (all blocks use 1h with no
	// preceding 5m block). The text intentionally contains HTML chars (<, >, &)
	// that json.Marshal would escape to \u003c etc., altering byte identity.
	payload := []byte(`{"tools":[{"name":"t1","cache_control":{"type":"ephemeral","ttl":"1h"}}],"system":[{"type":"text","text":"<system-reminder>foo & bar</system-reminder>","cache_control":{"type":"ephemeral","ttl":"1h"}}],"messages":[{"role":"user","content":[{"type":"text","text":"hello"}]}]}`)

	out := normalizeCacheControlTTL(payload)

	if !bytes.Equal(out, payload) {
		t.Fatalf("normalizeCacheControlTTL altered bytes when no change was needed.\noriginal: %s\ngot:      %s", payload, out)
	}
}

func TestNormalizeCacheControlTTL_PreservesKeyOrderWhenModified(t *testing.T) {
	payload := []byte(`{"model":"m","messages":[{"role":"user","content":[{"type":"text","text":"u1","cache_control":{"type":"ephemeral","ttl":"1h"}}]}],"tools":[{"name":"t1","cache_control":{"type":"ephemeral"}}],"system":[{"type":"text","text":"s1","cache_control":{"type":"ephemeral"}}]}`)

	out := normalizeCacheControlTTL(payload)

	if gjson.GetBytes(out, "messages.0.content.0.cache_control.ttl").Exists() {
		t.Fatalf("messages.0.content.0.cache_control.ttl should be removed after a default-5m block")
	}

	outStr := string(out)
	idxModel := strings.Index(outStr, `"model"`)
	idxMessages := strings.Index(outStr, `"messages"`)
	idxTools := strings.Index(outStr, `"tools"`)
	idxSystem := strings.Index(outStr, `"system"`)
	if idxModel == -1 || idxMessages == -1 || idxTools == -1 || idxSystem == -1 {
		t.Fatalf("failed to locate top-level keys in output: %s", outStr)
	}
	if !(idxModel < idxMessages && idxMessages < idxTools && idxTools < idxSystem) {
		t.Fatalf("top-level key order changed:\noriginal: %s\ngot:      %s", payload, out)
	}
}

func TestEnforceCacheControlLimit_StripsNonLastToolBeforeMessages(t *testing.T) {
	payload := []byte(`{
		"tools": [
			{"name":"t1","cache_control":{"type":"ephemeral"}},
			{"name":"t2","cache_control":{"type":"ephemeral"}}
		],
		"system": [{"type":"text","text":"s1","cache_control":{"type":"ephemeral"}}],
		"messages": [
			{"role":"user","content":[{"type":"text","text":"u1","cache_control":{"type":"ephemeral"}}]},
			{"role":"user","content":[{"type":"text","text":"u2","cache_control":{"type":"ephemeral"}}]}
		]
	}`)

	out := enforceCacheControlLimit(payload, 4)

	if got := countCacheControls(out); got != 4 {
		t.Fatalf("cache_control count = %d, want 4", got)
	}
	if gjson.GetBytes(out, "tools.0.cache_control").Exists() {
		t.Fatalf("tools.0.cache_control should be removed first (non-last tool)")
	}
	if !gjson.GetBytes(out, "tools.1.cache_control").Exists() {
		t.Fatalf("tools.1.cache_control (last tool) should be preserved")
	}
	if !gjson.GetBytes(out, "messages.0.content.0.cache_control").Exists() || !gjson.GetBytes(out, "messages.1.content.0.cache_control").Exists() {
		t.Fatalf("message cache_control blocks should be preserved when non-last tool removal is enough")
	}
}

func TestEnforceCacheControlLimit_PreservesKeyOrderWhenModified(t *testing.T) {
	payload := []byte(`{"model":"m","messages":[{"role":"user","content":[{"type":"text","text":"u1","cache_control":{"type":"ephemeral"}},{"type":"text","text":"u2","cache_control":{"type":"ephemeral"}}]}],"tools":[{"name":"t1","cache_control":{"type":"ephemeral"}},{"name":"t2","cache_control":{"type":"ephemeral"}}],"system":[{"type":"text","text":"s1","cache_control":{"type":"ephemeral"}}]}`)

	out := enforceCacheControlLimit(payload, 4)

	if got := countCacheControls(out); got != 4 {
		t.Fatalf("cache_control count = %d, want 4", got)
	}
	if gjson.GetBytes(out, "tools.0.cache_control").Exists() {
		t.Fatalf("tools.0.cache_control should be removed first (non-last tool)")
	}

	outStr := string(out)
	idxModel := strings.Index(outStr, `"model"`)
	idxMessages := strings.Index(outStr, `"messages"`)
	idxTools := strings.Index(outStr, `"tools"`)
	idxSystem := strings.Index(outStr, `"system"`)
	if idxModel == -1 || idxMessages == -1 || idxTools == -1 || idxSystem == -1 {
		t.Fatalf("failed to locate top-level keys in output: %s", outStr)
	}
	if !(idxModel < idxMessages && idxMessages < idxTools && idxTools < idxSystem) {
		t.Fatalf("top-level key order changed:\noriginal: %s\ngot:      %s", payload, out)
	}
}

func TestEnforceCacheControlLimit_ToolOnlyPayloadStillRespectsLimit(t *testing.T) {
	payload := []byte(`{
		"tools": [
			{"name":"t1","cache_control":{"type":"ephemeral"}},
			{"name":"t2","cache_control":{"type":"ephemeral"}},
			{"name":"t3","cache_control":{"type":"ephemeral"}},
			{"name":"t4","cache_control":{"type":"ephemeral"}},
			{"name":"t5","cache_control":{"type":"ephemeral"}}
		]
	}`)

	out := enforceCacheControlLimit(payload, 4)

	if got := countCacheControls(out); got != 4 {
		t.Fatalf("cache_control count = %d, want 4", got)
	}
	if gjson.GetBytes(out, "tools.0.cache_control").Exists() {
		t.Fatalf("tools.0.cache_control should be removed to satisfy max=4")
	}
	if !gjson.GetBytes(out, "tools.4.cache_control").Exists() {
		t.Fatalf("last tool cache_control should be preserved when possible")
	}
}

func TestClaudeExecutor_CountTokens_AppliesCacheControlGuards(t *testing.T) {
	var seenBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		seenBody = bytes.Clone(body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"input_tokens":42}`))
	}))
	defer server.Close()

	executor := NewClaudeExecutor(&config.Config{})
	auth := &cliproxyauth.Auth{Attributes: map[string]string{
		"api_key":  "key-123",
		"base_url": server.URL,
	}}

	payload := []byte(`{
		"tools": [
			{"name":"t1","cache_control":{"type":"ephemeral","ttl":"1h"}},
			{"name":"t2","cache_control":{"type":"ephemeral"}}
		],
		"system": [
			{"type":"text","text":"s1","cache_control":{"type":"ephemeral","ttl":"1h"}},
			{"type":"text","text":"s2","cache_control":{"type":"ephemeral","ttl":"1h"}}
		],
		"messages": [
			{"role":"user","content":[{"type":"text","text":"u1","cache_control":{"type":"ephemeral","ttl":"1h"}}]},
			{"role":"user","content":[{"type":"text","text":"u2","cache_control":{"type":"ephemeral","ttl":"1h"}}]}
		]
	}`)

	_, err := executor.CountTokens(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "claude-3-5-haiku-20241022",
		Payload: payload,
	}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FromString("claude")})
	if err != nil {
		t.Fatalf("CountTokens error: %v", err)
	}

	if len(seenBody) == 0 {
		t.Fatal("expected count_tokens request body to be captured")
	}
	if got := countCacheControls(seenBody); got > 4 {
		t.Fatalf("count_tokens body has %d cache_control blocks, want <= 4", got)
	}
	if hasTTLOrderingViolation(seenBody) {
		t.Fatalf("count_tokens body still has ttl ordering violations: %s", string(seenBody))
	}
}

func TestClaudeExecutor_CountTokens_UsesConfiguredBillingVersion(t *testing.T) {
	var seenBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		seenBody = bytes.Clone(body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"input_tokens":42}`))
	}))
	defer server.Close()

	executor := NewClaudeExecutor(&config.Config{
		ClaudeHeaderDefaults: config.ClaudeHeaderDefaults{
			UserAgent: "claude-cli/7.6.5 (external, cli)",
		},
	})
	auth := &cliproxyauth.Auth{Attributes: map[string]string{
		"api_key":  "key-123",
		"base_url": server.URL,
	}}

	_, err := executor.CountTokens(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "claude-3-5-sonnet-20241022",
		Payload: []byte(`{"messages":[{"role":"user","content":"hi"}]}`),
	}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FromString("claude")})
	if err != nil {
		t.Fatalf("CountTokens error: %v", err)
	}

	billingHeader := gjson.GetBytes(seenBody, "system.0.text").String()
	if !strings.HasPrefix(billingHeader, "x-anthropic-billing-header:") {
		t.Fatalf("system.0.text = %q, want billing header", billingHeader)
	}
	assertBillingHeaderVersion(t, billingHeader, "7.6.5")
}

func hasTTLOrderingViolation(payload []byte) bool {
	seen5m := false
	violates := false

	checkCC := func(cc gjson.Result) {
		if !cc.Exists() || violates {
			return
		}
		ttl := cc.Get("ttl").String()
		if ttl != "1h" {
			seen5m = true
			return
		}
		if seen5m {
			violates = true
		}
	}

	tools := gjson.GetBytes(payload, "tools")
	if tools.IsArray() {
		tools.ForEach(func(_, tool gjson.Result) bool {
			checkCC(tool.Get("cache_control"))
			return !violates
		})
	}

	system := gjson.GetBytes(payload, "system")
	if system.IsArray() {
		system.ForEach(func(_, item gjson.Result) bool {
			checkCC(item.Get("cache_control"))
			return !violates
		})
	}

	messages := gjson.GetBytes(payload, "messages")
	if messages.IsArray() {
		messages.ForEach(func(_, msg gjson.Result) bool {
			content := msg.Get("content")
			if content.IsArray() {
				content.ForEach(func(_, item gjson.Result) bool {
					checkCC(item.Get("cache_control"))
					return !violates
				})
			}
			return !violates
		})
	}

	return violates
}

func TestClaudeExecutor_Execute_InvalidGzipErrorBodyReturnsDecodeMessage(t *testing.T) {
	testClaudeExecutorInvalidCompressedErrorBody(t, func(executor *ClaudeExecutor, auth *cliproxyauth.Auth, payload []byte) error {
		_, err := executor.Execute(context.Background(), auth, cliproxyexecutor.Request{
			Model:   "claude-3-5-sonnet-20241022",
			Payload: payload,
		}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FromString("claude")})
		return err
	})
}

func TestClaudeExecutor_ExecuteStream_InvalidGzipErrorBodyReturnsDecodeMessage(t *testing.T) {
	testClaudeExecutorInvalidCompressedErrorBody(t, func(executor *ClaudeExecutor, auth *cliproxyauth.Auth, payload []byte) error {
		_, err := executor.ExecuteStream(context.Background(), auth, cliproxyexecutor.Request{
			Model:   "claude-3-5-sonnet-20241022",
			Payload: payload,
		}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FromString("claude")})
		return err
	})
}

func TestClaudeExecutor_CountTokens_InvalidGzipErrorBodyReturnsDecodeMessage(t *testing.T) {
	testClaudeExecutorInvalidCompressedErrorBody(t, func(executor *ClaudeExecutor, auth *cliproxyauth.Auth, payload []byte) error {
		_, err := executor.CountTokens(context.Background(), auth, cliproxyexecutor.Request{
			Model:   "claude-3-5-sonnet-20241022",
			Payload: payload,
		}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FromString("claude")})
		return err
	})
}

func testClaudeExecutorInvalidCompressedErrorBody(
	t *testing.T,
	invoke func(executor *ClaudeExecutor, auth *cliproxyauth.Auth, payload []byte) error,
) {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "gzip")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("not-a-valid-gzip-stream"))
	}))
	defer server.Close()

	executor := NewClaudeExecutor(&config.Config{})
	auth := &cliproxyauth.Auth{Attributes: map[string]string{
		"api_key":  "key-123",
		"base_url": server.URL,
	}}
	payload := []byte(`{"messages":[{"role":"user","content":[{"type":"text","text":"hi"}]}]}`)

	err := invoke(executor, auth, payload)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "failed to decode error response body") {
		t.Fatalf("expected decode failure message, got: %v", err)
	}
	if statusProvider, ok := err.(interface{ StatusCode() int }); !ok || statusProvider.StatusCode() != http.StatusBadRequest {
		t.Fatalf("expected status code 400, got: %v", err)
	}
}

func TestEnsureModelMaxTokens_UsesRegisteredMaxCompletionTokens(t *testing.T) {
	reg := registry.GetGlobalRegistry()
	clientID := "test-claude-max-completion-tokens-client"
	modelID := "test-claude-max-completion-tokens-model"
	reg.RegisterClient(clientID, "claude", []*registry.ModelInfo{{
		ID:                  modelID,
		Type:                "claude",
		OwnedBy:             "anthropic",
		Object:              "model",
		Created:             time.Now().Unix(),
		MaxCompletionTokens: 4096,
		UserDefined:         true,
	}})
	defer reg.UnregisterClient(clientID)

	input := []byte(`{"model":"test-claude-max-completion-tokens-model","messages":[{"role":"user","content":"hi"}]}`)
	out := ensureModelMaxTokens(input, modelID)

	if got := gjson.GetBytes(out, "max_tokens").Int(); got != 4096 {
		t.Fatalf("max_tokens = %d, want %d", got, 4096)
	}
}

func TestEnsureModelMaxTokens_DefaultsMissingValue(t *testing.T) {
	reg := registry.GetGlobalRegistry()
	clientID := "test-claude-default-max-tokens-client"
	modelID := "test-claude-default-max-tokens-model"
	reg.RegisterClient(clientID, "claude", []*registry.ModelInfo{{
		ID:          modelID,
		Type:        "claude",
		OwnedBy:     "anthropic",
		Object:      "model",
		Created:     time.Now().Unix(),
		UserDefined: true,
	}})
	defer reg.UnregisterClient(clientID)

	input := []byte(`{"model":"test-claude-default-max-tokens-model","messages":[{"role":"user","content":"hi"}]}`)
	out := ensureModelMaxTokens(input, modelID)

	if got := gjson.GetBytes(out, "max_tokens").Int(); got != defaultModelMaxTokens {
		t.Fatalf("max_tokens = %d, want %d", got, defaultModelMaxTokens)
	}
}

func TestEnsureModelMaxTokens_PreservesExplicitValue(t *testing.T) {
	reg := registry.GetGlobalRegistry()
	clientID := "test-claude-preserve-max-tokens-client"
	modelID := "test-claude-preserve-max-tokens-model"
	reg.RegisterClient(clientID, "claude", []*registry.ModelInfo{{
		ID:                  modelID,
		Type:                "claude",
		OwnedBy:             "anthropic",
		Object:              "model",
		Created:             time.Now().Unix(),
		MaxCompletionTokens: 4096,
		UserDefined:         true,
	}})
	defer reg.UnregisterClient(clientID)

	input := []byte(`{"model":"test-claude-preserve-max-tokens-model","max_tokens":2048,"messages":[{"role":"user","content":"hi"}]}`)
	out := ensureModelMaxTokens(input, modelID)

	if got := gjson.GetBytes(out, "max_tokens").Int(); got != 2048 {
		t.Fatalf("max_tokens = %d, want %d", got, 2048)
	}
}

func TestEnsureModelMaxTokens_SkipsUnregisteredModel(t *testing.T) {
	input := []byte(`{"model":"test-claude-unregistered-model","messages":[{"role":"user","content":"hi"}]}`)
	out := ensureModelMaxTokens(input, "test-claude-unregistered-model")

	if gjson.GetBytes(out, "max_tokens").Exists() {
		t.Fatalf("max_tokens should remain unset, got %s", gjson.GetBytes(out, "max_tokens").Raw)
	}
}

// TestClaudeExecutor_ExecuteStream_SetsIdentityAcceptEncoding verifies that streaming
// requests use Accept-Encoding: identity so the upstream cannot respond with a
// compressed SSE body that would silently break the line scanner.
func TestClaudeExecutor_ExecuteStream_SetsIdentityAcceptEncoding(t *testing.T) {
	var gotEncoding, gotAccept string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotEncoding = r.Header.Get("Accept-Encoding")
		gotAccept = r.Header.Get("Accept")
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: {\"type\":\"message_stop\"}\n\n"))
	}))
	defer server.Close()

	executor := NewClaudeExecutor(&config.Config{})
	auth := &cliproxyauth.Auth{Attributes: map[string]string{
		"api_key":  "key-123",
		"base_url": server.URL,
	}}
	payload := []byte(`{"messages":[{"role":"user","content":[{"type":"text","text":"hi"}]}]}`)

	result, err := executor.ExecuteStream(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "claude-3-5-sonnet-20241022",
		Payload: payload,
	}, cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FromString("claude"),
	})
	if err != nil {
		t.Fatalf("ExecuteStream error: %v", err)
	}
	for chunk := range result.Chunks {
		if chunk.Err != nil {
			t.Fatalf("unexpected chunk error: %v", chunk.Err)
		}
	}

	if gotEncoding != "identity" {
		t.Errorf("Accept-Encoding = %q, want %q", gotEncoding, "identity")
	}
	if gotAccept != "text/event-stream" {
		t.Errorf("Accept = %q, want %q", gotAccept, "text/event-stream")
	}
}

// TestClaudeExecutor_Execute_SetsCompressedAcceptEncoding verifies that non-streaming
// requests keep the full accept-encoding to allow response compression (which
// decodeResponseBody handles correctly).
func TestClaudeExecutor_Execute_SetsCompressedAcceptEncoding(t *testing.T) {
	var gotEncoding, gotAccept string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotEncoding = r.Header.Get("Accept-Encoding")
		gotAccept = r.Header.Get("Accept")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","model":"claude-3-5-sonnet-20241022","role":"assistant","content":[{"type":"text","text":"hi"}],"usage":{"input_tokens":1,"output_tokens":1}}`))
	}))
	defer server.Close()

	executor := NewClaudeExecutor(&config.Config{})
	auth := &cliproxyauth.Auth{Attributes: map[string]string{
		"api_key":  "key-123",
		"base_url": server.URL,
	}}
	payload := []byte(`{"messages":[{"role":"user","content":[{"type":"text","text":"hi"}]}]}`)

	_, err := executor.Execute(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "claude-3-5-sonnet-20241022",
		Payload: payload,
	}, cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FromString("claude"),
	})
	if err != nil {
		t.Fatalf("Execute error: %v", err)
	}

	if gotEncoding != "gzip, deflate, br, zstd" {
		t.Errorf("Accept-Encoding = %q, want %q", gotEncoding, "gzip, deflate, br, zstd")
	}
	if gotAccept != "application/json" {
		t.Errorf("Accept = %q, want %q", gotAccept, "application/json")
	}
}

// TestClaudeExecutor_ExecuteStream_GzipSuccessBodyDecoded verifies that a streaming
// HTTP 200 response with Content-Encoding: gzip is correctly decompressed before
// the line scanner runs, so SSE chunks are not silently dropped.
func TestClaudeExecutor_ExecuteStream_GzipSuccessBodyDecoded(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	_, _ = gz.Write([]byte("data: {\"type\":\"message_stop\"}\n"))
	_ = gz.Close()
	compressedBody := buf.Bytes()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = w.Write(compressedBody)
	}))
	defer server.Close()

	executor := NewClaudeExecutor(&config.Config{})
	auth := &cliproxyauth.Auth{Attributes: map[string]string{
		"api_key":  "key-123",
		"base_url": server.URL,
	}}
	payload := []byte(`{"messages":[{"role":"user","content":[{"type":"text","text":"hi"}]}]}`)

	result, err := executor.ExecuteStream(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "claude-3-5-sonnet-20241022",
		Payload: payload,
	}, cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FromString("claude"),
	})
	if err != nil {
		t.Fatalf("ExecuteStream error: %v", err)
	}

	var combined strings.Builder
	for chunk := range result.Chunks {
		if chunk.Err != nil {
			t.Fatalf("chunk error: %v", chunk.Err)
		}
		combined.Write(chunk.Payload)
	}

	if combined.Len() == 0 {
		t.Fatal("expected at least one chunk from gzip-encoded SSE body, got none (body was not decompressed)")
	}
	if !strings.Contains(combined.String(), "message_stop") {
		t.Errorf("expected SSE content in chunks, got: %q", combined.String())
	}
}

// TestDecodeResponseBody_MagicByteGzipNoHeader verifies that decodeResponseBody
// detects gzip-compressed content via magic bytes even when Content-Encoding is absent.
func TestDecodeResponseBody_MagicByteGzipNoHeader(t *testing.T) {
	const plaintext = "data: {\"type\":\"message_stop\"}\n"

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	_, _ = gz.Write([]byte(plaintext))
	_ = gz.Close()

	rc := io.NopCloser(&buf)
	decoded, err := decodeResponseBody(rc, "")
	if err != nil {
		t.Fatalf("decodeResponseBody error: %v", err)
	}
	defer decoded.Close()

	got, err := io.ReadAll(decoded)
	if err != nil {
		t.Fatalf("ReadAll error: %v", err)
	}
	if string(got) != plaintext {
		t.Errorf("decoded = %q, want %q", got, plaintext)
	}
}

// TestDecodeResponseBody_MagicByteZstdNoHeader verifies that decodeResponseBody
// detects zstd-compressed content via magic bytes even when Content-Encoding is absent.
func TestDecodeResponseBody_MagicByteZstdNoHeader(t *testing.T) {
	const plaintext = "data: {\"type\":\"message_stop\"}\n"

	var buf bytes.Buffer
	enc, err := zstd.NewWriter(&buf)
	if err != nil {
		t.Fatalf("zstd.NewWriter: %v", err)
	}
	_, _ = enc.Write([]byte(plaintext))
	_ = enc.Close()

	rc := io.NopCloser(&buf)
	decoded, err := decodeResponseBody(rc, "")
	if err != nil {
		t.Fatalf("decodeResponseBody error: %v", err)
	}
	defer decoded.Close()

	got, err := io.ReadAll(decoded)
	if err != nil {
		t.Fatalf("ReadAll error: %v", err)
	}
	if string(got) != plaintext {
		t.Errorf("decoded = %q, want %q", got, plaintext)
	}
}

// TestDecodeResponseBody_PlainTextNoHeader verifies that decodeResponseBody returns
// plain text untouched when Content-Encoding is absent and no magic bytes match.
func TestDecodeResponseBody_PlainTextNoHeader(t *testing.T) {
	const plaintext = "data: {\"type\":\"message_stop\"}\n"
	rc := io.NopCloser(strings.NewReader(plaintext))
	decoded, err := decodeResponseBody(rc, "")
	if err != nil {
		t.Fatalf("decodeResponseBody error: %v", err)
	}
	defer decoded.Close()

	got, err := io.ReadAll(decoded)
	if err != nil {
		t.Fatalf("ReadAll error: %v", err)
	}
	if string(got) != plaintext {
		t.Errorf("decoded = %q, want %q", got, plaintext)
	}
}

// TestClaudeExecutor_ExecuteStream_GzipNoContentEncodingHeader verifies the full
// pipeline: when the upstream returns a gzip-compressed SSE body WITHOUT setting
// Content-Encoding (a misbehaving upstream), the magic-byte sniff in
// decodeResponseBody still decompresses it, so chunks reach the caller.
func TestClaudeExecutor_ExecuteStream_GzipNoContentEncodingHeader(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	_, _ = gz.Write([]byte("data: {\"type\":\"message_stop\"}\n"))
	_ = gz.Close()
	compressedBody := buf.Bytes()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		// Intentionally omit Content-Encoding to simulate misbehaving upstream.
		_, _ = w.Write(compressedBody)
	}))
	defer server.Close()

	executor := NewClaudeExecutor(&config.Config{})
	auth := &cliproxyauth.Auth{Attributes: map[string]string{
		"api_key":  "key-123",
		"base_url": server.URL,
	}}
	payload := []byte(`{"messages":[{"role":"user","content":[{"type":"text","text":"hi"}]}]}`)

	result, err := executor.ExecuteStream(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "claude-3-5-sonnet-20241022",
		Payload: payload,
	}, cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FromString("claude"),
	})
	if err != nil {
		t.Fatalf("ExecuteStream error: %v", err)
	}

	var combined strings.Builder
	for chunk := range result.Chunks {
		if chunk.Err != nil {
			t.Fatalf("chunk error: %v", chunk.Err)
		}
		combined.Write(chunk.Payload)
	}

	if combined.Len() == 0 {
		t.Fatal("expected chunks from gzip body without Content-Encoding header, got none (magic-byte sniff failed)")
	}
	if !strings.Contains(combined.String(), "message_stop") {
		t.Errorf("unexpected chunk content: %q", combined.String())
	}
}

// TestClaudeExecutor_Execute_GzipErrorBodyNoContentEncodingHeader verifies that the
// error path (4xx) correctly decompresses a gzip body even when the upstream omits
// the Content-Encoding header.  This closes the gap left by PR #1771, which only
// fixed header-declared compression on the error path.
func TestClaudeExecutor_Execute_GzipErrorBodyNoContentEncodingHeader(t *testing.T) {
	const errJSON = `{"type":"error","error":{"type":"invalid_request_error","message":"test error"}}`

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	_, _ = gz.Write([]byte(errJSON))
	_ = gz.Close()
	compressedBody := buf.Bytes()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Intentionally omit Content-Encoding to simulate misbehaving upstream.
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write(compressedBody)
	}))
	defer server.Close()

	executor := NewClaudeExecutor(&config.Config{})
	auth := &cliproxyauth.Auth{Attributes: map[string]string{
		"api_key":  "key-123",
		"base_url": server.URL,
	}}
	payload := []byte(`{"messages":[{"role":"user","content":[{"type":"text","text":"hi"}]}]}`)

	_, err := executor.Execute(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "claude-3-5-sonnet-20241022",
		Payload: payload,
	}, cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FromString("claude"),
	})
	if err == nil {
		t.Fatal("expected an error for 400 response, got nil")
	}
	if !strings.Contains(err.Error(), "test error") {
		t.Errorf("error message should contain decompressed JSON, got: %q", err.Error())
	}
}

// TestClaudeExecutor_ExecuteStream_GzipErrorBodyNoContentEncodingHeader verifies
// the same for the streaming executor: 4xx gzip body without Content-Encoding is
// decoded and the error message is readable.
func TestClaudeExecutor_ExecuteStream_GzipErrorBodyNoContentEncodingHeader(t *testing.T) {
	const errJSON = `{"type":"error","error":{"type":"invalid_request_error","message":"stream test error"}}`

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	_, _ = gz.Write([]byte(errJSON))
	_ = gz.Close()
	compressedBody := buf.Bytes()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Intentionally omit Content-Encoding to simulate misbehaving upstream.
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write(compressedBody)
	}))
	defer server.Close()

	executor := NewClaudeExecutor(&config.Config{})
	auth := &cliproxyauth.Auth{Attributes: map[string]string{
		"api_key":  "key-123",
		"base_url": server.URL,
	}}
	payload := []byte(`{"messages":[{"role":"user","content":[{"type":"text","text":"hi"}]}]}`)

	_, err := executor.ExecuteStream(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "claude-3-5-sonnet-20241022",
		Payload: payload,
	}, cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FromString("claude"),
	})
	if err == nil {
		t.Fatal("expected an error for 400 response, got nil")
	}
	if !strings.Contains(err.Error(), "stream test error") {
		t.Errorf("error message should contain decompressed JSON, got: %q", err.Error())
	}
}

// TestClaudeExecutor_ExecuteStream_AcceptEncodingOverrideCannotBypassIdentity verifies that the
// streaming executor enforces Accept-Encoding: identity regardless of auth.Attributes override.
func TestClaudeExecutor_ExecuteStream_AcceptEncodingOverrideCannotBypassIdentity(t *testing.T) {
	var gotEncoding string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotEncoding = r.Header.Get("Accept-Encoding")
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: {\"type\":\"message_stop\"}\n\n"))
	}))
	defer server.Close()

	executor := NewClaudeExecutor(&config.Config{})
	auth := &cliproxyauth.Auth{Attributes: map[string]string{
		"api_key":                "key-123",
		"base_url":               server.URL,
		"header:Accept-Encoding": "gzip, deflate, br, zstd",
	}}
	payload := []byte(`{"messages":[{"role":"user","content":[{"type":"text","text":"hi"}]}]}`)

	result, err := executor.ExecuteStream(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "claude-3-5-sonnet-20241022",
		Payload: payload,
	}, cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FromString("claude"),
	})
	if err != nil {
		t.Fatalf("ExecuteStream error: %v", err)
	}
	for chunk := range result.Chunks {
		if chunk.Err != nil {
			t.Fatalf("unexpected chunk error: %v", chunk.Err)
		}
	}

	if gotEncoding != "identity" {
		t.Errorf("Accept-Encoding = %q; stream path must enforce identity regardless of auth.Attributes override", gotEncoding)
	}
}

func expectedClaudeCodeStaticPrompt() string {
	return strings.Join([]string{
		helps.ClaudeCodeIntro,
		helps.ClaudeCodeSystem,
		helps.ClaudeCodeDoingTasks,
		helps.ClaudeCodeToneAndStyle,
		helps.ClaudeCodeOutputEfficiency,
	}, "\n\n")
}

func expectedForwardedSystemReminder(text string) string {
	return fmt.Sprintf(`<system-reminder>
As you answer the user's questions, you can use the following context from the system:
%s

IMPORTANT: this context may or may not be relevant to your tasks. You should not respond to this context unless it is highly relevant to your task.
</system-reminder>
`, text)
}

// Test case 1: String system prompt is preserved by forwarding it to the first user message
func TestCheckSystemInstructionsWithMode_StringSystemPreserved(t *testing.T) {
	payload := []byte(`{"system":"You are a helpful assistant.","messages":[{"role":"user","content":"hi"}]}`)

	out := checkSystemInstructionsWithMode(payload, false, nil)

	system := gjson.GetBytes(out, "system")
	if !system.IsArray() {
		t.Fatalf("system should be an array, got %s", system.Type)
	}

	blocks := system.Array()
	if len(blocks) != 3 {
		t.Fatalf("expected 3 system blocks, got %d", len(blocks))
	}

	if !strings.HasPrefix(blocks[0].Get("text").String(), "x-anthropic-billing-header:") {
		t.Fatalf("blocks[0] should be billing header, got %q", blocks[0].Get("text").String())
	}
	assertBillingHeaderVersion(t, blocks[0].Get("text").String(), helps.DefaultClaudeVersion(nil))
	if strings.Contains(blocks[0].Get("text").String(), "cc_version=2.1.63.") {
		t.Fatalf("billing header should not use legacy version literal: %q", blocks[0].Get("text").String())
	}
	if blocks[1].Get("text").String() != "You are Claude Code, Anthropic's official CLI for Claude." {
		t.Fatalf("blocks[1] should be agent block, got %q", blocks[1].Get("text").String())
	}
	if blocks[2].Get("text").String() != expectedClaudeCodeStaticPrompt() {
		t.Fatalf("blocks[2] should be static Claude Code prompt, got %q", blocks[2].Get("text").String())
	}
	if blocks[2].Get("cache_control").Exists() {
		t.Fatalf("blocks[2] should not have cache_control, got %s", blocks[2].Get("cache_control").Raw)
	}

	if got := gjson.GetBytes(out, "messages.0.content").String(); got != expectedForwardedSystemReminder("You are a helpful assistant.")+"hi" {
		t.Fatalf("messages[0].content should include forwarded system prompt, got %q", got)
	}
}

// Test case 2: Strict mode keeps only the injected Claude Code system blocks
func TestCheckSystemInstructionsWithMode_StringSystemStrict(t *testing.T) {
	payload := []byte(`{"system":"You are a helpful assistant.","messages":[{"role":"user","content":"hi"}]}`)

	out := checkSystemInstructionsWithMode(payload, true, nil)

	blocks := gjson.GetBytes(out, "system").Array()
	if len(blocks) != 3 {
		t.Fatalf("strict mode should produce 3 injected blocks, got %d", len(blocks))
	}
	if got := gjson.GetBytes(out, "messages.0.content").String(); got != "hi" {
		t.Fatalf("strict mode should not forward system prompt into messages, got %q", got)
	}
}

// Test case 3: Empty string system prompt does not alter the first user message
func TestCheckSystemInstructionsWithMode_EmptyStringSystemIgnored(t *testing.T) {
	payload := []byte(`{"system":"","messages":[{"role":"user","content":"hi"}]}`)

	out := checkSystemInstructionsWithMode(payload, false, nil)

	blocks := gjson.GetBytes(out, "system").Array()
	if len(blocks) != 3 {
		t.Fatalf("empty string system should still produce 3 injected blocks, got %d", len(blocks))
	}
	if got := gjson.GetBytes(out, "messages.0.content").String(); got != "hi" {
		t.Fatalf("empty string system should not alter messages, got %q", got)
	}
}

// Test case 4: Array system prompt is forwarded to the first user message
func TestCheckSystemInstructionsWithMode_ArraySystemStillWorks(t *testing.T) {
	payload := []byte(`{"system":[{"type":"text","text":"Be concise."}],"messages":[{"role":"user","content":"hi"}]}`)

	out := checkSystemInstructionsWithMode(payload, false, nil)

	blocks := gjson.GetBytes(out, "system").Array()
	if len(blocks) != 3 {
		t.Fatalf("expected 3 system blocks, got %d", len(blocks))
	}
	if blocks[2].Get("text").String() != expectedClaudeCodeStaticPrompt() {
		t.Fatalf("blocks[2] should be static Claude Code prompt, got %q", blocks[2].Get("text").String())
	}
	if got := gjson.GetBytes(out, "messages.0.content").String(); got != expectedForwardedSystemReminder("Be concise.")+"hi" {
		t.Fatalf("messages[0].content should include forwarded array system prompt, got %q", got)
	}
}

// Test case 5: Special characters in string system prompt survive forwarding
func TestCheckSystemInstructionsWithMode_StringWithSpecialChars(t *testing.T) {
	payload := []byte(`{"system":"Use <xml> tags & \"quotes\" in output.","messages":[{"role":"user","content":"hi"}]}`)

	out := checkSystemInstructionsWithMode(payload, false, nil)

	blocks := gjson.GetBytes(out, "system").Array()
	if len(blocks) != 3 {
		t.Fatalf("expected 3 system blocks, got %d", len(blocks))
	}
	if got := gjson.GetBytes(out, "messages.0.content").String(); got != expectedForwardedSystemReminder(`Use <xml> tags & "quotes" in output.`)+"hi" {
		t.Fatalf("forwarded system prompt text mangled, got %q", got)
	}
}

func TestCheckSystemInstructionsWithMode_UsesConfiguredBillingVersion(t *testing.T) {
	cfg := &config.Config{
		ClaudeHeaderDefaults: config.ClaudeHeaderDefaults{
			UserAgent: "claude-cli/9.8.7 (external, cli)",
		},
	}
	payload := []byte(`{"system":"You are a helpful assistant.","messages":[{"role":"user","content":"hi"}]}`)

	out := checkSystemInstructionsWithMode(payload, false, cfg)

	billingHeader := gjson.GetBytes(out, "system.0.text").String()
	assertBillingHeaderVersion(t, billingHeader, "9.8.7")
}

func TestClaudeExecutor_ExperimentalCCHSigningDisabledByDefaultKeepsLegacyHeader(t *testing.T) {
	var seenBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		seenBody = bytes.Clone(body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","model":"claude-3-5-sonnet","role":"assistant","content":[{"type":"text","text":"ok"}],"usage":{"input_tokens":1,"output_tokens":1}}`))
	}))
	defer server.Close()

	executor := NewClaudeExecutor(&config.Config{})
	auth := &cliproxyauth.Auth{Attributes: map[string]string{
		"api_key":  "key-123",
		"base_url": server.URL,
	}}
	payload := []byte(`{"messages":[{"role":"user","content":[{"type":"text","text":"hi"}]}]}`)

	_, err := executor.Execute(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "claude-3-5-sonnet-20241022",
		Payload: payload,
	}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FromString("claude")})
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if len(seenBody) == 0 {
		t.Fatal("expected request body to be captured")
	}

	billingHeader := gjson.GetBytes(seenBody, "system.0.text").String()
	if !strings.HasPrefix(billingHeader, "x-anthropic-billing-header:") {
		t.Fatalf("system.0.text = %q, want billing header", billingHeader)
	}
	if strings.Contains(billingHeader, "cch=00000;") {
		t.Fatalf("legacy mode should not forward cch placeholder, got %q", billingHeader)
	}
}

func TestClaudeExecutor_ExperimentalCCHSigningOptInSignsFinalBody(t *testing.T) {
	var seenBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		seenBody = bytes.Clone(body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","model":"claude-3-5-sonnet","role":"assistant","content":[{"type":"text","text":"ok"}],"usage":{"input_tokens":1,"output_tokens":1}}`))
	}))
	defer server.Close()

	executor := NewClaudeExecutor(&config.Config{
		ClaudeKey: []config.ClaudeKey{{
			APIKey:                 "key-123",
			BaseURL:                server.URL,
			ExperimentalCCHSigning: true,
		}},
	})
	auth := &cliproxyauth.Auth{Attributes: map[string]string{
		"api_key":  "key-123",
		"base_url": server.URL,
	}}
	const messageText = "please keep literal cch=00000 in this message"
	payload := []byte(`{"messages":[{"role":"user","content":[{"type":"text","text":"please keep literal cch=00000 in this message"}]}]}`)

	_, err := executor.Execute(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "claude-3-5-sonnet-20241022",
		Payload: payload,
	}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FromString("claude")})
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if len(seenBody) == 0 {
		t.Fatal("expected request body to be captured")
	}
	if got := gjson.GetBytes(seenBody, "messages.0.content.0.text").String(); got != messageText {
		t.Fatalf("message text = %q, want %q", got, messageText)
	}

	billingPattern := regexp.MustCompile(`(x-anthropic-billing-header:[^"]*?\bcch=)([0-9a-f]{5})(;)`)
	match := billingPattern.FindSubmatch(seenBody)
	if match == nil {
		t.Fatalf("expected signed billing header in body: %s", string(seenBody))
	}
	actualCCH := string(match[2])
	unsignedBody := billingPattern.ReplaceAll(seenBody, []byte(`${1}00000${3}`))
	wantCCH := fmt.Sprintf("%05x", xxHash64.Checksum(unsignedBody, 0x6E52736AC806831E)&0xFFFFF)
	if actualCCH != wantCCH {
		t.Fatalf("cch = %q, want %q\nbody: %s", actualCCH, wantCCH, string(seenBody))
	}
}

func TestApplyCloaking_PreservesConfiguredStrictModeAndSensitiveWordsWhenModeOmitted(t *testing.T) {
	cfg := &config.Config{
		ClaudeKey: []config.ClaudeKey{{
			APIKey: "key-123",
			Cloak: &config.CloakConfig{
				StrictMode:     true,
				SensitiveWords: []string{"proxy"},
			},
		}},
	}
	auth := &cliproxyauth.Auth{Attributes: map[string]string{"api_key": "key-123"}}
	payload := []byte(`{"system":"proxy rules","messages":[{"role":"user","content":[{"type":"text","text":"proxy access"}]}]}`)

	out := applyCloaking(context.Background(), cfg, auth, payload, "claude-3-5-sonnet-20241022", "key-123")

	blocks := gjson.GetBytes(out, "system").Array()
	if len(blocks) != 3 {
		t.Fatalf("expected strict mode to keep the 3 injected Claude Code system blocks, got %d", len(blocks))
	}
	if got := gjson.GetBytes(out, "messages.0.content.#").Int(); got != 1 {
		t.Fatalf("strict mode should not prepend a forwarded system reminder block, got %d content blocks", got)
	}
	if got := gjson.GetBytes(out, "messages.0.content.0.text").String(); !strings.Contains(got, "\u200B") {
		t.Fatalf("expected configured sensitive word obfuscation to apply, got %q", got)
	}
}

func TestNormalizeClaudeTemperatureForThinking_AdaptiveCoercesToOne(t *testing.T) {
	payload := []byte(`{"temperature":0,"thinking":{"type":"adaptive"},"output_config":{"effort":"max"}}`)
	out := normalizeClaudeTemperatureForThinking(payload)

	if got := gjson.GetBytes(out, "temperature").Float(); got != 1 {
		t.Fatalf("temperature = %v, want 1", got)
	}
}

func TestNormalizeClaudeTemperatureForThinking_EnabledCoercesToOne(t *testing.T) {
	payload := []byte(`{"temperature":0.2,"thinking":{"type":"enabled","budget_tokens":2048}}`)
	out := normalizeClaudeTemperatureForThinking(payload)

	if got := gjson.GetBytes(out, "temperature").Float(); got != 1 {
		t.Fatalf("temperature = %v, want 1", got)
	}
}

func TestNormalizeClaudeTemperatureForThinking_NoThinkingLeavesTemperatureAlone(t *testing.T) {
	payload := []byte(`{"temperature":0,"messages":[{"role":"user","content":"hi"}]}`)
	out := normalizeClaudeTemperatureForThinking(payload)

	if got := gjson.GetBytes(out, "temperature").Float(); got != 0 {
		t.Fatalf("temperature = %v, want 0", got)
	}
}

func TestNormalizeClaudeTemperatureForThinking_AfterForcedToolChoiceKeepsOriginalTemperature(t *testing.T) {
	payload := []byte(`{"temperature":0,"thinking":{"type":"adaptive"},"output_config":{"effort":"max"},"tool_choice":{"type":"any"}}`)
	out := disableThinkingIfToolChoiceForced(payload)
	out = normalizeClaudeTemperatureForThinking(out)

	if gjson.GetBytes(out, "thinking").Exists() {
		t.Fatalf("thinking should be removed when tool_choice forces tool use")
	}
	if got := gjson.GetBytes(out, "temperature").Float(); got != 0 {
		t.Fatalf("temperature = %v, want 0", got)
	}
}

func TestRemapOAuthToolNames_TitleCase_NoReverseNeeded(t *testing.T) {
	body := []byte(`{"tools":[{"name":"Bash","description":"Run shell commands","input_schema":{"type":"object","properties":{"cmd":{"type":"string"}}}}],"messages":[{"role":"user","content":[{"type":"text","text":"hi"}]}]}`)

	out, renamed := remapOAuthToolNames(body)
	if renamed {
		t.Fatalf("renamed = true, want false")
	}
	if got := gjson.GetBytes(out, "tools.0.name").String(); got != "Bash" {
		t.Fatalf("tools.0.name = %q, want %q", got, "Bash")
	}

	resp := []byte(`{"content":[{"type":"tool_use","id":"toolu_01","name":"Bash","input":{"cmd":"ls"}}]}`)
	reversed := resp
	if renamed {
		reversed = reverseRemapOAuthToolNames(resp)
	}
	if got := gjson.GetBytes(reversed, "content.0.name").String(); got != "Bash" {
		t.Fatalf("content.0.name = %q, want %q", got, "Bash")
	}
}

func TestRemapOAuthToolNames_Lowercase_ReverseApplied(t *testing.T) {
	body := []byte(`{"tools":[{"name":"bash","description":"Run shell commands","input_schema":{"type":"object","properties":{"cmd":{"type":"string"}}}}],"messages":[{"role":"user","content":[{"type":"text","text":"hi"}]}]}`)

	out, renamed := remapOAuthToolNames(body)
	if !renamed {
		t.Fatalf("renamed = false, want true")
	}
	if got := gjson.GetBytes(out, "tools.0.name").String(); got != "Bash" {
		t.Fatalf("tools.0.name = %q, want %q", got, "Bash")
	}

	resp := []byte(`{"content":[{"type":"tool_use","id":"toolu_01","name":"Bash","input":{"cmd":"ls"}}]}`)
	reversed := resp
	if renamed {
		reversed = reverseRemapOAuthToolNames(resp)
	}
	if got := gjson.GetBytes(reversed, "content.0.name").String(); got != "bash" {
		t.Fatalf("content.0.name = %q, want %q", got, "bash")
	}
}
