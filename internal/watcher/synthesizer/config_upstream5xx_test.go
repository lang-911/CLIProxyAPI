package synthesizer

import (
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
)

func intPtr(i int) *int { return &i }

func synthesizeUpstream5xxTestAuths(t *testing.T, cfg *config.Config) []map[string]any {
	t.Helper()
	ctx := &SynthesisContext{
		Config:      cfg,
		Now:         time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		IDGenerator: NewStableIDGenerator(),
	}
	auths, err := (&ConfigSynthesizer{}).Synthesize(ctx)
	if err != nil {
		t.Fatalf("synthesize config: %v", err)
	}
	if len(auths) != 1 {
		t.Fatalf("expected 1 auth, got %d", len(auths))
	}
	return []map[string]any{auths[0].Metadata}
}

func assertUpstream5xxMetadata(t *testing.T, metadata map[string]any, want int) {
	t.Helper()
	got, ok := metadata["upstream_5xx_suspend_threshold"]
	if !ok {
		t.Fatalf("expected upstream_5xx_suspend_threshold metadata, got %v", metadata)
	}
	if got != want {
		t.Fatalf("upstream_5xx_suspend_threshold = %v, want %d", got, want)
	}
}

func assertNoUpstream5xxMetadata(t *testing.T, metadata map[string]any) {
	t.Helper()
	if metadata == nil {
		return
	}
	if _, ok := metadata["upstream_5xx_suspend_threshold"]; ok {
		t.Fatalf("expected no upstream_5xx_suspend_threshold metadata, got %v", metadata)
	}
}

func TestSynthesizeGeminiKeys_Upstream5xxOverride(t *testing.T) {
	metadata := synthesizeUpstream5xxTestAuths(t, &config.Config{
		GeminiKey: []config.GeminiKey{{APIKey: "k", Upstream5xxSuspendThreshold: intPtr(7)}},
	})[0]
	assertUpstream5xxMetadata(t, metadata, 7)
}

func TestSynthesizeGeminiKeys_NoOverride_NoMetadataKey(t *testing.T) {
	metadata := synthesizeUpstream5xxTestAuths(t, &config.Config{
		GeminiKey: []config.GeminiKey{{APIKey: "k"}},
	})[0]
	assertNoUpstream5xxMetadata(t, metadata)
}

func TestSynthesizeClaudeKeys_Upstream5xxOverride(t *testing.T) {
	metadata := synthesizeUpstream5xxTestAuths(t, &config.Config{
		ClaudeKey: []config.ClaudeKey{{APIKey: "k", Upstream5xxSuspendThreshold: intPtr(7)}},
	})[0]
	assertUpstream5xxMetadata(t, metadata, 7)
}

func TestSynthesizeCodexKeys_Upstream5xxOverride(t *testing.T) {
	metadata := synthesizeUpstream5xxTestAuths(t, &config.Config{
		CodexKey: []config.CodexKey{{APIKey: "k", Upstream5xxSuspendThreshold: intPtr(7)}},
	})[0]
	assertUpstream5xxMetadata(t, metadata, 7)
}

func TestSynthesizeOpenAICompat_Upstream5xxOverride_APIKeyEntries(t *testing.T) {
	metadata := synthesizeUpstream5xxTestAuths(t, &config.Config{
		OpenAICompatibility: []config.OpenAICompatibility{{
			Name:                        "compat",
			BaseURL:                     "https://compat.example",
			APIKeyEntries:               []config.OpenAICompatibilityAPIKey{{APIKey: "k"}},
			Upstream5xxSuspendThreshold: intPtr(5),
		}},
	})[0]
	assertUpstream5xxMetadata(t, metadata, 5)
}

func TestSynthesizeOpenAICompat_Upstream5xxOverride_Fallback(t *testing.T) {
	metadata := synthesizeUpstream5xxTestAuths(t, &config.Config{
		OpenAICompatibility: []config.OpenAICompatibility{{
			Name:                        "compat",
			BaseURL:                     "https://compat.example",
			Upstream5xxSuspendThreshold: intPtr(3),
		}},
	})[0]
	assertUpstream5xxMetadata(t, metadata, 3)
}

func TestSynthesizeVertex_NoUpstream5xxField(t *testing.T) {
	metadata := synthesizeUpstream5xxTestAuths(t, &config.Config{
		VertexCompatAPIKey: []config.VertexCompatKey{{APIKey: "k", BaseURL: "https://vertex.example"}},
	})[0]
	assertNoUpstream5xxMetadata(t, metadata)
}
