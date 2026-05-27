package config

import (
	"os"
	"path/filepath"
	"testing"
)

func loadUpstream5xxConfig(t *testing.T, yaml string) *Config {
	t.Helper()
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(configPath, []byte(yaml), 0o600); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}
	cfg, err := LoadConfigOptional(configPath, false)
	if err != nil {
		t.Fatalf("LoadConfigOptional() error = %v", err)
	}
	return cfg
}

func TestLoadConfigOptional_Upstream5xxDefault(t *testing.T) {
	cfg := loadUpstream5xxConfig(t, "debug: false\n")
	if got := cfg.Upstream5xxSuspendThreshold; got != 5 {
		t.Fatalf("Upstream5xxSuspendThreshold = %d, want 5", got)
	}
}

func TestLoadConfigOptional_Upstream5xxExplicitZero(t *testing.T) {
	cfg := loadUpstream5xxConfig(t, "upstream-5xx-suspend-threshold: 0\n")
	if got := cfg.Upstream5xxSuspendThreshold; got != 0 {
		t.Fatalf("Upstream5xxSuspendThreshold = %d, want 0", got)
	}
}

func TestLoadConfigOptional_Upstream5xxExplicitValue(t *testing.T) {
	cfg := loadUpstream5xxConfig(t, "upstream-5xx-suspend-threshold: 12\n")
	if got := cfg.Upstream5xxSuspendThreshold; got != 12 {
		t.Fatalf("Upstream5xxSuspendThreshold = %d, want 12", got)
	}
}

func TestLoadConfigOptional_Upstream5xxNegativeClamps(t *testing.T) {
	cfg := loadUpstream5xxConfig(t, "upstream-5xx-suspend-threshold: -3\n")
	if got := cfg.Upstream5xxSuspendThreshold; got != 0 {
		t.Fatalf("Upstream5xxSuspendThreshold = %d, want 0", got)
	}
}

func TestParseConfigBytes_Upstream5xxParity(t *testing.T) {
	cfg, err := ParseConfigBytes([]byte("upstream-5xx-suspend-threshold: 8\n"))
	if err != nil {
		t.Fatalf("ParseConfigBytes() error = %v", err)
	}
	if got := cfg.Upstream5xxSuspendThreshold; got != 8 {
		t.Fatalf("Upstream5xxSuspendThreshold = %d, want 8", got)
	}
}

func TestParseConfigBytes_Upstream5xxDefault(t *testing.T) {
	cfg, err := ParseConfigBytes([]byte("debug: false\n"))
	if err != nil {
		t.Fatalf("ParseConfigBytes() error = %v", err)
	}
	if got := cfg.Upstream5xxSuspendThreshold; got != 5 {
		t.Fatalf("Upstream5xxSuspendThreshold = %d, want 5", got)
	}
}

func TestLoadConfigOptional_Upstream5xx_PerCredentialOverride_Gemini(t *testing.T) {
	cfg := loadUpstream5xxConfig(t, `gemini-api-key:
  - api-key: "k"
    upstream-5xx-suspend-threshold: 10
`)
	if len(cfg.GeminiKey) != 1 {
		t.Fatalf("GeminiKey len = %d, want 1", len(cfg.GeminiKey))
	}
	if cfg.GeminiKey[0].Upstream5xxSuspendThreshold == nil {
		t.Fatal("GeminiKey[0].Upstream5xxSuspendThreshold = nil, want 10")
	}
	if got := *cfg.GeminiKey[0].Upstream5xxSuspendThreshold; got != 10 {
		t.Fatalf("GeminiKey[0].Upstream5xxSuspendThreshold = %d, want 10", got)
	}
}
