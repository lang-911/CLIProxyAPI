package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfigOptional_ClaudeHeaderDefaults(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	configYAML := []byte(`
claude-header-defaults:
  user-agent: "  claude-cli/2.1.70 (external, cli)  "
  package-version: "  0.80.0  "
  runtime-version: "  v24.5.0  "
  os: "  MacOS  "
  arch: "  arm64  "
  timeout: "  900  "
  device-id: "  device-123  "
  stabilize-device-profile: false
`)
	if err := os.WriteFile(configPath, configYAML, 0o600); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	cfg, err := LoadConfigOptional(configPath, false)
	if err != nil {
		t.Fatalf("LoadConfigOptional() error = %v", err)
	}

	if got := cfg.ClaudeHeaderDefaults.UserAgent; got != "claude-cli/2.1.70 (external, cli)" {
		t.Fatalf("UserAgent = %q, want %q", got, "claude-cli/2.1.70 (external, cli)")
	}
	if got := cfg.ClaudeHeaderDefaults.PackageVersion; got != "0.80.0" {
		t.Fatalf("PackageVersion = %q, want %q", got, "0.80.0")
	}
	if got := cfg.ClaudeHeaderDefaults.RuntimeVersion; got != "v24.5.0" {
		t.Fatalf("RuntimeVersion = %q, want %q", got, "v24.5.0")
	}
	if got := cfg.ClaudeHeaderDefaults.OS; got != "MacOS" {
		t.Fatalf("OS = %q, want %q", got, "MacOS")
	}
	if got := cfg.ClaudeHeaderDefaults.Arch; got != "arm64" {
		t.Fatalf("Arch = %q, want %q", got, "arm64")
	}
	if got := cfg.ClaudeHeaderDefaults.Timeout; got != "900" {
		t.Fatalf("Timeout = %q, want %q", got, "900")
	}
	if got := cfg.ClaudeHeaderDefaults.DeviceID; got != "device-123" {
		t.Fatalf("DeviceID = %q, want %q", got, "device-123")
	}
	if cfg.ClaudeHeaderDefaults.StabilizeDeviceProfile == nil {
		t.Fatal("StabilizeDeviceProfile = nil, want non-nil")
	}
	if got := *cfg.ClaudeHeaderDefaults.StabilizeDeviceProfile; got {
		t.Fatalf("StabilizeDeviceProfile = %v, want false", got)
	}
}

func TestLoadConfigOptional_ClaudeProviderConfig(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	configYAML := []byte(`
claude:
  base-url: "  https://claude.example.com/base  "
  dry-run: true
  tool-name-transformations:
    - pattern: "  ^list_.*$  "
      server: "  serena  "
    - pattern: "  [  "
      server: "ignored"
    - pattern: "   "
      server: "ignored"
    - pattern: "^read$"
      server: "   "
`)
	if err := os.WriteFile(configPath, configYAML, 0o600); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	cfg, err := LoadConfigOptional(configPath, false)
	if err != nil {
		t.Fatalf("LoadConfigOptional() error = %v", err)
	}

	if got := cfg.Claude.BaseURL; got != "https://claude.example.com/base" {
		t.Fatalf("Claude.BaseURL = %q, want %q", got, "https://claude.example.com/base")
	}
	if !cfg.Claude.DryRun {
		t.Fatal("Claude.DryRun = false, want true")
	}
	if len(cfg.Claude.ToolNameTransformations) != 1 {
		t.Fatalf("Claude.ToolNameTransformations len = %d, want 1", len(cfg.Claude.ToolNameTransformations))
	}
	rule := cfg.Claude.ToolNameTransformations[0]
	if got := rule.Pattern; got != "^list_.*$" {
		t.Fatalf("rule.Pattern = %q, want %q", got, "^list_.*$")
	}
	if got := rule.Server; got != "serena" {
		t.Fatalf("rule.Server = %q, want %q", got, "serena")
	}
	if !rule.Match("list_dir") {
		t.Fatal("expected compiled regex to match list_dir")
	}
	if rule.Match("read_file") {
		t.Fatal("expected compiled regex not to match read_file")
	}
}
