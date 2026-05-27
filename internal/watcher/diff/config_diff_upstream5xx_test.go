package diff

import (
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
)

func TestBuildConfigChangeDetails_Upstream5xxThreshold_Changed(t *testing.T) {
	oldCfg := &config.Config{Upstream5xxSuspendThreshold: 3}
	newCfg := &config.Config{Upstream5xxSuspendThreshold: 10}

	details := strings.Join(BuildConfigChangeDetails(oldCfg, newCfg), "\n")
	if !strings.Contains(details, "upstream-5xx-suspend-threshold: 3 -> 10") {
		t.Fatalf("expected upstream threshold change in details, got %q", details)
	}
}

func TestBuildConfigChangeDetails_Upstream5xxThreshold_Unchanged(t *testing.T) {
	oldCfg := &config.Config{Upstream5xxSuspendThreshold: 5}
	newCfg := &config.Config{Upstream5xxSuspendThreshold: 5}

	details := strings.Join(BuildConfigChangeDetails(oldCfg, newCfg), "\n")
	if strings.Contains(details, "upstream-5xx-suspend-threshold:") {
		t.Fatalf("did not expect upstream threshold change in details, got %q", details)
	}
}
