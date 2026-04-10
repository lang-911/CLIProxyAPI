package helps

import (
	"testing"

	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
)

func TestResolveClaudeDeviceID_UsesConfiguredValue(t *testing.T) {
	got := ResolveClaudeDeviceID(nil, "api-key-1", " configured-device ")
	if got != "configured-device" {
		t.Fatalf("ResolveClaudeDeviceID() = %q, want %q", got, "configured-device")
	}
}

func TestResolveClaudeDeviceID_IsDeterministicByScope(t *testing.T) {
	auth := &cliproxyauth.Auth{ID: "auth-1"}
	first := ResolveClaudeDeviceID(auth, "api-key-1", "")
	second := ResolveClaudeDeviceID(auth, "api-key-2", "")
	other := ResolveClaudeDeviceID(&cliproxyauth.Auth{ID: "auth-2"}, "api-key-1", "")

	if len(first) != 64 {
		t.Fatalf("ResolveClaudeDeviceID() length = %d, want 64", len(first))
	}
	if first != second {
		t.Fatalf("ResolveClaudeDeviceID() should prefer auth scope, got %q and %q", first, second)
	}
	if first == other {
		t.Fatalf("ResolveClaudeDeviceID() should differ for different scopes, got %q", first)
	}
}

func TestUsesStructuredClaudeUserID(t *testing.T) {
	if UsesStructuredClaudeUserID("2.1.77") {
		t.Fatal("UsesStructuredClaudeUserID(2.1.77) = true, want false")
	}
	if !UsesStructuredClaudeUserID("2.1.78") {
		t.Fatal("UsesStructuredClaudeUserID(2.1.78) = false, want true")
	}
	if !UsesStructuredClaudeUserID("2.1.89") {
		t.Fatal("UsesStructuredClaudeUserID(2.1.89) = false, want true")
	}
}
