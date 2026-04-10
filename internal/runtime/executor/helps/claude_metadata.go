package helps

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"

	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
)

const structuredClaudeUserIDVersion = "2.1.78"

type claudeStructuredUserID struct {
	DeviceID    string `json:"device_id"`
	AccountUUID string `json:"account_uuid"`
	SessionID   string `json:"session_id"`
}

func claudeScopeKey(auth *cliproxyauth.Auth, apiKey string) string {
	switch {
	case auth != nil && strings.TrimSpace(auth.ID) != "":
		return "auth:" + strings.TrimSpace(auth.ID)
	case strings.TrimSpace(apiKey) != "":
		return "api_key:" + strings.TrimSpace(apiKey)
	default:
		return "global"
	}
}

func parseClaudeVersionString(version string) (claudeCLIVersion, bool) {
	parts := strings.Split(strings.TrimSpace(version), ".")
	if len(parts) != 3 {
		return claudeCLIVersion{}, false
	}
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return claudeCLIVersion{}, false
	}
	minor, err := strconv.Atoi(parts[1])
	if err != nil {
		return claudeCLIVersion{}, false
	}
	patch, err := strconv.Atoi(parts[2])
	if err != nil {
		return claudeCLIVersion{}, false
	}
	return claudeCLIVersion{major: major, minor: minor, patch: patch}, true
}

func ClaudeVersionFromUserAgent(userAgent string) (string, bool) {
	version, ok := parseClaudeCLIVersion(userAgent)
	if !ok {
		return "", false
	}
	return version.String(), true
}

func ClaudeVersionAtLeast(version, minimum string) bool {
	currentVersion, ok := parseClaudeVersionString(version)
	if !ok {
		return false
	}
	minimumVersion, ok := parseClaudeVersionString(minimum)
	if !ok {
		return false
	}
	return currentVersion.Compare(minimumVersion) >= 0
}

func UsesStructuredClaudeUserID(version string) bool {
	return ClaudeVersionAtLeast(version, structuredClaudeUserIDVersion)
}

func ResolveClaudeDeviceID(auth *cliproxyauth.Auth, apiKey string, configuredDeviceID string) string {
	if deviceID := strings.TrimSpace(configuredDeviceID); deviceID != "" {
		return deviceID
	}
	sum := sha256.Sum256([]byte(claudeScopeKey(auth, apiKey)))
	return hex.EncodeToString(sum[:])
}

func BuildStructuredClaudeUserID(deviceID, sessionID string) string {
	payload, err := json.Marshal(claudeStructuredUserID{
		DeviceID:    strings.TrimSpace(deviceID),
		AccountUUID: "",
		SessionID:   strings.TrimSpace(sessionID),
	})
	if err != nil {
		return `{"device_id":"","account_uuid":"","session_id":""}`
	}
	return string(payload)
}
