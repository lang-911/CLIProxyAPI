// auth_diff.go computes human-readable diffs for auth file field changes.
package diff

import (
	"fmt"
	"strings"

	coreauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
)

// BuildAuthChangeDetails computes a redacted, human-readable list of auth field changes.
// Only safe operator-visible fields are tracked; sensitive data is never printed.
func BuildAuthChangeDetails(oldAuth, newAuth *coreauth.Auth) []string {
	changes := make([]string, 0, 4)

	// Handle nil cases by using empty Auth as default
	if oldAuth == nil {
		oldAuth = &coreauth.Auth{}
	}
	if newAuth == nil {
		return changes
	}

	// Compare prefix
	oldPrefix := strings.TrimSpace(oldAuth.Prefix)
	newPrefix := strings.TrimSpace(newAuth.Prefix)
	if oldPrefix != newPrefix {
		changes = append(changes, fmt.Sprintf("prefix: %s -> %s", oldPrefix, newPrefix))
	}

	// Compare proxy_url (redacted)
	oldProxy := strings.TrimSpace(oldAuth.ProxyURL)
	newProxy := strings.TrimSpace(newAuth.ProxyURL)
	if oldProxy != newProxy {
		changes = append(changes, fmt.Sprintf("proxy_url: %s -> %s", formatProxyURL(oldProxy), formatProxyURL(newProxy)))
	}

	oldPlanType := authAttributeValue(oldAuth, "plan_type")
	newPlanType := authAttributeValue(newAuth, "plan_type")
	if oldPlanType != newPlanType {
		changes = append(changes, fmt.Sprintf("plan_type: %s -> %s", oldPlanType, newPlanType))
	}

	// Compare disabled
	if oldAuth.Disabled != newAuth.Disabled {
		changes = append(changes, fmt.Sprintf("disabled: %t -> %t", oldAuth.Disabled, newAuth.Disabled))
	}

	return changes
}

func authAttributeValue(auth *coreauth.Auth, key string) string {
	if auth == nil || auth.Attributes == nil {
		return ""
	}
	return strings.TrimSpace(auth.Attributes[key])
}
