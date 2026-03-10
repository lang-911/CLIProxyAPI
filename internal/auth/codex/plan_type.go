package codex

import "strings"

var supportedPlanTypes = map[string]struct{}{
	"free": {},
	"plus": {},
	"pro":  {},
	"team": {},
}

// NormalizePlanType returns the supported normalized plan type or empty string.
func NormalizePlanType(planType string) string {
	normalized := strings.ToLower(strings.TrimSpace(planType))
	if _, ok := supportedPlanTypes[normalized]; !ok {
		return ""
	}
	return normalized
}

// ResolvePlanTypeFromMetadata returns the effective Codex plan type for auth-file metadata.
// It prefers an explicit file override and falls back to the JWT id_token claim.
func ResolvePlanTypeFromMetadata(metadata map[string]any) string {
	if metadata == nil {
		return ""
	}
	if rawPlanType, ok := metadata["plan_type"].(string); ok {
		if normalized := NormalizePlanType(rawPlanType); normalized != "" {
			return normalized
		}
	}
	idTokenRaw, ok := metadata["id_token"].(string)
	if !ok || strings.TrimSpace(idTokenRaw) == "" {
		return ""
	}
	claims, err := ParseJWTToken(idTokenRaw)
	if err != nil || claims == nil {
		return ""
	}
	return NormalizePlanType(claims.CodexAuthInfo.ChatgptPlanType)
}
