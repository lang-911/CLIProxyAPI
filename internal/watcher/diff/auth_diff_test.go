package diff

import (
	"testing"

	coreauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
)

func TestBuildAuthChangeDetails_PlanType(t *testing.T) {
	oldAuth := &coreauth.Auth{
		Attributes: map[string]string{
			"plan_type": "team",
		},
	}
	newAuth := &coreauth.Auth{
		Attributes: map[string]string{
			"plan_type": "plus",
		},
	}

	changes := BuildAuthChangeDetails(oldAuth, newAuth)
	expectContains(t, changes, "plan_type: team -> plus")
}
