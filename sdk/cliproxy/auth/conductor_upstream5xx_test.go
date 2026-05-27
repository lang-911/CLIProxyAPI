package auth

import (
	"context"
	"testing"
	"time"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

func saveUpstream5xxThreshold(t *testing.T) {
	t.Helper()
	prev := upstream5xxSuspendThreshold.Load()
	t.Cleanup(func() { upstream5xxSuspendThreshold.Store(prev) })
}

func saveQuotaCooldownDisabled(t *testing.T) {
	t.Helper()
	prev := quotaCooldownDisabled.Load()
	t.Cleanup(func() { quotaCooldownDisabled.Store(prev) })
}

func markResult500(m *Manager, authID, model string) {
	m.MarkResult(context.Background(), Result{
		AuthID:   authID,
		Provider: "claude",
		Model:    model,
		Success:  false,
		Error:    &Error{HTTPStatus: 500, Message: "boom"},
	})
}

func markResultSuccess(m *Manager, authID, model string) {
	m.MarkResult(context.Background(), Result{
		AuthID:   authID,
		Provider: "claude",
		Model:    model,
		Success:  true,
	})
}

func registerUpstream5xxTestAuth(t *testing.T, m *Manager, auth *Auth) {
	t.Helper()
	if _, errRegister := m.Register(context.Background(), auth); errRegister != nil {
		t.Fatalf("register auth: %v", errRegister)
	}
}

func getUpstream5xxTestAuth(t *testing.T, m *Manager, authID string) *Auth {
	t.Helper()
	updated, ok := m.GetByID(authID)
	if !ok || updated == nil {
		t.Fatalf("expected auth %q to be present", authID)
	}
	return updated
}

func TestEffectiveUpstream5xxSuspendThreshold_GlobalAndOverride(t *testing.T) {
	saveUpstream5xxThreshold(t)
	upstream5xxSuspendThreshold.Store(10)

	if got := effectiveUpstream5xxSuspendThreshold(nil); got != 10 {
		t.Fatalf("nil auth threshold = %d, want 10", got)
	}
	if got := effectiveUpstream5xxSuspendThreshold(&Auth{}); got != 10 {
		t.Fatalf("nil metadata threshold = %d, want 10", got)
	}
	if got := effectiveUpstream5xxSuspendThreshold(&Auth{Metadata: map[string]any{"upstream_5xx_suspend_threshold": 2}}); got != 2 {
		t.Fatalf("override threshold = %d, want 2", got)
	}
	if got := effectiveUpstream5xxSuspendThreshold(&Auth{Metadata: map[string]any{"upstream_5xx_suspend_threshold": 0}}); got != 0 {
		t.Fatalf("zero override threshold = %d, want 0", got)
	}
	if got := effectiveUpstream5xxSuspendThreshold(&Auth{Metadata: map[string]any{"upstream_5xx_suspend_threshold": -3}}); got != 0 {
		t.Fatalf("negative override threshold = %d, want 0", got)
	}
	if got := effectiveUpstream5xxSuspendThreshold(&Auth{Metadata: map[string]any{"upstream-5xx-suspend-threshold": 7}}); got != 7 {
		t.Fatalf("legacy override threshold = %d, want 7", got)
	}
}

func TestSetUpstream5xxSuspendThreshold_ClampsNegative(t *testing.T) {
	saveUpstream5xxThreshold(t)

	SetUpstream5xxSuspendThreshold(-5)
	if got := effectiveUpstream5xxSuspendThreshold(nil); got != 0 {
		t.Fatalf("negative global threshold = %d, want 0", got)
	}
	SetUpstream5xxSuspendThreshold(3)
	if got := effectiveUpstream5xxSuspendThreshold(nil); got != 3 {
		t.Fatalf("global threshold = %d, want 3", got)
	}
}

func TestMarkResult_Upstream5xxThreshold_DisablesAtThreshold_PerModel(t *testing.T) {
	saveQuotaCooldownDisabled(t)
	saveUpstream5xxThreshold(t)
	SetUpstream5xxSuspendThreshold(3)

	m := NewManager(nil, nil, nil)
	registerUpstream5xxTestAuth(t, m, &Auth{ID: "a1", Provider: "claude"})
	for range 3 {
		markResult500(m, "a1", "x")
	}

	updated := getUpstream5xxTestAuth(t, m, "a1")
	if !updated.Disabled || updated.Status != StatusDisabled || updated.ConsecutiveUpstream5xxCount() != 3 {
		t.Fatalf("auth state = disabled %v status %q count %d, want disabled true status %q count 3", updated.Disabled, updated.Status, updated.ConsecutiveUpstream5xxCount(), StatusDisabled)
	}
}

func TestMarkResult_Upstream5xxThreshold_DisablesAtThreshold_WholeAuth(t *testing.T) {
	saveQuotaCooldownDisabled(t)
	saveUpstream5xxThreshold(t)
	SetUpstream5xxSuspendThreshold(3)

	m := NewManager(nil, nil, nil)
	registerUpstream5xxTestAuth(t, m, &Auth{ID: "a1", Provider: "claude"})
	for range 3 {
		markResult500(m, "a1", "")
	}

	updated := getUpstream5xxTestAuth(t, m, "a1")
	if !updated.Disabled || updated.Status != StatusDisabled || updated.ConsecutiveUpstream5xxCount() != 3 {
		t.Fatalf("auth state = disabled %v status %q count %d, want disabled true status %q count 3", updated.Disabled, updated.Status, updated.ConsecutiveUpstream5xxCount(), StatusDisabled)
	}
}

func TestMarkResult_Upstream5xxThreshold_408DoesNotCount(t *testing.T) {
	saveUpstream5xxThreshold(t)
	SetUpstream5xxSuspendThreshold(1)

	m := NewManager(nil, nil, nil)
	registerUpstream5xxTestAuth(t, m, &Auth{ID: "a1", Provider: "claude"})
	m.MarkResult(context.Background(), Result{AuthID: "a1", Provider: "claude", Model: "x", Error: &Error{HTTPStatus: 408, Message: "timeout"}})

	updated := getUpstream5xxTestAuth(t, m, "a1")
	if updated.Disabled || updated.ConsecutiveUpstream5xxCount() != 0 {
		t.Fatalf("auth disabled=%v count=%d, want false 0", updated.Disabled, updated.ConsecutiveUpstream5xxCount())
	}
}

func TestMarkResult_Upstream5xxThreshold_ResetsOnSuccess_PerModel(t *testing.T) {
	saveUpstream5xxThreshold(t)
	SetUpstream5xxSuspendThreshold(5)

	m := NewManager(nil, nil, nil)
	registerUpstream5xxTestAuth(t, m, &Auth{ID: "a1", Provider: "claude"})
	markResult500(m, "a1", "x")
	markResult500(m, "a1", "x")
	if got := getUpstream5xxTestAuth(t, m, "a1").ConsecutiveUpstream5xxCount(); got != 2 {
		t.Fatalf("count before success = %d, want 2", got)
	}
	markResultSuccess(m, "a1", "x")

	updated := getUpstream5xxTestAuth(t, m, "a1")
	if updated.Disabled || updated.ConsecutiveUpstream5xxCount() != 0 {
		t.Fatalf("auth disabled=%v count=%d, want false 0", updated.Disabled, updated.ConsecutiveUpstream5xxCount())
	}
}

func TestMarkResult_Upstream5xxThreshold_ResetsOnSuccess_WholeAuth(t *testing.T) {
	saveUpstream5xxThreshold(t)
	SetUpstream5xxSuspendThreshold(5)

	m := NewManager(nil, nil, nil)
	registerUpstream5xxTestAuth(t, m, &Auth{ID: "a1", Provider: "claude"})
	markResult500(m, "a1", "")
	markResult500(m, "a1", "")
	if got := getUpstream5xxTestAuth(t, m, "a1").ConsecutiveUpstream5xxCount(); got != 2 {
		t.Fatalf("count before success = %d, want 2", got)
	}
	markResultSuccess(m, "a1", "")

	if got := getUpstream5xxTestAuth(t, m, "a1").ConsecutiveUpstream5xxCount(); got != 0 {
		t.Fatalf("count after success = %d, want 0", got)
	}
}

func TestMarkResult_Upstream5xxThreshold_NonResetOnNon5xxFailure(t *testing.T) {
	saveUpstream5xxThreshold(t)
	SetUpstream5xxSuspendThreshold(3)

	m := NewManager(nil, nil, nil)
	registerUpstream5xxTestAuth(t, m, &Auth{ID: "a1", Provider: "claude", Metadata: map[string]any{"disable_cooling": true}})
	markResult500(m, "a1", "x")
	m.MarkResult(context.Background(), Result{AuthID: "a1", Provider: "claude", Model: "x", Error: &Error{HTTPStatus: 429, Message: "quota"}})
	markResult500(m, "a1", "x")
	markResult500(m, "a1", "x")

	updated := getUpstream5xxTestAuth(t, m, "a1")
	if !updated.Disabled || updated.ConsecutiveUpstream5xxCount() != 3 {
		t.Fatalf("auth disabled=%v count=%d, want true 3", updated.Disabled, updated.ConsecutiveUpstream5xxCount())
	}
}

func TestMarkResult_Upstream5xxThreshold_GlobalZeroDisablesFeature(t *testing.T) {
	saveUpstream5xxThreshold(t)
	SetUpstream5xxSuspendThreshold(0)

	m := NewManager(nil, nil, nil)
	registerUpstream5xxTestAuth(t, m, &Auth{ID: "a1", Provider: "claude"})
	for range 100 {
		markResult500(m, "a1", "x")
	}

	updated := getUpstream5xxTestAuth(t, m, "a1")
	if updated.Disabled || updated.ConsecutiveUpstream5xxCount() != 0 {
		t.Fatalf("auth disabled=%v count=%d, want false 0", updated.Disabled, updated.ConsecutiveUpstream5xxCount())
	}
}

func TestMarkResult_Upstream5xxThreshold_AuthOverrideZeroDisablesPerAuth(t *testing.T) {
	saveUpstream5xxThreshold(t)
	SetUpstream5xxSuspendThreshold(5)

	m := NewManager(nil, nil, nil)
	registerUpstream5xxTestAuth(t, m, &Auth{ID: "a1", Provider: "claude", Metadata: map[string]any{"upstream_5xx_suspend_threshold": 0}})
	for range 10 {
		markResult500(m, "a1", "x")
	}

	updated := getUpstream5xxTestAuth(t, m, "a1")
	if updated.Disabled || updated.ConsecutiveUpstream5xxCount() != 0 {
		t.Fatalf("auth disabled=%v count=%d, want false 0", updated.Disabled, updated.ConsecutiveUpstream5xxCount())
	}
}

func TestMarkResult_Upstream5xxThreshold_AuthOverrideBeatsGlobal(t *testing.T) {
	saveUpstream5xxThreshold(t)
	SetUpstream5xxSuspendThreshold(10)

	m := NewManager(nil, nil, nil)
	registerUpstream5xxTestAuth(t, m, &Auth{ID: "a1", Provider: "claude", Metadata: map[string]any{"upstream_5xx_suspend_threshold": 2}})
	markResult500(m, "a1", "x")
	markResult500(m, "a1", "x")

	if updated := getUpstream5xxTestAuth(t, m, "a1"); !updated.Disabled {
		t.Fatalf("auth disabled=%v, want true", updated.Disabled)
	}
}

func TestManager_ResetUpstream5xxCount(t *testing.T) {
	saveUpstream5xxThreshold(t)
	SetUpstream5xxSuspendThreshold(10)

	m := NewManager(nil, nil, nil)
	registerUpstream5xxTestAuth(t, m, &Auth{ID: "a1", Provider: "claude"})
	for range 3 {
		markResult500(m, "a1", "x")
	}
	m.ResetUpstream5xxCount(context.Background(), "a1")
	if got := getUpstream5xxTestAuth(t, m, "a1").ConsecutiveUpstream5xxCount(); got != 0 {
		t.Fatalf("count after reset = %d, want 0", got)
	}
	markResult500(m, "a1", "x")
	if got := getUpstream5xxTestAuth(t, m, "a1").ConsecutiveUpstream5xxCount(); got != 1 {
		t.Fatalf("count after another 500 = %d, want 1", got)
	}
}

func TestManager_Update_PreservesUpstream5xxCount(t *testing.T) {
	saveUpstream5xxThreshold(t)
	SetUpstream5xxSuspendThreshold(10)

	m := NewManager(nil, nil, nil)
	registerUpstream5xxTestAuth(t, m, &Auth{ID: "a1", Provider: "claude"})
	markResult500(m, "a1", "x")
	markResult500(m, "a1", "x")
	if _, errUpdate := m.Update(context.Background(), &Auth{ID: "a1", Provider: "claude"}); errUpdate != nil {
		t.Fatalf("update auth: %v", errUpdate)
	}

	if got := getUpstream5xxTestAuth(t, m, "a1").ConsecutiveUpstream5xxCount(); got != 2 {
		t.Fatalf("count after update = %d, want 2", got)
	}
}

func TestSelector_ThresholdDisabledAuthIsExcluded(t *testing.T) {
	saveUpstream5xxThreshold(t)
	SetUpstream5xxSuspendThreshold(2)

	m := NewManager(nil, nil, nil)
	registerUpstream5xxTestAuth(t, m, &Auth{ID: "a1", Provider: "claude"})
	registerUpstream5xxTestAuth(t, m, &Auth{ID: "a2", Provider: "claude"})
	markResult500(m, "a1", "m")
	markResult500(m, "a1", "m")
	a1Clone := getUpstream5xxTestAuth(t, m, "a1")
	a2Clone := getUpstream5xxTestAuth(t, m, "a2")
	if !a1Clone.Disabled {
		t.Fatalf("a1 disabled=%v, want true", a1Clone.Disabled)
	}

	selected, errPick := (&RoundRobinSelector{}).Pick(context.Background(), "claude", "m", cliproxyexecutor.Options{}, []*Auth{a1Clone, a2Clone})
	if errPick != nil {
		t.Fatalf("pick enabled auth: %v", errPick)
	}
	if selected == nil || selected.ID != a2Clone.ID {
		t.Fatalf("selected auth = %#v, want a2", selected)
	}
	if _, errPick = (&RoundRobinSelector{}).Pick(context.Background(), "claude", "m", cliproxyexecutor.Options{}, []*Auth{a1Clone}); errPick == nil {
		t.Fatalf("expected error when only disabled auth is available")
	}
}

func TestMarkResult_Upstream5xxThreshold_DoesNotResetCounterPostSuspend(t *testing.T) {
	saveUpstream5xxThreshold(t)
	SetUpstream5xxSuspendThreshold(2)

	m := NewManager(nil, nil, nil)
	registerUpstream5xxTestAuth(t, m, &Auth{ID: "a1", Provider: "claude"})
	markResult500(m, "a1", "x")
	markResult500(m, "a1", "x")

	updated := getUpstream5xxTestAuth(t, m, "a1")
	if !updated.Disabled || updated.ConsecutiveUpstream5xxCount() != 2 {
		t.Fatalf("auth disabled=%v count=%d, want true 2", updated.Disabled, updated.ConsecutiveUpstream5xxCount())
	}
}

func TestRecordUpstream5xxAndMaybeSuspend_NilAuth(t *testing.T) {
	if recordUpstream5xxAndMaybeSuspend(nil, time.Now()) {
		t.Fatalf("nil auth suspended, want false")
	}
}

func TestAuth_ConsecutiveUpstream5xxCount_NilReceiver(t *testing.T) {
	if got := (*Auth)(nil).ConsecutiveUpstream5xxCount(); got != 0 {
		t.Fatalf("nil receiver count = %d, want 0", got)
	}
}

func TestAuth_Upstream5xxSuspendThresholdOverride_Variants(t *testing.T) {
	if got, ok := (&Auth{}).Upstream5xxSuspendThresholdOverride(); ok || got != 0 {
		t.Fatalf("nil metadata override = (%d, %v), want (0, false)", got, ok)
	}
	if got, ok := (&Auth{Metadata: map[string]any{"upstream_5xx_suspend_threshold": 2}}).Upstream5xxSuspendThresholdOverride(); !ok || got != 2 {
		t.Fatalf("override = (%d, %v), want (2, true)", got, ok)
	}
	if got, ok := (&Auth{Metadata: map[string]any{"upstream_5xx_suspend_threshold": -3}}).Upstream5xxSuspendThresholdOverride(); !ok || got != 0 {
		t.Fatalf("negative override = (%d, %v), want (0, true)", got, ok)
	}
	if got, ok := (&Auth{Metadata: map[string]any{"upstream-5xx-suspend-threshold": 7}}).Upstream5xxSuspendThresholdOverride(); !ok || got != 7 {
		t.Fatalf("legacy override = (%d, %v), want (7, true)", got, ok)
	}
}

func TestManager_Persist_SkipsAPIKeyAuthsWithoutFileBacking(t *testing.T) {
	saveUpstream5xxThreshold(t)
	SetUpstream5xxSuspendThreshold(2)

	store := &countingStore{}
	m := NewManager(store, nil, nil)
	registerUpstream5xxTestAuth(t, m, &Auth{ID: "a1", Provider: "claude", Metadata: map[string]any{"upstream_5xx_suspend_threshold": 2}})
	before := store.saveCount.Load()
	markResult500(m, "a1", "x")
	markResult500(m, "a1", "x")
	if got := store.saveCount.Load(); got != before {
		t.Fatalf("Save count after threshold = %d, want unchanged %d", got, before)
	}
}

func TestManager_Persist_StillFiresForFileBacked(t *testing.T) {
	saveUpstream5xxThreshold(t)
	SetUpstream5xxSuspendThreshold(2)

	store := &countingStore{}
	m := NewManager(store, nil, nil)
	registerUpstream5xxTestAuth(t, m, &Auth{
		ID:         "a1",
		Provider:   "claude",
		FileName:   "/tmp/foo.json",
		Attributes: map[string]string{"path": "/tmp/foo.json"},
		Metadata:   map[string]any{"type": "claude"},
	})
	before := store.saveCount.Load()
	markResult500(m, "a1", "x")
	markResult500(m, "a1", "x")
	if got := store.saveCount.Load(); got <= before {
		t.Fatalf("Save count after threshold = %d, want > %d", got, before)
	}
}
