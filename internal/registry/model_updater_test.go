package registry

import "testing"

func TestSnapshotModelSection_KnownModel(t *testing.T) {
	t.Parallel()

	snapshot := snapshotModelSection(getModels().Claude, "claude-sonnet-4-6")
	if snapshot.ID != "claude-sonnet-4-6" {
		t.Fatalf("snapshot.ID = %q, want %q", snapshot.ID, "claude-sonnet-4-6")
	}
	if snapshot.ContextLength != 1_000_000 {
		t.Fatalf("snapshot.ContextLength = %d, want %d", snapshot.ContextLength, 1_000_000)
	}
	if snapshot.MaxCompletionTokens == 0 {
		t.Fatalf("snapshot.MaxCompletionTokens = %d, want non-zero", snapshot.MaxCompletionTokens)
	}
	if !snapshot.HasThinking {
		t.Fatal("snapshot.HasThinking = false, want true")
	}
}

func TestSnapshotModelSection_MissingModel(t *testing.T) {
	t.Parallel()

	snapshot := snapshotModelSection(getModels().Claude, "claude-missing-model")
	if snapshot != (modelDebugSnapshot{}) {
		t.Fatalf("snapshot = %+v, want zero value", snapshot)
	}
}

func TestClaudeCatalogDebugSnapshots_UsesProvidedCatalog(t *testing.T) {
	t.Parallel()

	oldData := &staticModelsJSON{
		Claude: []*ModelInfo{
			{ID: "claude-sonnet-4-6", ContextLength: 200_000, MaxCompletionTokens: 64_000},
			{ID: "claude-opus-4-6", ContextLength: 1_000_000, MaxCompletionTokens: 128_000, Thinking: &ThinkingSupport{}},
		},
	}
	newData := &staticModelsJSON{
		Claude: []*ModelInfo{
			{ID: "claude-sonnet-4-6", ContextLength: 1_000_000, MaxCompletionTokens: 64_000, Thinking: &ThinkingSupport{}},
			{ID: "claude-opus-4-6", ContextLength: 1_000_000, MaxCompletionTokens: 128_000, Thinking: &ThinkingSupport{}},
		},
	}

	oldSnapshots := claudeCatalogDebugSnapshots(oldData)
	newSnapshots := claudeCatalogDebugSnapshots(newData)
	if len(oldSnapshots) != 2 || len(newSnapshots) != 2 {
		t.Fatalf("unexpected snapshot lengths old=%d new=%d", len(oldSnapshots), len(newSnapshots))
	}
	if oldSnapshots[0].ContextLength != 200_000 {
		t.Fatalf("old sonnet context_length = %d, want %d", oldSnapshots[0].ContextLength, 200_000)
	}
	if newSnapshots[0].ContextLength != 1_000_000 {
		t.Fatalf("new sonnet context_length = %d, want %d", newSnapshots[0].ContextLength, 1_000_000)
	}
	if oldSnapshots[0].HasThinking {
		t.Fatal("old sonnet HasThinking = true, want false")
	}
	if !newSnapshots[0].HasThinking {
		t.Fatal("new sonnet HasThinking = false, want true")
	}
}
