package helps

import (
	"testing"

	"github.com/tidwall/gjson"
)

// TestStripGeminiUnsupportedFunctionIDs_CamelCase verifies that `id` fields
// emitted on functionCall / functionResponse parts are removed.
func TestStripGeminiUnsupportedFunctionIDs_CamelCase(t *testing.T) {
	payload := []byte(`{
        "contents":[
            {"role":"user","parts":[{"text":"hi"}]},
            {"role":"model","parts":[{"functionCall":{"id":"call_1","name":"lookup","args":{"q":"x"}}}]},
            {"role":"user","parts":[{"functionResponse":{"id":"call_1","name":"lookup","response":{"r":"ok"}}}]}
        ]
    }`)

	out := StripGeminiUnsupportedFunctionIDs(payload)

	if gjson.GetBytes(out, "contents.1.parts.0.functionCall.id").Exists() {
		t.Errorf("functionCall.id should be removed: %s", string(out))
	}
	if gjson.GetBytes(out, "contents.2.parts.0.functionResponse.id").Exists() {
		t.Errorf("functionResponse.id should be removed: %s", string(out))
	}
	// Unrelated fields must survive.
	if got := gjson.GetBytes(out, "contents.1.parts.0.functionCall.name").String(); got != "lookup" {
		t.Errorf("functionCall.name lost, got %q", got)
	}
	if got := gjson.GetBytes(out, "contents.2.parts.0.functionResponse.name").String(); got != "lookup" {
		t.Errorf("functionResponse.name lost, got %q", got)
	}
	if got := gjson.GetBytes(out, "contents.1.parts.0.functionCall.args.q").String(); got != "x" {
		t.Errorf("functionCall.args lost, got %q", got)
	}
}

// TestStripGeminiUnsupportedFunctionIDs_SnakeCase verifies that the snake_case
// proto JSON variant is also stripped. Gemini protobuf JSON accepts both
// camelCase and snake_case field names.
func TestStripGeminiUnsupportedFunctionIDs_SnakeCase(t *testing.T) {
	payload := []byte(`{
        "contents":[
            {"role":"user","parts":[{"text":"hi"}]},
            {"role":"model","parts":[{"function_call":{"id":"call_1","name":"lookup","args":{}}}]},
            {"role":"user","parts":[{"function_response":{"id":"call_1","name":"lookup","response":{}}}]}
        ]
    }`)

	out := StripGeminiUnsupportedFunctionIDs(payload)

	if gjson.GetBytes(out, "contents.1.parts.0.function_call.id").Exists() {
		t.Errorf("function_call.id should be removed: %s", string(out))
	}
	if gjson.GetBytes(out, "contents.2.parts.0.function_response.id").Exists() {
		t.Errorf("function_response.id should be removed: %s", string(out))
	}
}

// TestStripGeminiUnsupportedFunctionIDs_NoContents ensures the helper is a
// no-op when there is no `contents` array (e.g. countTokens preprocessing).
func TestStripGeminiUnsupportedFunctionIDs_NoContents(t *testing.T) {
	payload := []byte(`{"model":"gemini-2.5-pro"}`)
	out := StripGeminiUnsupportedFunctionIDs(payload)
	if string(out) != string(payload) {
		t.Errorf("expected unchanged payload, got %s", string(out))
	}
}

// TestStripGeminiUnsupportedFunctionIDs_NoIDFields ensures payloads without
// any `id` field are returned unchanged in content.
func TestStripGeminiUnsupportedFunctionIDs_NoIDFields(t *testing.T) {
	payload := []byte(`{"contents":[{"role":"user","parts":[{"text":"hi"}]}]}`)
	out := StripGeminiUnsupportedFunctionIDs(payload)
	if got := gjson.GetBytes(out, "contents.0.parts.0.text").String(); got != "hi" {
		t.Errorf("text lost, got %q", got)
	}
}
