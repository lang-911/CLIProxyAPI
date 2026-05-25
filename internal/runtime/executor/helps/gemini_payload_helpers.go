package helps

import (
	"fmt"

	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

// StripGeminiUnsupportedFunctionIDs removes the `id` field from every
// functionCall / functionResponse part inside `contents[*].parts[*]`.
//
// Google's Generative Language API (v1beta) and Vertex AI both reject any
// unknown field under FunctionCall / FunctionResponse with an
// INVALID_ARGUMENT 400 (e.g.
// "Unknown name \"id\" at 'contents[1].parts[0].function_call'"). This can
// happen when an upstream translator or a caller (e.g. AI SDK clients,
// chained CPA proxies) attaches an OpenAI-style tool call ID to those parts.
//
// Both JSON spellings are stripped because Gemini protobuf JSON accepts
// camelCase ("functionCall") and snake_case ("function_call") field names,
// and inbound payloads use either form.
func StripGeminiUnsupportedFunctionIDs(payload []byte) []byte {
	contents := gjson.GetBytes(payload, "contents")
	if !contents.IsArray() {
		return payload
	}

	out := payload
	keys := []string{
		"functionCall.id",
		"functionResponse.id",
		"function_call.id",
		"function_response.id",
	}
	for contentIndex, content := range contents.Array() {
		parts := content.Get("parts")
		if !parts.IsArray() {
			continue
		}
		for partIndex := range parts.Array() {
			for _, key := range keys {
				path := fmt.Sprintf("contents.%d.parts.%d.%s", contentIndex, partIndex, key)
				if !gjson.GetBytes(out, path).Exists() {
					continue
				}
				if updated, errDelete := sjson.DeleteBytes(out, path); errDelete == nil {
					out = updated
				}
			}
		}
	}
	return out
}
