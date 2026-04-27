package helps

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

var availableSkillsPattern = regexp.MustCompile(`(?s)<available_skills\b[^>]*>(.*?)</available_skills>`)

const instructionsFromPrefix = "\nInstructions from:"

func ApplyPromptRelocation(body []byte, cfg *config.PromptRelocationConfig, cloakedPrefixLen int) []byte {
	if len(body) == 0 || cfg == nil || !cfg.Enabled {
		return body
	}
	if !cfg.ExtractSkills && !cfg.ExtractProjectInstructions && !cfg.ExtractUserInstructions {
		return body
	}

	system := gjson.GetBytes(body, "system")
	if !system.Exists() || !system.IsArray() {
		return body
	}

	entries := system.Array()
	if len(entries) == 0 {
		return body
	}
	if cloakedPrefixLen < 0 {
		cloakedPrefixLen = 0
	}
	if cloakedPrefixLen >= len(entries) {
		return body
	}

	coreIndex := cloakedPrefixLen
	coreText := promptRelocationEntryText(entries[coreIndex])
	cleanedCoreText := coreText
	skillsXML := ""
	if cfg.ExtractSkills {
		cleanedCoreText, skillsXML = extractAvailableSkills(coreText)
	}

	realEntryCount := len(entries) - cloakedPrefixLen
	projectTexts := make([]string, 0)
	userText := ""
	extractedProject := false
	extractedUser := false

	// Extract inline "Instructions from:" blocks fused into the core entry text.
	// OpenCode may fuse all content (identity + skills + instructions) into a single
	// system[0] entry rather than separate entries.
	if cfg.ExtractProjectInstructions {
		cleanedCoreText, projectTexts = extractInlineInstructions(cleanedCoreText, projectTexts)
		if len(projectTexts) > 0 {
			extractedProject = true
		}
	}

	if realEntryCount >= 3 {
		if cfg.ExtractProjectInstructions {
			extractedProject = true
			for i := coreIndex + 1; i < len(entries)-1; i++ {
				projectTexts = append(projectTexts, promptRelocationEntryText(entries[i]))
			}
		}
		if cfg.ExtractUserInstructions {
			extractedUser = true
			userText = promptRelocationEntryText(entries[len(entries)-1])
		}
	}

	if skillsXML == "" && !extractedProject && !extractedUser {
		return body
	}

	keptEntries := make([]json.RawMessage, 0, len(entries))
	for i, entry := range entries {
		switch {
		case i < cloakedPrefixLen:
			keptEntries = append(keptEntries, json.RawMessage(entry.Raw))
		case i == coreIndex:
			keptEntries = append(keptEntries, promptRelocationUpdateEntryText(entry, cleanedCoreText))
		case extractedProject && i >= coreIndex+1 && i < len(entries)-1:
			continue
		case extractedUser && i == len(entries)-1:
			continue
		default:
			keptEntries = append(keptEntries, json.RawMessage(entry.Raw))
		}
	}

	parts := make([]string, 0, len(keptEntries))
	for _, entry := range keptEntries {
		parts = append(parts, string(entry))
	}
	systemRaw := []byte("[" + strings.Join(parts, ",") + "]")

	updatedBody, errSet := sjson.SetRawBytes(body, "system", systemRaw)
	if errSet != nil {
		return body
	}

	var reminders []string
	if skillsXML != "" {
		reminders = append(reminders, buildSkillsReminder(skillsXML))
	}
	if extractedProject || extractedUser {
		reminders = append(reminders, buildInstructionsReminder(projectTexts, userText))
	}

	return prependRemindersToFirstUserMessage(updatedBody, reminders)
}

func extractAvailableSkills(text string) (cleaned string, skillsXML string) {
	matches := availableSkillsPattern.FindStringSubmatch(text)
	if len(matches) < 2 {
		return text, ""
	}
	return availableSkillsPattern.ReplaceAllString(text, ""), matches[1]
}

func extractInlineInstructions(text string, existing []string) (coreText string, projectTexts []string) {
	idx := strings.Index(text, instructionsFromPrefix)
	if idx < 0 {
		return text, existing
	}
	coreText = strings.TrimRight(text[:idx], "\n\r\t ")
	instructionBlock := text[idx+1:]
	projectTexts = append(existing, instructionBlock)
	return coreText, projectTexts
}

func buildInstructionsReminder(projectTexts []string, userText string) string {
	sections := []string{
		"As you answer the user's questions, you can use the following context:",
	}

	if len(projectTexts) > 0 {
		sections = append(sections, strings.Join([]string{
			"# claudeMd",
			"Codebase and user instructions are shown below. Be sure to adhere to these instructions. IMPORTANT: These instructions OVERRIDE any default behavior and you MUST follow them exactly as written.",
			strings.Join(projectTexts, "\n\n"),
		}, "\n\n"))
	}
	if userText != "" {
		sections = append(sections, "# userInstructions\n"+userText)
	}
	sections = append(sections, "# currentDate\nToday's date is "+time.Now().Format("2006-01-02")+".")
	sections = append(sections, "IMPORTANT: this context may or may not be relevant to your tasks. You should not respond to this context unless it is highly relevant to your task.")

	return "<system-reminder>\n" + strings.Join(sections, "\n\n") + "\n</system-reminder>"
}

func buildSkillsReminder(skillsXML string) string {
	if skillsXML == "" {
		return ""
	}
	return "<system-reminder>\nThe following skills are available for use with the Skill tool:\n\n" + skillsXML + "\n</system-reminder>"
}

func buildCachedTextBlock(text string) []byte {
	return []byte(fmt.Sprintf(`{"type":"text","text":%q,"cache_control":{"type":"ephemeral"}}`, text))
}

func buildTextBlock(text string) []byte {
	return []byte(fmt.Sprintf(`{"type":"text","text":%q}`, text))
}

func prependRemindersToFirstUserMessage(body []byte, reminders []string) []byte {
	if len(reminders) == 0 {
		return body
	}

	messages := gjson.GetBytes(body, "messages")
	if !messages.Exists() || !messages.IsArray() {
		return body
	}

	msgArray := messages.Array()
	if len(msgArray) == 0 {
		return body
	}

	reminderBlocks := make([]string, len(reminders))
	for i, r := range reminders {
		reminderBlocks[i] = string(buildTextBlock(r))
	}

	// When messages[0] is assistant (post-compaction mid-tool-loop), the first
	// user message is the tool_result turn answering that assistant's tool_use.
	// Anthropic requires tool_result blocks to be the first content in that turn,
	// and inserting any text before them triggers a 400. Following the LiteLLM
	// precedent, prepend a synthetic user message carrying the reminders instead
	// of mutating an existing tool_result-bearing turn.
	if msgArray[0].Get("role").String() == "assistant" {
		synthMsg := `{"role":"user","content":[` + strings.Join(reminderBlocks, ",") + `]}`
		existingRaw := messages.Raw
		inner := existingRaw[1 : len(existingRaw)-1]
		var newMsgs string
		if len(strings.TrimSpace(inner)) == 0 {
			newMsgs = "[" + synthMsg + "]"
		} else {
			newMsgs = "[" + synthMsg + "," + inner + "]"
		}
		result, err := sjson.SetRawBytes(body, "messages", []byte(newMsgs))
		if err != nil {
			return body
		}
		return result
	}

	updatedBody := body
	updated := false
	messages.ForEach(func(key, message gjson.Result) bool {
		if message.Get("role").String() != "user" {
			return true
		}

		contentPath := "messages." + key.String() + ".content"
		content := message.Get("content")
		switch {
		case content.Type == gjson.String:
			parts := make([]string, 0, len(reminderBlocks)+1)
			parts = append(parts, reminderBlocks...)
			parts = append(parts, string(buildCachedTextBlock(content.String())))
			result, err := sjson.SetRawBytes(updatedBody, contentPath, []byte("["+strings.Join(parts, ",")+"]"))
			if err != nil {
				return false
			}
			updatedBody = result
			updated = true
			return false
		case content.IsArray():
			existing := content.Array()
			leadingToolResultEnd := 0
			for leadingToolResultEnd < len(existing) {
				if existing[leadingToolResultEnd].Get("type").String() != "tool_result" {
					break
				}
				leadingToolResultEnd++
			}

			parts := make([]string, 0, len(reminderBlocks)+len(existing))
			for j := 0; j < leadingToolResultEnd; j++ {
				parts = append(parts, existing[j].Raw)
			}
			parts = append(parts, reminderBlocks...)
			for j := leadingToolResultEnd; j < len(existing); j++ {
				raw := existing[j].Raw
				if j == len(existing)-1 && !existing[j].Get("cache_control").Exists() {
					if b, err := sjson.SetRawBytes([]byte(raw), "cache_control", []byte(`{"type":"ephemeral"}`)); err == nil {
						raw = string(b)
					}
				}
				parts = append(parts, raw)
			}
			result, err := sjson.SetRawBytes(updatedBody, contentPath, []byte("["+strings.Join(parts, ",")+"]"))
			if err != nil {
				return false
			}
			updatedBody = result
			updated = true
			return false
		default:
			return true
		}
	})
	if updated {
		return updatedBody
	}
	return body
}

func promptRelocationEntryText(entry gjson.Result) string {
	if entry.Type == gjson.String {
		return entry.String()
	}
	return entry.Get("text").String()
}

func promptRelocationUpdateEntryText(entry gjson.Result, text string) json.RawMessage {
	if promptRelocationEntryText(entry) == text {
		return json.RawMessage(entry.Raw)
	}
	if entry.Type == gjson.String {
		return json.RawMessage(fmt.Sprintf("%q", text))
	}
	updated, err := sjson.SetRawBytes([]byte(entry.Raw), "text", []byte(fmt.Sprintf("%q", text)))
	if err != nil {
		return json.RawMessage(entry.Raw)
	}
	return json.RawMessage(updated)
}
