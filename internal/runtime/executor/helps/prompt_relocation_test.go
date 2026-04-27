package helps

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	"github.com/tidwall/gjson"
)

func TestPromptRelocation(t *testing.T) {
	t.Run("ApplyPromptRelocation_Disabled", func(t *testing.T) {
		body := basePromptRelocationBody()
		cfg := &config.PromptRelocationConfig{Enabled: false, ExtractSkills: true, ExtractProjectInstructions: true, ExtractUserInstructions: true}

		got := ApplyPromptRelocation(body, cfg, 0)
		if !bytes.Equal(got, body) {
			t.Fatal("expected body to remain unchanged")
		}
	})

	t.Run("ApplyPromptRelocation_NilConfig", func(t *testing.T) {
		body := basePromptRelocationBody()

		got := ApplyPromptRelocation(body, nil, 0)
		if !bytes.Equal(got, body) {
			t.Fatal("expected body to remain unchanged")
		}
	})

	t.Run("ApplyPromptRelocation_NoSystemField", func(t *testing.T) {
		body := []byte(`{"messages":[{"role":"user","content":"hello"}]}`)
		cfg := &config.PromptRelocationConfig{Enabled: true, ExtractSkills: true}

		got := ApplyPromptRelocation(body, cfg, 0)
		if !bytes.Equal(got, body) {
			t.Fatal("expected body to remain unchanged")
		}
	})

	t.Run("ApplyPromptRelocation_StringSystem", func(t *testing.T) {
		body := []byte(`{"system":"plain system","messages":[{"role":"user","content":"hello"}]}`)
		cfg := &config.PromptRelocationConfig{Enabled: true, ExtractSkills: true}

		got := ApplyPromptRelocation(body, cfg, 0)
		if !bytes.Equal(got, body) {
			t.Fatal("expected body to remain unchanged")
		}
	})

	t.Run("ApplyPromptRelocation_FullExtraction", func(t *testing.T) {
		body := basePromptRelocationBody()
		cfg := &config.PromptRelocationConfig{Enabled: true, ExtractSkills: true, ExtractProjectInstructions: true, ExtractUserInstructions: true}

		got := ApplyPromptRelocation(body, cfg, 0)
		if got == nil {
			t.Fatal("expected non-nil body")
		}
		if len(gjson.GetBytes(got, "system").Array()) != 1 {
			t.Fatalf("system length = %d, want 1", len(gjson.GetBytes(got, "system").Array()))
		}
		coreText := gjson.GetBytes(got, "system.0.text").String()
		if strings.Contains(coreText, "<available_skills") {
			t.Fatalf("core text still contains skills block: %q", coreText)
		}
		skillsBlock := gjson.GetBytes(got, "messages.0.content.0.text").String()
		if !strings.Contains(skillsBlock, "<skill><name>bit-cli</name><description>CLI reference</description></skill>") {
			t.Fatalf("skills block missing skills xml: %q", skillsBlock)
		}
		instrBlock := gjson.GetBytes(got, "messages.0.content.1.text").String()
		if !strings.Contains(instrBlock, "# claudeMd") {
			t.Fatalf("instructions block missing claudeMd section: %q", instrBlock)
		}
		if !strings.Contains(instrBlock, "# userInstructions") {
			t.Fatalf("instructions block missing userInstructions section: %q", instrBlock)
		}
		if !strings.Contains(instrBlock, "# currentDate") {
			t.Fatalf("instructions block missing currentDate section: %q", instrBlock)
		}
	})

	t.Run("ApplyPromptRelocation_SkillsOnly", func(t *testing.T) {
		body := basePromptRelocationBody()
		cfg := &config.PromptRelocationConfig{Enabled: true, ExtractSkills: true}

		got := ApplyPromptRelocation(body, cfg, 0)
		if len(gjson.GetBytes(got, "system").Array()) != 4 {
			t.Fatalf("system length = %d, want 4", len(gjson.GetBytes(got, "system").Array()))
		}
		coreText := gjson.GetBytes(got, "system.0.text").String()
		if strings.Contains(coreText, "<available_skills") {
			t.Fatalf("core text still contains skills block: %q", coreText)
		}
		reminder := gjson.GetBytes(got, "messages.0.content.0.text").String()
		if !strings.Contains(reminder, "The following skills are available") {
			t.Fatalf("reminder missing skills section: %q", reminder)
		}
		if strings.Contains(reminder, "# claudeMd") {
			t.Fatalf("unexpected claudeMd section: %q", reminder)
		}
	})

	t.Run("ApplyPromptRelocation_ProjectOnly", func(t *testing.T) {
		body := basePromptRelocationBody()
		cfg := &config.PromptRelocationConfig{Enabled: true, ExtractProjectInstructions: true}

		got := ApplyPromptRelocation(body, cfg, 0)
		if len(gjson.GetBytes(got, "system").Array()) != 2 {
			t.Fatalf("system length = %d, want 2", len(gjson.GetBytes(got, "system").Array()))
		}
		reminder := gjson.GetBytes(got, "messages.0.content.0.text").String()
		if !strings.Contains(reminder, "# claudeMd") {
			t.Fatalf("reminder missing claudeMd section: %q", reminder)
		}
		if strings.Contains(reminder, "# userInstructions") {
			t.Fatalf("unexpected userInstructions section: %q", reminder)
		}
	})

	t.Run("ApplyPromptRelocation_UserOnly", func(t *testing.T) {
		body := basePromptRelocationBody()
		cfg := &config.PromptRelocationConfig{Enabled: true, ExtractUserInstructions: true}

		got := ApplyPromptRelocation(body, cfg, 0)
		if len(gjson.GetBytes(got, "system").Array()) != 3 {
			t.Fatalf("system length = %d, want 3", len(gjson.GetBytes(got, "system").Array()))
		}
		reminder := gjson.GetBytes(got, "messages.0.content.0.text").String()
		if !strings.Contains(reminder, "# userInstructions") {
			t.Fatalf("reminder missing userInstructions section: %q", reminder)
		}
		if strings.Contains(reminder, "# claudeMd") {
			t.Fatalf("unexpected claudeMd section: %q", reminder)
		}
	})

	t.Run("ApplyPromptRelocation_WithCloakedPrefix", func(t *testing.T) {
		body := []byte(`{
			"system":[
				{"type":"text","text":"cloaked-one"},
				{"type":"text","text":"cloaked-two","cache_control":{"type":"ephemeral"}},
				{"type":"text","text":"Core prompt\n<available_skills><skill><name>bit-cli</name></skill></available_skills>"},
				{"type":"text","text":"Project one"},
				"Project two",
				{"type":"text","text":"User instruction"}
			],
			"messages":[{"role":"user","content":[{"type":"text","text":"hello"}]}]
		}`)
		cfg := &config.PromptRelocationConfig{Enabled: true, ExtractSkills: true, ExtractProjectInstructions: true, ExtractUserInstructions: true}

		got := ApplyPromptRelocation(body, cfg, 2)
		if len(gjson.GetBytes(got, "system").Array()) != 3 {
			t.Fatalf("system length = %d, want 3", len(gjson.GetBytes(got, "system").Array()))
		}
		if gjson.GetBytes(got, "system.0.text").String() != "cloaked-one" {
			t.Fatalf("unexpected first cloaked text: %q", gjson.GetBytes(got, "system.0.text").String())
		}
		if gjson.GetBytes(got, "system.1.text").String() != "cloaked-two" {
			t.Fatalf("unexpected second cloaked text: %q", gjson.GetBytes(got, "system.1.text").String())
		}
	})

	t.Run("ApplyPromptRelocation_TooFewEntries", func(t *testing.T) {
		body := []byte(`{
			"system":[
				{"type":"text","text":"Core prompt\n<available_skills><skill><name>bit-cli</name></skill></available_skills>"},
				{"type":"text","text":"Only one extra entry"}
			],
			"messages":[{"role":"user","content":[{"type":"text","text":"hello"}]}]
		}`)
		cfg := &config.PromptRelocationConfig{Enabled: true, ExtractSkills: true, ExtractProjectInstructions: true, ExtractUserInstructions: true}

		got := ApplyPromptRelocation(body, cfg, 0)
		if len(gjson.GetBytes(got, "system").Array()) != 2 {
			t.Fatalf("system length = %d, want 2", len(gjson.GetBytes(got, "system").Array()))
		}
		reminder := gjson.GetBytes(got, "messages.0.content.0.text").String()
		if strings.Contains(reminder, "# claudeMd") || strings.Contains(reminder, "# userInstructions") {
			t.Fatalf("unexpected instructions sections: %q", reminder)
		}
		if !strings.Contains(reminder, "The following skills are available") {
			t.Fatalf("reminder missing skills section: %q", reminder)
		}
	})

	t.Run("ApplyPromptRelocation_NoSkillsInPrompt", func(t *testing.T) {
		body := []byte(`{
			"system":[{"type":"text","text":"Core prompt without skills"}],
			"messages":[{"role":"user","content":[{"type":"text","text":"hello"}]}]
		}`)
		cfg := &config.PromptRelocationConfig{Enabled: true, ExtractSkills: true}

		got := ApplyPromptRelocation(body, cfg, 0)
		if !bytes.Equal(got, body) {
			t.Fatal("expected body to remain unchanged")
		}
	})

	t.Run("ApplyPromptRelocation_StringUserContent", func(t *testing.T) {
		body := []byte(`{
			"system":[
				{"type":"text","text":"Core prompt\n<available_skills><skill><name>bit-cli</name></skill></available_skills>"},
				{"type":"text","text":"Project one"},
				{"type":"text","text":"User instruction"}
			],
			"messages":[{"role":"user","content":"plain user content"}]
		}`)
		cfg := &config.PromptRelocationConfig{Enabled: true, ExtractSkills: true, ExtractProjectInstructions: true, ExtractUserInstructions: true}

		got := ApplyPromptRelocation(body, cfg, 0)
		content := gjson.GetBytes(got, "messages.0.content")
		if !content.IsArray() {
			t.Fatal("expected string content to be converted to array")
		}
		if len(content.Array()) != 3 {
			t.Fatalf("content length = %d, want 3 (instructions + skills + original)", len(content.Array()))
		}
		if gjson.GetBytes(got, "messages.0.content.2.text").String() != "plain user content" {
			t.Fatalf("original content text = %q, want plain user content", gjson.GetBytes(got, "messages.0.content.2.text").String())
		}
	})

	t.Run("ApplyPromptRelocation_PreservesOtherFields", func(t *testing.T) {
		body := basePromptRelocationBody()
		cfg := &config.PromptRelocationConfig{Enabled: true, ExtractSkills: true, ExtractProjectInstructions: true, ExtractUserInstructions: true}

		got := ApplyPromptRelocation(body, cfg, 0)
		if gjson.GetBytes(got, "model").String() != "claude-sonnet-4" {
			t.Fatalf("model = %q, want claude-sonnet-4", gjson.GetBytes(got, "model").String())
		}
		if gjson.GetBytes(got, "temperature").Num != 0.2 {
			t.Fatalf("temperature = %v, want 0.2", gjson.GetBytes(got, "temperature").Num)
		}
		if len(gjson.GetBytes(got, "tools").Array()) != 1 {
			t.Fatalf("tools length = %d, want 1", len(gjson.GetBytes(got, "tools").Array()))
		}
	})

	t.Run("ApplyPromptRelocation_CurrentDate", func(t *testing.T) {
		body := basePromptRelocationBody()
		cfg := &config.PromptRelocationConfig{Enabled: true, ExtractProjectInstructions: true}

		got := ApplyPromptRelocation(body, cfg, 0)
		wantDate := time.Now().Format("2006-01-02")
		reminder := gjson.GetBytes(got, "messages.0.content.0.text").String()
		if !strings.Contains(reminder, wantDate) {
			t.Fatalf("reminder missing current date %q: %q", wantDate, reminder)
		}
	})
}

func TestExtractAvailableSkills(t *testing.T) {
	text := strings.Join([]string{
		"Before",
		"<available_skills>",
		"  <skill>",
		"    <name>bit-cli</name>",
		"    <description>CLI reference</description>",
		"  </skill>",
		"</available_skills>",
		"After",
	}, "\n")

	cleaned, skillsXML := extractAvailableSkills(text)
	if strings.Contains(cleaned, "<available_skills>") {
		t.Fatalf("cleaned text still contains skills tag: %q", cleaned)
	}
	if !strings.Contains(cleaned, "Before") || !strings.Contains(cleaned, "After") {
		t.Fatalf("cleaned text lost surrounding content: %q", cleaned)
	}
	if !strings.Contains(skillsXML, "<name>bit-cli</name>") {
		t.Fatalf("skills xml missing name: %q", skillsXML)
	}
	if !strings.Contains(skillsXML, "<description>CLI reference</description>") {
		t.Fatalf("skills xml missing description: %q", skillsXML)
	}
}

func TestApplyPromptRelocation_NoUnicodeEscaping(t *testing.T) {
	cfg := &config.PromptRelocationConfig{Enabled: true, ExtractSkills: true, ExtractProjectInstructions: true, ExtractUserInstructions: true}
	body := basePromptRelocationBody()
	out := ApplyPromptRelocation(body, cfg, 0)

	outStr := string(out)
	if strings.Contains(outStr, `\u003c`) || strings.Contains(outStr, `\u003e`) {
		t.Fatal("output contains unicode-escaped angle brackets; expected literal < and >")
	}
	reminder := gjson.GetBytes(out, "messages.0.content.0.text").String()
	if !strings.Contains(reminder, "<system-reminder>") {
		t.Fatalf("expected literal <system-reminder> tag in reminder, got: %s", reminder[:200])
	}
}

func TestApplyPromptRelocation_InlineInstructionsFromSingleEntry(t *testing.T) {
	cfg := &config.PromptRelocationConfig{Enabled: true, ExtractSkills: true, ExtractProjectInstructions: true}
	body := []byte(`{
		"system":[
			{"type":"text","text":"You are Claude Code.\n<available_skills><skill><name>bit-cli</name><description>CLI ref</description></skill></available_skills>\nInstructions from: /path/to/AGENTS.md\n# Repository Guidelines\n\nFollow conventions.\n\nInstructions from: /path/to/rules/testing.md\n# Testing\n\nAlways test.","cache_control":{"type":"ephemeral"}}
		],
		"messages":[
			{"role":"user","content":[{"type":"text","text":"Hi"}]}
		]
	}`)

	out := ApplyPromptRelocation(body, cfg, 0)

	coreText := gjson.GetBytes(out, "system.0.text").String()
	if strings.Contains(coreText, "Instructions from:") {
		t.Fatal("core text still contains Instructions from: blocks")
	}
	if !strings.Contains(coreText, "You are Claude Code.") {
		t.Fatal("core identity text was removed")
	}
	if strings.Contains(coreText, "<available_skills>") {
		t.Fatal("skills not stripped from core text")
	}

	skillsBlock := gjson.GetBytes(out, "messages.0.content.0.text").String()
	if !strings.Contains(skillsBlock, "bit-cli") {
		t.Fatal("skills block missing skills")
	}
	instrBlock := gjson.GetBytes(out, "messages.0.content.1.text").String()
	if !strings.Contains(instrBlock, "# claudeMd") {
		t.Fatal("instructions block missing # claudeMd section")
	}
	if !strings.Contains(instrBlock, "Repository Guidelines") {
		t.Fatal("instructions block missing AGENTS.md content")
	}
	if !strings.Contains(instrBlock, "Always test") {
		t.Fatal("instructions block missing testing.md content")
	}
}

func TestExtractInlineInstructions(t *testing.T) {
	text := "Core prompt text here.\nInstructions from: /path/AGENTS.md\n# Repo\nFollow rules.\n\nInstructions from: /path/rules/test.md\n# Testing\nTest all."
	core, projects := extractInlineInstructions(text, nil)
	if core != "Core prompt text here." {
		t.Fatalf("unexpected core text: %q", core)
	}
	if len(projects) != 1 {
		t.Fatalf("expected 1 project block, got %d", len(projects))
	}
	if !strings.Contains(projects[0], "Instructions from: /path/AGENTS.md") {
		t.Fatalf("project block missing first instruction: %q", projects[0])
	}
	if !strings.Contains(projects[0], "Instructions from: /path/rules/test.md") {
		t.Fatalf("project block missing second instruction: %q", projects[0])
	}
}

func TestExtractInlineInstructions_NoMatch(t *testing.T) {
	text := "Just a plain core prompt with no instructions."
	core, projects := extractInlineInstructions(text, nil)
	if core != text {
		t.Fatalf("expected unchanged core, got: %q", core)
	}
	if len(projects) != 0 {
		t.Fatalf("expected no projects, got %d", len(projects))
	}
}

func basePromptRelocationBody() []byte {
	return []byte(`{
		"model":"claude-sonnet-4",
		"temperature":0.2,
		"tools":[{"name":"bash"}],
		"system":[
			{"type":"text","text":"You are Claude Code.\n<available_skills><skill><name>bit-cli</name><description>CLI reference</description></skill></available_skills>","cache_control":{"type":"ephemeral"}},
			{"type":"text","text":"Project instruction one."},
			"Project instruction two.",
			{"type":"text","text":"User instruction here."}
		],
		"messages":[
			{"role":"assistant","content":[{"type":"text","text":"Not the target"}]},
			{"role":"user","content":[{"type":"text","text":"Please help"}]}
		]
	}`)
}

func TestApplyPromptRelocation_PreservesLeadingToolResultBlocks(t *testing.T) {
	cfg := &config.PromptRelocationConfig{Enabled: true, ExtractSkills: true, ExtractProjectInstructions: true, ExtractUserInstructions: true}
	body := []byte(`{
		"system":[
			{"type":"text","text":"You are Claude Code.\n<available_skills><skill><name>bit-cli</name><description>CLI reference</description></skill></available_skills>","cache_control":{"type":"ephemeral"}},
			{"type":"text","text":"Project instruction one."},
			"Project instruction two.",
			{"type":"text","text":"User instruction here."}
		],
		"messages":[
			{"role":"assistant","content":[
				{"type":"tool_use","id":"toolu_01","name":"Read","input":{"path":"/a"}},
				{"type":"tool_use","id":"toolu_02","name":"Read","input":{"path":"/b"}}
			]},
			{"role":"user","content":[
				{"type":"tool_result","tool_use_id":"toolu_01","content":"ok"},
				{"type":"tool_result","tool_use_id":"toolu_02","content":"ok"},
				{"type":"text","text":"Trailing user text."}
			]}
		]
	}`)

	out := ApplyPromptRelocation(body, cfg, 0)

	msgs := gjson.GetBytes(out, "messages").Array()
	if len(msgs) != 3 {
		t.Fatalf("expected 3 messages (synthetic + original 2), got %d", len(msgs))
	}
	if msgs[0].Get("role").String() != "user" {
		t.Fatalf("synthetic message role = %q, want user", msgs[0].Get("role").String())
	}
	synthContent := msgs[0].Get("content").Array()
	if !strings.Contains(synthContent[0].Get("text").String(), "The following skills are available") {
		t.Fatalf("synthetic message missing skills reminder: %s", synthContent[0].Raw)
	}
	if !strings.Contains(synthContent[1].Get("text").String(), "# claudeMd") {
		t.Fatalf("synthetic message missing instructions reminder: %s", synthContent[1].Raw)
	}
	if msgs[1].Get("role").String() != "assistant" {
		t.Fatalf("original assistant message moved to index 1")
	}
	userContent := msgs[2].Get("content").Array()
	if userContent[0].Get("type").String() != "tool_result" || userContent[0].Get("tool_use_id").String() != "toolu_01" {
		t.Fatalf("user content[0] = %s, want first tool_result toolu_01", userContent[0].Raw)
	}
	if userContent[1].Get("type").String() != "tool_result" || userContent[1].Get("tool_use_id").String() != "toolu_02" {
		t.Fatalf("user content[1] = %s, want second tool_result toolu_02", userContent[1].Raw)
	}
	if userContent[2].Get("text").String() != "Trailing user text." {
		t.Fatalf("trailing user text not preserved: %s", userContent[2].Raw)
	}
}

func TestApplyPromptRelocation_AllToolResultsNoTrailingText(t *testing.T) {
	cfg := &config.PromptRelocationConfig{Enabled: true, ExtractSkills: true}
	body := []byte(`{
		"system":[
			{"type":"text","text":"You are Claude Code.\n<available_skills><skill><name>bit-cli</name></skill></available_skills>"}
		],
		"messages":[
			{"role":"assistant","content":[{"type":"tool_use","id":"toolu_01","name":"Read","input":{}}]},
			{"role":"user","content":[
				{"type":"tool_result","tool_use_id":"toolu_01","content":"ok"}
			]}
		]
	}`)

	out := ApplyPromptRelocation(body, cfg, 0)

	msgs := gjson.GetBytes(out, "messages").Array()
	if len(msgs) != 3 {
		t.Fatalf("expected 3 messages (synthetic + original 2), got %d", len(msgs))
	}
	if !strings.Contains(msgs[0].Get("content.0.text").String(), "The following skills are available") {
		t.Fatalf("synthetic message missing skills reminder: %s", msgs[0].Raw)
	}
	if msgs[2].Get("content.0.type").String() != "tool_result" {
		t.Fatalf("tool_result in original user message must remain untouched: %s", msgs[2].Raw)
	}
}

func TestApplyPromptRelocation_SyntheticUserMessageStructure(t *testing.T) {
	cfg := &config.PromptRelocationConfig{Enabled: true, ExtractSkills: true, ExtractProjectInstructions: true}
	body := []byte(`{
		"system":[
			{"type":"text","text":"You are Claude Code.\n<available_skills><skill><name>bit-cli</name></skill></available_skills>\nInstructions from: /path/AGENTS.md\n# Repo\nFollow conventions."},
			{"type":"text","text":"User instruction."}
		],
		"messages":[
			{"role":"assistant","content":[{"type":"text","text":"done"}]},
			{"role":"user","content":"What next?"}
		]
	}`)

	out := ApplyPromptRelocation(body, cfg, 0)

	msgs := gjson.GetBytes(out, "messages").Array()
	if len(msgs) != 3 {
		t.Fatalf("expected 3 messages (synthetic + original 2), got %d", len(msgs))
	}
	if msgs[0].Get("role").String() != "user" {
		t.Fatalf("synthetic message role = %q, want user", msgs[0].Get("role").String())
	}
	synthBlocks := msgs[0].Get("content").Array()
	if !strings.Contains(synthBlocks[0].Get("text").String(), "bit-cli") {
		t.Fatalf("synthetic content[0] missing skills: %s", synthBlocks[0].Raw)
	}
	if !strings.Contains(synthBlocks[1].Get("text").String(), "# claudeMd") {
		t.Fatalf("synthetic content[1] missing instructions: %s", synthBlocks[1].Raw)
	}
	if msgs[1].Get("role").String() != "assistant" {
		t.Fatalf("original assistant at index 1, got %q", msgs[1].Get("role").String())
	}
	if msgs[2].Get("content").String() != "What next?" {
		t.Fatalf("original user message at index 2 should be unchanged: %s", msgs[2].Raw)
	}
}

func TestApplyPromptRelocation_NonToolResultLeadingBlockUnchanged(t *testing.T) {
	cfg := &config.PromptRelocationConfig{Enabled: true, ExtractSkills: true}
	body := []byte(`{
		"system":[
			{"type":"text","text":"You are Claude Code.\n<available_skills><skill><name>bit-cli</name></skill></available_skills>"}
		],
		"messages":[
			{"role":"user","content":[{"type":"text","text":"Original first text"}]}
		]
	}`)

	out := ApplyPromptRelocation(body, cfg, 0)

	contentArr := gjson.GetBytes(out, "messages.0.content").Array()
	if !strings.Contains(contentArr[0].Get("text").String(), "The following skills are available") {
		t.Fatalf("skills reminder should be first when no tool_result leads, got: %s", contentArr[0].Raw)
	}
	if contentArr[len(contentArr)-1].Get("text").String() != "Original first text" {
		t.Fatalf("original text should remain last: %s", contentArr[len(contentArr)-1].Raw)
	}
}
