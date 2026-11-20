package agent

import (
	"os"
	"testing"

	"github.com/Autumn-27/norma/llm"
)

func TestProviderEnvIsFalsy(t *testing.T) {
	for _, tt := range []struct {
		input string
		want  bool
	}{
		{"0", true}, {"false", true}, {"off", true}, {"no", true},
		{" \tFaLsE\n", true},
		{"1", false}, {"true", false}, {"on", false}, {"yes", false},
		{"", false}, {" \t", false}, {"invalid", false},
	} {
		if got := isFalsy(tt.input); got != tt.want {
			t.Errorf("isFalsy(%q) = %t, want %t", tt.input, got, tt.want)
		}
	}
}

func TestProviderEnvFromEnv(t *testing.T) {
	for _, key := range []string{
		"ARTEX_LLM_PROVIDER", "ARTEX_LLM_MODEL", "ARTEX_LLM_BASE_URL",
		"ARTEX_LLM_PROXY", "ARTEX_LLM_STREAM", "ANTHROPIC_API_KEY", "OPENAI_API_KEY",
	} {
		t.Setenv(key, "")
		if err := os.Unsetenv(key); err != nil {
			t.Fatalf("unset %s: %v", key, err)
		}
	}

	for _, tt := range []struct {
		name string
		env  map[string]string
		want Config
		ok   bool
	}{
		{name: "unset without credentials"},
		{
			name: "infers Anthropic first when both keys are set",
			env:  map[string]string{"ANTHROPIC_API_KEY": "test-anthropic", "OPENAI_API_KEY": "test-openai"},
			want: Config{Format: llm.FormatAnthropic, APIKey: "test-anthropic", Model: "claude-opus-4-8", Stream: true},
			ok:   true,
		},
		{
			name: "infers OpenAI from its key",
			env:  map[string]string{"OPENAI_API_KEY": "test-openai"},
			want: Config{Format: llm.FormatOpenAI, APIKey: "test-openai", Model: "gpt-4o", Stream: true},
			ok:   true,
		},
		{
			name: "defaults Responses model",
			env:  map[string]string{"ARTEX_LLM_PROVIDER": "openai-responses", "OPENAI_API_KEY": "test-openai"},
			want: Config{Format: llm.FormatOpenAIResponses, APIKey: "test-openai", Model: "gpt-5", Stream: true},
			ok:   true,
		},
		{
			name: "explicit provider and overrides",
			env: map[string]string{
				"ARTEX_LLM_PROVIDER": "openai", "ARTEX_LLM_MODEL": "custom-model",
				"ARTEX_LLM_BASE_URL": "https://api.example.test/v1", "ARTEX_LLM_PROXY": "  socks5://proxy.example.test:1080  ",
				"ARTEX_LLM_STREAM": " OFF ", "OPENAI_API_KEY": "test-openai", "ANTHROPIC_API_KEY": "test-anthropic",
			},
			want: Config{
				Format: llm.FormatOpenAI, APIKey: "test-openai", Model: "custom-model",
				BaseURL: "https://api.example.test/v1", Proxy: "socks5://proxy.example.test:1080", Stream: false,
			},
			ok: true,
		},
		{
			name: "unknown provider and stream value use defaults",
			env: map[string]string{
				"ARTEX_LLM_PROVIDER": "unknown", "ARTEX_LLM_STREAM": "invalid",
				"ANTHROPIC_API_KEY": "test-anthropic", "OPENAI_API_KEY": "test-openai",
			},
			want: Config{Format: llm.FormatAnthropic, APIKey: "test-anthropic", Model: "claude-opus-4-8", Stream: true},
			ok:   true,
		},
		{
			name: "selected provider requires its own key",
			env:  map[string]string{"ARTEX_LLM_PROVIDER": "openai", "ANTHROPIC_API_KEY": "test-anthropic"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			for key, value := range tt.env {
				t.Setenv(key, value)
			}
			if got, ok := FromEnv(); got != tt.want || ok != tt.ok {
				t.Errorf("FromEnv() = (%+v, %t), want (%+v, %t)", got, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestProviderEnvCompactionWindow(t *testing.T) {
	for _, tt := range []struct {
		name string
		k    int
		want int
	}{
		{name: "zero config", want: 200_000},
		{name: "negative uses default", k: -1, want: 200_000},
		{name: "below minimum", k: 31, want: 32_000},
		{name: "at minimum", k: 32, want: 32_000},
		{name: "configured size in tokens", k: 128, want: 128_000},
		{name: "at maximum", k: 1000, want: 1_000_000},
		{name: "above maximum", k: 1001, want: 1_000_000},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := (Config{ContextWindowK: tt.k}).CompactionWindow(); got != tt.want {
				t.Errorf("CompactionWindow() with ContextWindowK=%d = %d, want %d", tt.k, got, tt.want)
			}
		})
	}
}
