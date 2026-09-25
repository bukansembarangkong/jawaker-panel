// Package copilot: LLM provider configuration and HTTP calling (PRD §28).
//
// Supports any OpenAI-compatible endpoint (OpenAI, Ollama, LM Studio, Gemini via proxy),
// the native Gemini REST API, and the Ollama REST API. Falls back to the rule-based
// advisor when no provider is configured or the call fails.
package copilot

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// ProviderType enumerates supported LLM providers.
type ProviderType string

const (
	ProviderOpenAICompat ProviderType = "openai_compatible" // OpenAI, any compatible endpoint, Ollama
	ProviderGemini       ProviderType = "gemini"            // Google Gemini REST API
)

// ProviderConfig holds the runtime LLM provider configuration.
// Stored in DB via copilot.Store or loaded from env on startup.
type ProviderConfig struct {
	Type     ProviderType `json:"type"`
	Endpoint string       `json:"endpoint"` // e.g. https://api.openai.com/v1
	APIKey   string       `json:"-"`        // never serialized in responses
	Model    string       `json:"model"`    // e.g. gpt-4o, gemini-1.5-pro, llama3
}

// RedactedCopy returns the config with APIKey replaced by a redacted marker.
func (c ProviderConfig) RedactedCopy() ProviderConfig {
	r := c
	if r.APIKey != "" {
		r.APIKey = "redacted"
	}
	return r
}

// LLMClient calls the configured LLM provider.
type LLMClient struct {
	cfg    ProviderConfig
	client *http.Client
}

// NewLLMClient builds a client from the given config.
func NewLLMClient(cfg ProviderConfig) *LLMClient {
	return &LLMClient{
		cfg:    cfg,
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

// Complete sends a single-turn prompt and returns the text completion.
func (c *LLMClient) Complete(ctx context.Context, systemPrompt, userMsg string) (string, error) {
	switch c.cfg.Type {
	case ProviderGemini:
		return c.geminiComplete(ctx, systemPrompt, userMsg)
	default: // openai_compatible (also works for Ollama)
		return c.openAIComplete(ctx, systemPrompt, userMsg)
	}
}

// ── OpenAI-compatible ─────────────────────────────────────────────────────────

type oaiMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type oaiRequest struct {
	Model    string       `json:"model"`
	Messages []oaiMessage `json:"messages"`
}

type oaiResponse struct {
	Choices []struct {
		Message oaiMessage `json:"message"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

func (c *LLMClient) openAIComplete(ctx context.Context, system, user string) (string, error) {
	endpoint := strings.TrimRight(c.cfg.Endpoint, "/")
	if endpoint == "" {
		endpoint = "https://api.openai.com/v1"
	}
	model := c.cfg.Model
	if model == "" {
		model = "gpt-4o"
	}

	body, _ := json.Marshal(oaiRequest{
		Model: model,
		Messages: []oaiMessage{
			{Role: "system", Content: system},
			{Role: "user", Content: user},
		},
	})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("copilot: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.cfg.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.cfg.APIKey)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("copilot: llm call: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))

	var out oaiResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", fmt.Errorf("copilot: decode response: %w", err)
	}
	if out.Error != nil {
		return "", fmt.Errorf("copilot: provider error: %s", out.Error.Message)
	}
	if len(out.Choices) == 0 {
		return "", fmt.Errorf("copilot: no choices in response")
	}
	return out.Choices[0].Message.Content, nil
}

// ── Gemini ────────────────────────────────────────────────────────────────────

type geminiPart struct {
	Text string `json:"text"`
}

type geminiContent struct {
	Role  string       `json:"role"`
	Parts []geminiPart `json:"parts"`
}

type geminiRequest struct {
	Contents []geminiContent `json:"contents"`
}

type geminiResponse struct {
	Candidates []struct {
		Content struct {
			Parts []geminiPart `json:"parts"`
		} `json:"content"`
	} `json:"candidates"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

func (c *LLMClient) geminiComplete(ctx context.Context, system, user string) (string, error) {
	model := c.cfg.Model
	if model == "" {
		model = "gemini-1.5-flash"
	}
	endpoint := c.cfg.Endpoint
	if endpoint == "" {
		endpoint = "https://generativelanguage.googleapis.com/v1beta"
	}
	url := fmt.Sprintf("%s/models/%s:generateContent?key=%s", strings.TrimRight(endpoint, "/"), model, c.cfg.APIKey)

	body, _ := json.Marshal(geminiRequest{
		Contents: []geminiContent{
			{Role: "user", Parts: []geminiPart{{Text: system + "\n\n" + user}}},
		},
	})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("copilot: build gemini request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("copilot: gemini call: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))

	var out geminiResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", fmt.Errorf("copilot: decode gemini response: %w", err)
	}
	if out.Error != nil {
		return "", fmt.Errorf("copilot: gemini error: %s", out.Error.Message)
	}
	if len(out.Candidates) == 0 || len(out.Candidates[0].Content.Parts) == 0 {
		return "", fmt.Errorf("copilot: empty gemini response")
	}
	return out.Candidates[0].Content.Parts[0].Text, nil
}
