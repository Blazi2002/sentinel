// Package reasoning turns a telemetry event into a remediation plan
// by querying a locally-hosted large language model.
//
// In development the model is served by Ollama on the local machine.
// In production the same role is filled by a vLLM server on the
// customer's GPU hardware. Only this client file is aware of which
// engine is used — the rest of the package is engine-agnostic.
package reasoning

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// defaultOllamaURL is where Ollama listens by default.
const defaultOllamaURL = "http://localhost:11434"

// OllamaClient talks to an Ollama server over HTTP.
type OllamaClient struct {
	baseURL string
	model   string
	http    *http.Client
}

// NewOllamaClient builds a client for the given model.
func NewOllamaClient(model string) *OllamaClient {
	return &OllamaClient{
		baseURL: defaultOllamaURL,
		model:   model,
		// LLM inference is slow; allow a generous timeout.
		http: &http.Client{Timeout: 120 * time.Second},
	}
}

// generateRequest is the JSON body sent to Ollama's /api/generate.
type generateRequest struct {
	Model  string `json:"model"`
	Prompt string `json:"prompt"`
	System string `json:"system,omitempty"`
	Stream bool   `json:"stream"`
	Format string `json:"format,omitempty"` // "json" forces valid JSON output
}

// generateResponse is the JSON body Ollama returns.
type generateResponse struct {
	Response string `json:"response"`
	Done     bool   `json:"done"`
}

// Generate sends a prompt to the model and returns its raw text answer.
// If forceJSON is true, the model is constrained to emit valid JSON.
func (c *OllamaClient) Generate(
	ctx context.Context, systemPrompt, userPrompt string, forceJSON bool,
) (string, error) {
	reqBody := generateRequest{
		Model:  c.model,
		Prompt: userPrompt,
		System: systemPrompt,
		Stream: false,
	}
	if forceJSON {
		reqBody.Format = "json"
	}

	payload, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("encoding request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.baseURL+"/api/generate", bytes.NewReader(payload))
	if err != nil {
		return "", fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("calling ollama: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("ollama returned status %d", resp.StatusCode)
	}

	var result generateResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("decoding response: %w", err)
	}
	return result.Response, nil
}

// Health checks that the Ollama server is reachable.
func (c *OllamaClient) Health(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		c.baseURL+"/api/tags", nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("ollama not reachable: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("ollama health check failed: status %d", resp.StatusCode)
	}
	return nil
}
