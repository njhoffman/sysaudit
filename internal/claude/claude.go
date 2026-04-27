// Package claude wraps the Anthropic SDK to analyze sysaudit scan results.
package claude

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"

	"github.com/njhoffman/sysaudit/internal/scan"
)

// Options configures a Claude analysis call.
type Options struct {
	APIKey        string
	Model         string
	MaxTokens     int64
	AnalysisLevel string // summary | standard | deep
	Verbosity     string // low | normal | high
}

// Analysis is the structured response from Claude.
type Analysis struct {
	Text         string
	InputTokens  int64
	OutputTokens int64
	Model        string
}

// Client is a thin wrapper around anthropic.Client.
type Client struct {
	api  anthropic.Client
	opts Options
}

// New constructs a Client. APIKey may be empty; in that case the SDK falls
// back to the ANTHROPIC_API_KEY environment variable.
func New(opts Options) (*Client, error) {
	if opts.Model == "" {
		return nil, errors.New("claude: model is required")
	}
	if opts.MaxTokens <= 0 {
		return nil, errors.New("claude: max_tokens must be > 0")
	}
	var sdkOpts []option.RequestOption
	if opts.APIKey != "" {
		sdkOpts = append(sdkOpts, option.WithAPIKey(opts.APIKey))
	}
	api := anthropic.NewClient(sdkOpts...)
	return &Client{api: api, opts: opts}, nil
}

// Analyze sends the given scan results to Claude and returns a textual analysis.
func (c *Client) Analyze(ctx context.Context, results []*scan.Result) (*Analysis, error) {
	prompt, err := buildPrompt(results, c.opts.AnalysisLevel, c.opts.Verbosity)
	if err != nil {
		return nil, fmt.Errorf("build prompt: %w", err)
	}
	msg, err := c.api.Messages.New(ctx, anthropic.MessageNewParams{
		Model:     c.opts.Model,
		MaxTokens: c.opts.MaxTokens,
		System: []anthropic.TextBlockParam{
			{Text: systemPrompt(c.opts.AnalysisLevel)},
		},
		Messages: []anthropic.MessageParam{
			anthropic.NewUserMessage(anthropic.NewTextBlock(prompt)),
		},
	})
	if err != nil {
		return nil, fmt.Errorf("messages.new: %w", err)
	}
	out := &Analysis{
		Model:        msg.Model,
		InputTokens:  msg.Usage.InputTokens,
		OutputTokens: msg.Usage.OutputTokens,
	}
	var b strings.Builder
	for _, block := range msg.Content {
		if t := block.AsText(); t.Text != "" {
			b.WriteString(t.Text)
		}
	}
	out.Text = b.String()
	return out, nil
}

func systemPrompt(level string) string {
	base := "You are a Linux system auditor. You receive structured scan results from a Go program and produce a concise, actionable analysis. " +
		"Highlight real problems, propose concrete remediation, and ignore noise. Output well-structured markdown with headings, bullet lists, and short code blocks where useful."
	switch normalizeLevel(level) {
	case "summary":
		return base + " Keep the entire response under 300 words. Lead with a one-line verdict, then a short list of the most important findings."
	case "deep":
		return base + " Be thorough. For each significant finding, explain the likely cause, blast radius, and remediation steps. Cross-reference findings when they point at the same root cause."
	default:
		return base + " Be balanced: cover the important findings without padding. Aim for 400-700 words."
	}
}

func buildPrompt(results []*scan.Result, level, verbosity string) (string, error) {
	if len(results) == 0 {
		return "", errors.New("no scan results provided")
	}
	payload, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return "", err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Analyze the following sysaudit scan results.\n\n")
	fmt.Fprintf(&b, "Analysis level: %s\n", normalizeLevel(level))
	fmt.Fprintf(&b, "Response verbosity: %s\n\n", normalizeVerbosity(verbosity))
	fmt.Fprintf(&b, "Scans included: ")
	for i, r := range results {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(r.Kind)
	}
	b.WriteString("\n\n")
	b.WriteString("Scan payload (JSON):\n```json\n")
	b.Write(payload)
	b.WriteString("\n```\n")
	return b.String(), nil
}

func normalizeLevel(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "summary", "brief", "short":
		return "summary"
	case "deep", "detailed", "thorough":
		return "deep"
	default:
		return "standard"
	}
}

func normalizeVerbosity(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "low", "quiet":
		return "low"
	case "high", "verbose":
		return "high"
	default:
		return "normal"
	}
}
