package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad_NoFile(t *testing.T) {
	// Point XDG at a directory we know is empty so config.yaml is absent.
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("ANTHROPIC_API_KEY", "")

	v := New()
	cfg, err := Load(v)
	if err != nil {
		t.Fatalf("Load with no file should not error, got: %v", err)
	}
	if cfg.Journal != DefaultJournalFlags {
		t.Errorf("default journal flags not applied: got %q want %q", cfg.Journal, DefaultJournalFlags)
	}
	if got, want := cfg.Claude.Model, DefaultModel; got != want {
		t.Errorf("default model: got %q want %q", got, want)
	}
	if cfg.Claude.MaxTokens != DefaultMaxTokens {
		t.Errorf("default max_tokens: got %d want %d", cfg.Claude.MaxTokens, DefaultMaxTokens)
	}
}

func TestLoad_FromYAML(t *testing.T) {
	dir := t.TempDir()
	cfgDir := filepath.Join(dir, "sysaudit")
	if err := os.MkdirAll(cfgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	yaml := []byte(`
journal: "-p 3 --no-pager"
logs:
  - auth
  - kern
claude:
  model: claude-sonnet-4-6
  max_tokens: 2048
  analysis_level: deep
`)
	if err := os.WriteFile(filepath.Join(cfgDir, "config.yaml"), yaml, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("ANTHROPIC_API_KEY", "")

	v := New()
	cfg, err := Load(v)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Journal != "-p 3 --no-pager" {
		t.Errorf("journal not loaded from YAML: %q", cfg.Journal)
	}
	if got := cfg.Logs; len(got) != 2 || got[0] != "auth" || got[1] != "kern" {
		t.Errorf("logs not loaded from YAML: %v", got)
	}
	if cfg.Claude.Model != "claude-sonnet-4-6" {
		t.Errorf("claude.model: got %q", cfg.Claude.Model)
	}
	if cfg.Claude.MaxTokens != 2048 {
		t.Errorf("claude.max_tokens: got %d", cfg.Claude.MaxTokens)
	}
	if cfg.Claude.AnalysisLevel != "deep" {
		t.Errorf("claude.analysis_level: got %q", cfg.Claude.AnalysisLevel)
	}
}

func TestLoad_EnvAPIKeyFallback(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("ANTHROPIC_API_KEY", "sk-test-123")

	v := New()
	cfg, err := Load(v)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Claude.APIKey != "sk-test-123" {
		t.Errorf("expected APIKey from env, got %q", cfg.Claude.APIKey)
	}
}

func TestLoad_YAMLAPIKeyOverridesEnv(t *testing.T) {
	dir := t.TempDir()
	cfgDir := filepath.Join(dir, "sysaudit")
	if err := os.MkdirAll(cfgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfgDir, "config.yaml"),
		[]byte("claude:\n  api_key: from-yaml\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("ANTHROPIC_API_KEY", "from-env")

	v := New()
	cfg, err := Load(v)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Claude.APIKey != "from-yaml" {
		t.Errorf("expected YAML to win over env, got %q", cfg.Claude.APIKey)
	}
}

func TestPath(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	p, err := Path()
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(dir, "sysaudit", "config.yaml")
	if p != want {
		t.Errorf("Path(): got %q want %q", p, want)
	}
}
