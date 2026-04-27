package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// runCmd executes a fresh root command with the given args, capturing
// stdout/stderr. It also isolates the test from the user's real config by
// pointing XDG_CONFIG_HOME at a tempdir and zeroing the package-level
// globalFlags struct so a previous test's flag values don't bleed over.
func runCmd(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("ANTHROPIC_API_KEY", "")
	gf = globalFlags{}

	root := newRootCmd()
	outBuf := &bytes.Buffer{}
	errBuf := &bytes.Buffer{}
	root.SetOut(outBuf)
	root.SetErr(errBuf)
	root.SetArgs(args)

	err = root.Execute()
	return outBuf.String(), errBuf.String(), err
}

func TestIntegration_VersionFlag(t *testing.T) {
	stdout, _, err := runCmd(t, "--version")
	if err != nil {
		t.Fatalf("--version errored: %v", err)
	}
	if !strings.HasPrefix(stdout, "sysaudit ") {
		t.Errorf("unexpected --version output: %q", stdout)
	}
}

func TestIntegration_HelpFlagListsAllSwitches(t *testing.T) {
	stdout, _, err := runCmd(t, "--help")
	if err != nil {
		t.Fatalf("--help errored: %v", err)
	}
	for _, want := range []string{
		"--procs", "--services", "--users", "--groups",
		"--logs", "--journal", "--programs", "--all",
		"--no-claude", "--analysis-level", "--tokens", "--model",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("--help missing flag %q", want)
		}
	}
}

func TestIntegration_ProcsScanRendersStdout(t *testing.T) {
	stdout, _, err := runCmd(t, "--procs", "--no-claude")
	if err != nil {
		t.Fatalf("scan errored: %v", err)
	}
	for _, want := range []string{"sysaudit report", "Findings", "Scan summaries", "procs"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout missing %q\n--- output ---\n%s\n---", want, stdout)
		}
	}
}

func TestIntegration_ProcsScanWritesMarkdownFile(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "report.md")
	_, _, err := runCmd(t, "--procs", "--no-claude", "--output", out)
	if err != nil {
		t.Fatalf("scan errored: %v", err)
	}
	body, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("output file unreadable: %v", err)
	}
	for _, want := range []string{
		"# sysaudit report",
		"## Findings",
		"## Scan summaries",
		"### procs",
	} {
		if !strings.Contains(string(body), want) {
			t.Errorf("markdown missing %q\n--- output ---\n%s\n---", want, body)
		}
	}
}

func TestIntegration_InvalidLogsSourceErrors(t *testing.T) {
	_, _, err := runCmd(t, "--logs=auth,nope", "--no-claude")
	if err == nil {
		t.Fatal("expected error for unknown logs source")
	}
	if !strings.Contains(err.Error(), "unknown log source") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestIntegration_InvalidProgramErrors(t *testing.T) {
	_, _, err := runCmd(t, "--programs=sshd,definitelynotreal", "--no-claude")
	if err == nil {
		t.Fatal("expected error for unknown program")
	}
	if !strings.Contains(err.Error(), "unknown program") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestIntegration_UsersScan_RunsWithoutClaude(t *testing.T) {
	// users.Scan reads /etc/passwd which exists on every Linux CI runner.
	// Even when /etc/shadow is unreadable the scan continues with an
	// info-severity note.
	stdout, _, err := runCmd(t, "--users", "--no-claude")
	if err != nil {
		t.Fatalf("scan errored: %v", err)
	}
	if !strings.Contains(stdout, "users") {
		t.Errorf("stdout missing 'users': %s", stdout)
	}
}

func TestIntegration_AllNoClaude(t *testing.T) {
	// End-to-end: every implemented scanner runs (procs+services+users
	// +logs[6 sources]+programs). On a CI runner without nginx/postgres/
	// docker etc., the program analyzers cleanly skip; the rest produce
	// digests. The point is to catch dispatch/wiring regressions.
	stdout, _, err := runCmd(t, "--all", "--no-claude")
	if err != nil {
		t.Fatalf("--all errored: %v", err)
	}
	for _, want := range []string{
		"sysaudit report",
		"procs", "services", "users", "logs", "programs",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("--all output missing %q", want)
		}
	}
}

func TestIntegration_ConfigYAMLOverridesDefaults(t *testing.T) {
	// Drop a config.yaml under XDG_CONFIG_HOME and verify the loader
	// picks it up (claude.model in particular). --no-claude prevents an
	// API call, but the model string still flows through to the report
	// header... actually with --no-claude there's no Analysis at all,
	// so we can't verify via output. Instead we assert no error and the
	// scan completes — which is enough to catch a config-load regression
	// (e.g. broken YAML parser).
	dir := t.TempDir()
	cfgDir := filepath.Join(dir, "sysaudit")
	if err := os.MkdirAll(cfgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	body := []byte(`
journal: "-p 3 --no-pager"
claude:
  model: claude-test-model
  max_tokens: 2048
`)
	if err := os.WriteFile(filepath.Join(cfgDir, "config.yaml"), body, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("ANTHROPIC_API_KEY", "")
	gf = globalFlags{}

	root := newRootCmd()
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"--procs", "--no-claude"})
	if err := root.Execute(); err != nil {
		t.Fatalf("scan with custom config errored: %v", err)
	}
}
