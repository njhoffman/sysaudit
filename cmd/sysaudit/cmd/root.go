// Package cmd wires the cobra CLI for sysaudit.
package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/njhoffman/sysaudit/internal/claude"
	"github.com/njhoffman/sysaudit/internal/config"
	xlog "github.com/njhoffman/sysaudit/internal/log"
	"github.com/njhoffman/sysaudit/internal/report"
	"github.com/njhoffman/sysaudit/internal/scan"
	"github.com/njhoffman/sysaudit/internal/scan/logs"
	"github.com/njhoffman/sysaudit/internal/scan/procs"
	"github.com/njhoffman/sysaudit/internal/scan/services"
	"github.com/njhoffman/sysaudit/internal/scan/users"
	"github.com/njhoffman/sysaudit/internal/version"
)

type globalFlags struct {
	verbose bool
	debug   bool
	quiet   bool
	output  string

	// Claude
	tokens          int
	model           string
	analysisLevel   string
	claudeVerbosity string
	skipClaude      bool

	// subcommand switches
	procs    bool
	services bool
	users    bool
	groups   bool
	logs     []string
	journal  string
	programs []string
	all      bool
}

var gf globalFlags

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "sysaudit",
		Short:         "Scan a Linux system for errors and misconfigurations and analyze with Claude.",
		Long:          "sysaudit scans processes, services, users/groups, and logs, summarizes the findings, sends the summary to Claude for analysis, and writes a report (colorful on stdout, markdown when --output is set).",
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       version.String(),
		RunE:          runRoot,
	}
	root.SetVersionTemplate("sysaudit " + version.String() + "\n")

	pf := root.PersistentFlags()
	pf.BoolVarP(&gf.verbose, "verbose", "v", false, "Increase log verbosity")
	pf.BoolVarP(&gf.debug, "debug", "d", false, "Enable debug logging")
	pf.BoolVarP(&gf.quiet, "quiet", "q", false, "Suppress non-error output")
	pf.StringVarP(&gf.output, "output", "o", "", "Write the report to FILE as markdown (default: colorful stdout)")

	// Claude options
	pf.IntVarP(&gf.tokens, "tokens", "t", config.DefaultMaxTokens, "Maximum tokens for Claude analysis")
	pf.StringVarP(&gf.model, "model", "m", config.DefaultModel, "Claude model to use")
	pf.StringVarP(&gf.analysisLevel, "analysis-level", "A", config.DefaultAnalysisLevel, "Claude analysis depth: summary|standard|deep")
	pf.StringVar(&gf.claudeVerbosity, "claude-verbosity", config.DefaultVerbosity, "Claude response verbosity: low|normal|high")
	pf.BoolVar(&gf.skipClaude, "no-claude", false, "Skip Claude analysis; report scan results only")

	// Subcommand switches (flags on root, per spec)
	pf.BoolVarP(&gf.procs, "procs", "p", false, "Scan running processes")
	pf.BoolVarP(&gf.services, "services", "s", false, "Scan running user and system services")
	pf.BoolVarP(&gf.users, "users", "u", false, "Scan users")
	pf.BoolVarP(&gf.groups, "groups", "g", false, "Scan groups")
	pf.StringSliceVarP(&gf.logs, "logs", "L", nil, "Logs to scan (comma-separated): auth,boot,journal,dmesg,kern,misc")
	pf.StringVarP(&gf.journal, "journal", "j", config.DefaultJournalFlags, "Pass-through flags for journalctl")
	pf.StringSliceVarP(&gf.programs, "programs", "P", nil, "Program-specific configurations to analyze (not yet implemented)")
	pf.BoolVarP(&gf.all, "all", "a", false, "Scan everything")

	root.PersistentFlags().Lookup("logs").NoOptDefVal = strings.Join(config.DefaultLogs, ",")

	return root
}

// Execute is the package entrypoint.
func Execute() error {
	root := newRootCmd()
	return root.Execute()
}

func runRoot(cmd *cobra.Command, _ []string) error {
	v := config.New()
	bindFlags(cmd, v)
	cfg, err := config.Load(v)
	if err != nil {
		return err
	}
	mergeFlagsIntoConfig(cmd, cfg)

	logger := xlog.New(xlog.Options{
		Level: xlog.LevelFromFlags(cfg.Verbose, cfg.Debug, cfg.Quiet),
	})

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	scanKinds := selectScans(gf)
	logger.Debug("selected scans", "kinds", scanKinds)

	results := []*scan.Result{}
	skipped := []string{}
	for _, kind := range scanKinds {
		switch kind {
		case "procs":
			logger.Info("scanning processes")
			res, err := procs.Scan(ctx, procs.DefaultOptions())
			if err != nil {
				return fmt.Errorf("procs scan: %w", err)
			}
			results = append(results, res)
		case "services":
			logger.Info("scanning services")
			res, err := services.Scan(ctx, services.DefaultOptions())
			if err != nil {
				return fmt.Errorf("services scan: %w", err)
			}
			results = append(results, res)
		case "users":
			logger.Info("scanning users and groups")
			res, err := users.Scan(ctx, users.DefaultOptions())
			if err != nil {
				return fmt.Errorf("users scan: %w", err)
			}
			results = append(results, res)
		case "logs":
			sources, perr := logs.ParseSources(cfg.Logs)
			if perr != nil {
				return fmt.Errorf("--logs: %w", perr)
			}
			logOpts := logs.DefaultOptions()
			switch {
			case len(sources) > 0:
				logOpts.Sources = sources
			case gf.all:
				// --all without an explicit --logs scans every source.
				logOpts.Sources = logs.AllSources
			}
			if cfg.Journal != "" {
				logOpts.JournalArgs = cfg.Journal
			}
			logger.Info("scanning logs", "sources", logOpts.Sources)
			res, err := logs.Scan(ctx, logOpts)
			if err != nil {
				return fmt.Errorf("logs scan: %w", err)
			}
			results = append(results, res)
		default:
			logger.Warn("scan not yet implemented", "kind", kind)
			skipped = append(skipped, kind)
		}
	}
	if len(results) == 0 {
		return fmt.Errorf("no scans implemented for selection: %v", scanKinds)
	}

	var analysis *claude.Analysis
	if !gf.skipClaude {
		if cfg.Claude.APIKey == "" {
			logger.Warn("no Claude API key (set ANTHROPIC_API_KEY or claude.api_key); skipping analysis")
		} else {
			logger.Info("running Claude analysis", "model", cfg.Claude.Model)
			cli, err := claude.New(claude.Options{
				APIKey:        cfg.Claude.APIKey,
				Model:         cfg.Claude.Model,
				MaxTokens:     int64(cfg.Claude.MaxTokens),
				AnalysisLevel: cfg.Claude.AnalysisLevel,
				Verbosity:     cfg.Claude.Verbosity,
			})
			if err != nil {
				return fmt.Errorf("claude client: %w", err)
			}
			analysis, err = cli.Analyze(ctx, results)
			if err != nil {
				return fmt.Errorf("claude analyze: %w", err)
			}
		}
	}

	host, _ := os.Hostname()
	rep := &report.Report{
		GeneratedAt: time.Now(),
		Hostname:    host,
		Results:     results,
		Analysis:    analysis,
	}

	if cfg.Output != "" {
		f, err := os.Create(cfg.Output)
		if err != nil {
			return fmt.Errorf("create output file: %w", err)
		}
		werr := report.WriteMarkdown(f, rep)
		cerr := f.Close()
		if werr != nil {
			return fmt.Errorf("write markdown: %w", werr)
		}
		if cerr != nil {
			return fmt.Errorf("close output: %w", cerr)
		}
		logger.Info("wrote report", "path", cfg.Output)
	} else {
		if err := report.WriteStdout(os.Stdout, rep); err != nil {
			return fmt.Errorf("write stdout report: %w", err)
		}
	}

	if len(skipped) > 0 {
		logger.Warn("some scans were skipped (not yet implemented)", "kinds", skipped)
	}
	return nil
}

// selectScans returns the ordered list of scan kinds to attempt, derived from
// the spec: --all wins; otherwise the union of explicit switches; otherwise
// the default (procs + services). Note: "users" covers both --users and
// --groups (one scanner reads both files), so --all does not list "groups"
// separately — that would cause a phantom "not yet implemented" warning.
func selectScans(gf globalFlags) []string {
	if gf.all {
		return []string{"procs", "services", "users", "logs", "programs"}
	}
	kinds := []string{}
	if gf.procs {
		kinds = append(kinds, "procs")
	}
	if gf.services {
		kinds = append(kinds, "services")
	}
	if gf.users || gf.groups {
		kinds = append(kinds, "users")
	}
	if len(gf.logs) > 0 {
		kinds = append(kinds, "logs")
	}
	if len(gf.programs) > 0 {
		kinds = append(kinds, "programs")
	}
	if len(kinds) == 0 {
		kinds = []string{"procs", "services"}
	}
	return kinds
}

// bindFlags wires cobra flags into viper so config + flag merging is consistent.
func bindFlags(cmd *cobra.Command, v *viper.Viper) {
	must := func(err error) {
		if err != nil {
			panic(err)
		}
	}
	must(v.BindPFlag("verbose", cmd.Flag("verbose")))
	must(v.BindPFlag("debug", cmd.Flag("debug")))
	must(v.BindPFlag("quiet", cmd.Flag("quiet")))
	must(v.BindPFlag("output", cmd.Flag("output")))
	must(v.BindPFlag("journal", cmd.Flag("journal")))
	must(v.BindPFlag("logs", cmd.Flag("logs")))
	must(v.BindPFlag("claude.max_tokens", cmd.Flag("tokens")))
	must(v.BindPFlag("claude.model", cmd.Flag("model")))
	must(v.BindPFlag("claude.analysis_level", cmd.Flag("analysis-level")))
	must(v.BindPFlag("claude.verbosity", cmd.Flag("claude-verbosity")))
}

// mergeFlagsIntoConfig overrides config fields with CLI flag values when the
// flag was set, so CLI flags take precedence over the YAML file.
func mergeFlagsIntoConfig(cmd *cobra.Command, cfg *config.Config) {
	if cmd.Flag("verbose").Changed {
		cfg.Verbose = gf.verbose
	}
	if cmd.Flag("debug").Changed {
		cfg.Debug = gf.debug
	}
	if cmd.Flag("quiet").Changed {
		cfg.Quiet = gf.quiet
	}
	if cmd.Flag("output").Changed {
		cfg.Output = gf.output
	}
	if cmd.Flag("journal").Changed {
		cfg.Journal = gf.journal
	}
	if cmd.Flag("logs").Changed {
		cfg.Logs = gf.logs
	}
	if cmd.Flag("tokens").Changed {
		cfg.Claude.MaxTokens = gf.tokens
	}
	if cmd.Flag("model").Changed {
		cfg.Claude.Model = gf.model
	}
	if cmd.Flag("analysis-level").Changed {
		cfg.Claude.AnalysisLevel = gf.analysisLevel
	}
	if cmd.Flag("claude-verbosity").Changed {
		cfg.Claude.Verbosity = gf.claudeVerbosity
	}
}
