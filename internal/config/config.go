package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/viper"
)

// Config is the merged view of YAML config + CLI flags.
type Config struct {
	Verbose bool   `mapstructure:"verbose"`
	Debug   bool   `mapstructure:"debug"`
	Quiet   bool   `mapstructure:"quiet"`
	Output  string `mapstructure:"output"`

	Journal string   `mapstructure:"journal"`
	Logs    []string `mapstructure:"logs"`

	Claude ClaudeConfig `mapstructure:"claude"`
}

type ClaudeConfig struct {
	APIKey        string `mapstructure:"api_key"`
	Model         string `mapstructure:"model"`
	MaxTokens     int    `mapstructure:"max_tokens"`
	AnalysisLevel string `mapstructure:"analysis_level"`
	Verbosity     string `mapstructure:"verbosity"`
}

const (
	DefaultJournalFlags = "-p 4 -b -n 500 --no-pager"
	DefaultModel        = "claude-opus-4-7"
	DefaultMaxTokens    = 4096
)

var (
	DefaultLogs          = []string{"boot", "dmesg", "journal"}
	DefaultAnalysisLevel = "standard"
	DefaultVerbosity     = "normal"
)

// New returns a viper instance preconfigured with sysaudit defaults and
// search paths. Callers bind their cobra flags onto it before calling Load.
func New() *viper.Viper {
	v := viper.New()
	v.SetConfigName("config")
	v.SetConfigType("yaml")
	if dir, err := configDir(); err == nil {
		v.AddConfigPath(dir)
	}
	v.SetEnvPrefix("SYSAUDIT")
	v.AutomaticEnv()

	v.SetDefault("journal", DefaultJournalFlags)
	// Note: no SetDefault for "logs". cfg.Logs being empty is meaningful —
	// it means the user did not request a logs scan. The cobra --logs flag
	// has its own NoOptDefVal so `--logs` (with no value) resolves to
	// DefaultLogs without bleeding the default into config.
	v.SetDefault("claude.model", DefaultModel)
	v.SetDefault("claude.max_tokens", DefaultMaxTokens)
	v.SetDefault("claude.analysis_level", DefaultAnalysisLevel)
	v.SetDefault("claude.verbosity", DefaultVerbosity)

	return v
}

// Load reads the config file (if present) and unmarshals into a Config.
// A missing config file is not an error; only parse errors are.
func Load(v *viper.Viper) (*Config, error) {
	if err := v.ReadInConfig(); err != nil {
		var notFound viper.ConfigFileNotFoundError
		if !errors.As(err, &notFound) {
			return nil, fmt.Errorf("read config: %w", err)
		}
	}
	if key := os.Getenv("ANTHROPIC_API_KEY"); key != "" && v.GetString("claude.api_key") == "" {
		v.Set("claude.api_key", key)
	}
	cfg := &Config{}
	if err := v.Unmarshal(cfg); err != nil {
		return nil, fmt.Errorf("unmarshal config: %w", err)
	}
	return cfg, nil
}

// Path returns the config file path that would be used (whether or not it exists).
func Path() (string, error) {
	dir, err := configDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "config.yaml"), nil
}

func configDir() (string, error) {
	xdg := os.Getenv("XDG_CONFIG_HOME")
	if xdg != "" {
		return filepath.Join(xdg, "sysaudit"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "sysaudit"), nil
}
