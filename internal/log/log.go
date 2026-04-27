package log

import (
	"io"
	"os"

	clog "github.com/charmbracelet/log"
)

type Level int

const (
	LevelInfo Level = iota
	LevelVerbose
	LevelDebug
	LevelQuiet
)

type Options struct {
	Level Level
	Out   io.Writer
}

func New(opts Options) *clog.Logger {
	out := opts.Out
	if out == nil {
		out = os.Stderr
	}
	logger := clog.NewWithOptions(out, clog.Options{
		ReportTimestamp: false,
		ReportCaller:    opts.Level == LevelDebug,
	})
	switch opts.Level {
	case LevelQuiet:
		logger.SetLevel(clog.ErrorLevel)
	case LevelDebug:
		logger.SetLevel(clog.DebugLevel)
	case LevelVerbose:
		logger.SetLevel(clog.InfoLevel)
	default:
		logger.SetLevel(clog.WarnLevel)
	}
	return logger
}

// LevelFromFlags resolves a Level given the global verbosity flags.
// Precedence (highest wins): debug > verbose > quiet.
func LevelFromFlags(verbose, debug, quiet bool) Level {
	switch {
	case debug:
		return LevelDebug
	case verbose:
		return LevelVerbose
	case quiet:
		return LevelQuiet
	default:
		return LevelInfo
	}
}
