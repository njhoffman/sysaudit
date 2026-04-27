// Package report renders scan results + Claude analysis to either colorful stdout
// or a markdown file.
package report

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/charmbracelet/glamour"
	"github.com/charmbracelet/lipgloss"

	"github.com/njhoffman/sysaudit/internal/claude"
	"github.com/njhoffman/sysaudit/internal/scan"
)

// Report bundles everything the renderers need.
type Report struct {
	GeneratedAt time.Time
	Hostname    string
	Results     []*scan.Result
	Analysis    *claude.Analysis
}

// WriteMarkdown writes the report as markdown to w. Suitable for files.
func WriteMarkdown(w io.Writer, r *Report) error {
	bw := newBufWriter(w)
	bw.printf("# sysaudit report\n\n")
	bw.printf("- **Host:** %s\n", r.Hostname)
	bw.printf("- **Generated:** %s\n", r.GeneratedAt.Format(time.RFC3339))
	if r.Analysis != nil {
		bw.printf("- **Model:** %s (%d in / %d out tokens)\n",
			r.Analysis.Model, r.Analysis.InputTokens, r.Analysis.OutputTokens)
	}
	bw.printf("\n")

	bw.printf("## Findings\n\n")
	all := allFindings(r.Results)
	if len(all) == 0 {
		bw.printf("_No findings._\n\n")
	} else {
		bw.printf("| Severity | Kind | Subject | Detail |\n")
		bw.printf("|---|---|---|---|\n")
		for _, f := range all {
			bw.printf("| %s | %s | %s | %s |\n",
				f.severity, f.kind, mdEscape(f.subject), mdEscape(f.detail))
		}
		bw.printf("\n")
	}

	bw.printf("## Scan summaries\n\n")
	for _, res := range r.Results {
		bw.printf("### %s\n\n", res.Kind)
		bw.printf("- duration: %s\n", res.FinishedAt.Sub(res.StartedAt))
		for _, line := range summaryLines(res) {
			bw.printf("- %s\n", line)
		}
		bw.printf("\n")
	}

	if r.Analysis != nil && r.Analysis.Text != "" {
		bw.printf("## Claude analysis\n\n")
		bw.printf("%s\n", strings.TrimSpace(r.Analysis.Text))
	}

	return bw.err
}

// WriteStdout renders a colorful TTY-friendly version of the report.
func WriteStdout(w io.Writer, r *Report) error {
	header := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("12"))
	subtle := lipgloss.NewStyle().Foreground(lipgloss.Color("244"))
	dim := lipgloss.NewStyle().Foreground(lipgloss.Color("245"))
	bold := lipgloss.NewStyle().Bold(true)

	bw := newBufWriter(w)
	bw.printf("%s\n", header.Render("sysaudit report"))
	bw.printf("%s\n", subtle.Render(fmt.Sprintf("host: %s   generated: %s",
		r.Hostname, r.GeneratedAt.Format(time.RFC3339))))
	if r.Analysis != nil {
		bw.printf("%s\n", subtle.Render(fmt.Sprintf("model: %s   tokens in/out: %d / %d",
			r.Analysis.Model, r.Analysis.InputTokens, r.Analysis.OutputTokens)))
	}
	bw.printf("\n")

	bw.printf("%s\n", header.Render("Findings"))
	all := allFindings(r.Results)
	if len(all) == 0 {
		bw.printf("%s\n", dim.Render("(none)"))
	} else {
		for _, f := range all {
			bw.printf("  %s %s %s\n",
				severityChip(f.severity),
				bold.Render(fmt.Sprintf("[%s]", f.kind)),
				f.subject)
			if f.detail != "" {
				bw.printf("%s\n", dim.Render("    "+f.detail))
			}
		}
	}
	bw.printf("\n")

	bw.printf("%s\n", header.Render("Scan summaries"))
	for _, res := range r.Results {
		bw.printf("%s\n", bold.Render("  "+res.Kind))
		bw.printf("%s\n", dim.Render(fmt.Sprintf("    duration: %s",
			res.FinishedAt.Sub(res.StartedAt))))
		for _, line := range summaryLines(res) {
			bw.printf("    %s\n", line)
		}
	}
	bw.printf("\n")

	if r.Analysis != nil && r.Analysis.Text != "" {
		bw.printf("%s\n", header.Render("Claude analysis"))
		rendered, err := renderMarkdownTTY(r.Analysis.Text)
		if err != nil {
			bw.printf("%s\n", r.Analysis.Text)
		} else {
			bw.printf("%s\n", rendered)
		}
	}
	return bw.err
}

func renderMarkdownTTY(md string) (string, error) {
	style := "auto"
	if _, ok := os.LookupEnv("NO_COLOR"); ok {
		style = "notty"
	}
	tr, err := glamour.NewTermRenderer(
		glamour.WithStandardStyle(style),
		glamour.WithWordWrap(0),
	)
	if err != nil {
		return "", err
	}
	return tr.Render(md)
}

type flatFinding struct {
	kind     string
	severity scan.Severity
	subject  string
	detail   string
}

func allFindings(rs []*scan.Result) []flatFinding {
	out := []flatFinding{}
	for _, r := range rs {
		for _, f := range r.Findings {
			out = append(out, flatFinding{
				kind: r.Kind, severity: f.Severity,
				subject: f.Subject, detail: f.Detail,
			})
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		return severityRank(out[i].severity) > severityRank(out[j].severity)
	})
	return out
}

func severityRank(s scan.Severity) int {
	switch s {
	case scan.SeverityCritical:
		return 5
	case scan.SeverityError:
		return 4
	case scan.SeverityWarning:
		return 3
	case scan.SeverityNotice:
		return 2
	case scan.SeverityInfo:
		return 1
	default:
		return 0
	}
}

func severityChip(s scan.Severity) string {
	color := "244"
	switch s {
	case scan.SeverityCritical:
		color = "9"
	case scan.SeverityError:
		color = "1"
	case scan.SeverityWarning:
		color = "3"
	case scan.SeverityNotice:
		color = "6"
	case scan.SeverityInfo:
		color = "4"
	}
	return lipgloss.NewStyle().
		Foreground(lipgloss.Color("0")).
		Background(lipgloss.Color(color)).
		Padding(0, 1).
		Render(strings.ToUpper(string(s)))
}

func summaryLines(r *scan.Result) []string {
	out := []string{}
	keys := make([]string, 0, len(r.Summary))
	for k := range r.Summary {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := r.Summary[k]
		out = append(out, fmt.Sprintf("%s: %s", k, summaryValue(v)))
	}
	return out
}

func summaryValue(v any) string {
	switch t := v.(type) {
	case nil:
		return "<nil>"
	case map[string]int:
		parts := []string{}
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			parts = append(parts, fmt.Sprintf("%s=%d", k, t[k]))
		}
		return strings.Join(parts, " ")
	case []any:
		return fmt.Sprintf("(%d items)", len(t))
	default:
		s := fmt.Sprintf("%v", v)
		if len(s) > 200 {
			return s[:200] + "..."
		}
		return s
	}
}

func mdEscape(s string) string {
	r := strings.NewReplacer("|", `\|`, "\n", " ", "\r", " ")
	return r.Replace(s)
}

type bufWriter struct {
	w   io.Writer
	err error
}

func newBufWriter(w io.Writer) *bufWriter { return &bufWriter{w: w} }

func (b *bufWriter) printf(format string, args ...any) {
	if b.err != nil {
		return
	}
	_, b.err = fmt.Fprintf(b.w, format, args...)
}
