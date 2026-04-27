// Package services scans systemd unit files and active services and produces
// a digest plus derived findings.
package services

import (
	"bufio"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Unit is one row from `systemctl list-units --type=service --output=json`.
type Unit struct {
	Name        string `json:"unit"`
	Load        string `json:"load"`
	Active      string `json:"active"`
	Sub         string `json:"sub"`
	Description string `json:"description"`
}

// Properties is the parsed key=value output from `systemctl show <unit>`.
type Properties struct {
	Type          string
	LoadState     string
	ActiveState   string
	SubState      string
	Restart       string
	NRestarts     int
	Result        string
	UnitFileState string
	FragmentPath  string
	Description   string

	// Raw holds every property line so callers can inspect rare fields
	// without us having to enumerate them all.
	Raw map[string]string
}

// Scope identifies a systemd bus.
type Scope string

const (
	ScopeSystem Scope = "system"
	ScopeUser   Scope = "user"
)

// ansiPattern strips ANSI color escape codes that some user environments
// inject into systemctl output even with NO_COLOR/SYSTEMD_COLORS.
var ansiPattern = regexp.MustCompile(`\x1b\[[0-9;]*[A-Za-z]`)

// stripANSI removes ANSI color codes from b.
func stripANSI(b []byte) []byte {
	return ansiPattern.ReplaceAll(b, nil)
}

// parseUnits decodes the JSON array emitted by `systemctl list-units`.
func parseUnits(raw []byte) ([]Unit, error) {
	clean := stripANSI(raw)
	clean = []byte(strings.TrimSpace(string(clean)))
	if len(clean) == 0 {
		return nil, nil
	}
	var out []Unit
	if err := json.Unmarshal(clean, &out); err != nil {
		return nil, fmt.Errorf("parse list-units json: %w", err)
	}
	return out, nil
}

// parseShow decodes the key=value output of `systemctl show <unit>`.
func parseShow(raw []byte) Properties {
	props := Properties{Raw: map[string]string{}}
	scanner := bufio.NewScanner(strings.NewReader(string(stripANSI(raw))))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		eq := strings.IndexByte(line, '=')
		if eq <= 0 {
			continue
		}
		k, v := line[:eq], line[eq+1:]
		props.Raw[k] = v
		switch k {
		case "Type":
			props.Type = v
		case "LoadState":
			props.LoadState = v
		case "ActiveState":
			props.ActiveState = v
		case "SubState":
			props.SubState = v
		case "Restart":
			props.Restart = v
		case "NRestarts":
			n, _ := strconv.Atoi(v)
			props.NRestarts = n
		case "Result":
			props.Result = v
		case "UnitFileState":
			props.UnitFileState = v
		case "FragmentPath":
			props.FragmentPath = v
		case "Description":
			props.Description = v
		}
	}
	return props
}

// ShowProperties is the list of properties we ask `systemctl show` for.
// Keeping it short keeps the output volume bounded for hundreds of units.
var ShowProperties = []string{
	"Type",
	"LoadState",
	"ActiveState",
	"SubState",
	"Restart",
	"NRestarts",
	"Result",
	"UnitFileState",
	"FragmentPath",
	"Description",
}
