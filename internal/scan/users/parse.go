// Package users scans /etc/passwd, /etc/group, and /etc/shadow and produces
// a digest plus derived findings.
package users

import (
	"bufio"
	"io"
	"strconv"
	"strings"
)

// PasswdEntry is one line from /etc/passwd.
type PasswdEntry struct {
	Name      string
	UID       int
	GID       int
	GECOS     string
	Home      string
	Shell     string
	HasShadow bool   // password field is "x"
	RawPwd    string // raw password field (for noting "*"/"!" special markers)
}

// GroupEntry is one line from /etc/group.
type GroupEntry struct {
	Name    string
	GID     int
	Members []string
}

// ShadowEntry is one line from /etc/shadow.
type ShadowEntry struct {
	Name       string
	HashField  string // password hash, or "" / "*" / "!" / "!!"
	LastChange int    // days since epoch; -1 if unset
	MinAge     int
	MaxAge     int
	WarnDays   int
	InactDays  int
	ExpireDays int
}

// ParsePasswd parses /etc/passwd format. Malformed lines are skipped.
func ParsePasswd(r io.Reader) []PasswdEntry {
	out := []PasswdEntry{}
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, ":", 7)
		if len(parts) < 7 {
			continue
		}
		uid, err1 := strconv.Atoi(parts[2])
		gid, err2 := strconv.Atoi(parts[3])
		if err1 != nil || err2 != nil {
			continue
		}
		out = append(out, PasswdEntry{
			Name:      parts[0],
			RawPwd:    parts[1],
			UID:       uid,
			GID:       gid,
			GECOS:     parts[4],
			Home:      parts[5],
			Shell:     parts[6],
			HasShadow: parts[1] == "x",
		})
	}
	return out
}

// ParseGroup parses /etc/group format.
func ParseGroup(r io.Reader) []GroupEntry {
	out := []GroupEntry{}
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, ":", 4)
		if len(parts) < 4 {
			continue
		}
		gid, err := strconv.Atoi(parts[2])
		if err != nil {
			continue
		}
		members := []string{}
		if parts[3] != "" {
			for _, m := range strings.Split(parts[3], ",") {
				m = strings.TrimSpace(m)
				if m != "" {
					members = append(members, m)
				}
			}
		}
		out = append(out, GroupEntry{Name: parts[0], GID: gid, Members: members})
	}
	return out
}

// ParseShadow parses /etc/shadow format. Numeric fields tolerate empty
// columns by mapping them to -1.
func ParseShadow(r io.Reader) []ShadowEntry {
	out := []ShadowEntry{}
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, ":", 9)
		if len(parts) < 8 {
			continue
		}
		out = append(out, ShadowEntry{
			Name:       parts[0],
			HashField:  parts[1],
			LastChange: atoiOrNeg(parts[2]),
			MinAge:     atoiOrNeg(parts[3]),
			MaxAge:     atoiOrNeg(parts[4]),
			WarnDays:   atoiOrNeg(parts[5]),
			InactDays:  atoiOrNeg(parts[6]),
			ExpireDays: atoiOrNeg(parts[7]),
		})
	}
	return out
}

func atoiOrNeg(s string) int {
	if s == "" {
		return -1
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return -1
	}
	return n
}

// Standard paths we check for mode/owner anomalies.
const (
	PathPasswd = "/etc/passwd"
	PathShadow = "/etc/shadow"
	PathGroup  = "/etc/group"
)

// PrivilegedGroups are groups whose membership confers significant ability
// to escalate or otherwise impact the system. The list is conservative;
// distros vary.
var PrivilegedGroups = []string{"sudo", "wheel", "root", "adm", "docker", "lxd", "kvm", "disk"}

// SystemAccountUIDMax is the largest UID that systems traditionally reserve
// for system/service accounts. Login on these accounts is generally not
// expected.
const SystemAccountUIDMax = 999

// LoginShells are program paths that grant interactive shell access. Used
// to flag system accounts that have one.
var LoginShells = map[string]bool{
	"/bin/sh":       true,
	"/bin/bash":     true,
	"/bin/dash":     true,
	"/bin/zsh":      true,
	"/bin/fish":     true,
	"/usr/bin/sh":   true,
	"/usr/bin/bash": true,
	"/usr/bin/dash": true,
	"/usr/bin/zsh":  true,
	"/usr/bin/fish": true,
}
