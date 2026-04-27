package users

import (
	"fmt"
	"io/fs"
	"os"
	"sort"
	"strings"

	"github.com/njhoffman/sysaudit/internal/scan"
)

// expectedFileMode lists the conventional secure mode and owner/group
// for each scanned file. Anything looser triggers a finding.
type expectedFileMode struct {
	maxMode fs.FileMode // any bits beyond this set fire the rule
	owner   string
	group   string // empty means don't check group
}

var expectedModes = map[string]expectedFileMode{
	PathPasswd: {maxMode: 0o644, owner: "root", group: ""},
	PathGroup:  {maxMode: 0o644, owner: "root", group: ""},
	PathShadow: {maxMode: 0o640, owner: "root", group: "shadow"},
}

// DeriveFindings produces the full set of findings from parsed inputs. Any
// of pwd/grp/shd may be empty (e.g., shadow not readable); rules that need
// shadow are simply skipped in that case.
func DeriveFindings(pwd []PasswdEntry, grp []GroupEntry, shd []ShadowEntry, fileStats map[string]os.FileInfo, shadowReadable bool) []scan.Finding {
	out := []scan.Finding{}

	out = append(out, findUID0Extras(pwd)...)
	out = append(out, findUIDCollisions(pwd)...)
	out = append(out, findGIDCollisions(grp)...)
	out = append(out, findSystemAccountsWithLoginShell(pwd)...)
	out = append(out, findPrivilegedGroupMembership(pwd, grp)...)
	out = append(out, findFilePermAnomalies(fileStats)...)

	if shadowReadable {
		out = append(out, findShadowAnomalies(pwd, shd)...)
	} else {
		out = append(out, scan.Finding{
			Severity: scan.SeverityInfo,
			Subject:  "shadow not readable; password-hash checks were skipped",
			Detail:   "Run as root or as a member of group `shadow` to enable empty-hash and locked-but-shell checks.",
		})
	}

	sort.SliceStable(out, func(i, j int) bool {
		return severityRank(out[i].Severity) > severityRank(out[j].Severity)
	})
	return out
}

func findUID0Extras(pwd []PasswdEntry) []scan.Finding {
	out := []scan.Finding{}
	for _, e := range pwd {
		if e.UID == 0 && e.Name != "root" {
			out = append(out, scan.Finding{
				Severity: scan.SeverityCritical,
				Subject:  fmt.Sprintf("UID 0 user is not root: %s", e.Name),
				Detail:   fmt.Sprintf("home=%s shell=%s — additional UID-0 accounts are equivalent to root and a common backdoor pattern.", e.Home, e.Shell),
			})
		}
	}
	return out
}

func findUIDCollisions(pwd []PasswdEntry) []scan.Finding {
	out := []scan.Finding{}
	byUID := map[int][]string{}
	for _, e := range pwd {
		byUID[e.UID] = append(byUID[e.UID], e.Name)
	}
	uids := make([]int, 0, len(byUID))
	for uid := range byUID {
		uids = append(uids, uid)
	}
	sort.Ints(uids)
	for _, uid := range uids {
		names := byUID[uid]
		if len(names) > 1 {
			sev := scan.SeverityWarning
			if uid == 0 {
				sev = scan.SeverityCritical
			}
			out = append(out, scan.Finding{
				Severity: sev,
				Subject:  fmt.Sprintf("UID %d shared by %d users", uid, len(names)),
				Detail:   fmt.Sprintf("users: %s — UID collisions break audit attribution and can hide a backdoor.", strings.Join(names, ", ")),
			})
		}
	}
	return out
}

func findGIDCollisions(grp []GroupEntry) []scan.Finding {
	out := []scan.Finding{}
	byGID := map[int][]string{}
	for _, g := range grp {
		byGID[g.GID] = append(byGID[g.GID], g.Name)
	}
	gids := make([]int, 0, len(byGID))
	for gid := range byGID {
		gids = append(gids, gid)
	}
	sort.Ints(gids)
	for _, gid := range gids {
		names := byGID[gid]
		if len(names) > 1 {
			out = append(out, scan.Finding{
				Severity: scan.SeverityNotice,
				Subject:  fmt.Sprintf("GID %d shared by %d groups", gid, len(names)),
				Detail:   fmt.Sprintf("groups: %s", strings.Join(names, ", ")),
			})
		}
	}
	return out
}

func findSystemAccountsWithLoginShell(pwd []PasswdEntry) []scan.Finding {
	out := []scan.Finding{}
	for _, e := range pwd {
		if e.UID == 0 || e.UID > SystemAccountUIDMax {
			continue
		}
		if LoginShells[e.Shell] {
			out = append(out, scan.Finding{
				Severity: scan.SeverityWarning,
				Subject:  fmt.Sprintf("system account has login shell: %s (UID %d)", e.Name, e.UID),
				Detail:   fmt.Sprintf("shell=%s home=%s — service accounts should use /usr/sbin/nologin.", e.Shell, e.Home),
			})
		}
	}
	return out
}

func findPrivilegedGroupMembership(pwd []PasswdEntry, grp []GroupEntry) []scan.Finding {
	priv := map[string]bool{}
	for _, g := range PrivilegedGroups {
		priv[g] = true
	}
	primaryGID := map[string]int{}
	for _, p := range pwd {
		primaryGID[p.Name] = p.GID
	}
	gidToName := map[int]string{}
	for _, g := range grp {
		gidToName[g.GID] = g.Name
	}

	memberByGroup := map[string]map[string]bool{}
	for _, g := range grp {
		if !priv[g.Name] {
			continue
		}
		if memberByGroup[g.Name] == nil {
			memberByGroup[g.Name] = map[string]bool{}
		}
		for _, m := range g.Members {
			memberByGroup[g.Name][m] = true
		}
	}
	// users whose primary GID matches a privileged group are also members.
	for _, p := range pwd {
		gname, ok := gidToName[p.GID]
		if !ok || !priv[gname] {
			continue
		}
		if memberByGroup[gname] == nil {
			memberByGroup[gname] = map[string]bool{}
		}
		memberByGroup[gname][p.Name] = true
	}

	out := []scan.Finding{}
	groups := make([]string, 0, len(memberByGroup))
	for g := range memberByGroup {
		groups = append(groups, g)
	}
	sort.Strings(groups)
	for _, g := range groups {
		members := memberByGroup[g]
		if len(members) == 0 {
			continue
		}
		// Skip the tautological "root in group root" case; it's required
		// by convention and reporting it is just noise.
		if g == "root" && len(members) == 1 {
			if _, only := members["root"]; only {
				continue
			}
		}
		names := make([]string, 0, len(members))
		for n := range members {
			names = append(names, n)
		}
		sort.Strings(names)
		out = append(out, scan.Finding{
			Severity: scan.SeverityNotice,
			Subject:  fmt.Sprintf("members of privileged group %s: %s", g, strings.Join(names, ", ")),
			Detail:   fmt.Sprintf("Membership in %s confers privileges: review whether each account still needs it.", g),
		})
	}
	return out
}

func findShadowAnomalies(pwd []PasswdEntry, shd []ShadowEntry) []scan.Finding {
	out := []scan.Finding{}
	pwdByName := map[string]PasswdEntry{}
	for _, p := range pwd {
		pwdByName[p.Name] = p
	}
	for _, s := range shd {
		// Empty hash field with no lock marker is a passwordless account.
		if s.HashField == "" {
			out = append(out, scan.Finding{
				Severity: scan.SeverityCritical,
				Subject:  fmt.Sprintf("user has empty password hash: %s", s.Name),
				Detail:   "An empty hash field allows login with no password. Lock the account or set a password.",
			})
			continue
		}
		// Locked accounts (* / ! / !!) with login shells: can't log in via
		// password, but SSH key or sudo-from-other-user could still grant
		// access. Flag at notice level — common for service accounts and
		// not always wrong.
		if isLockedHash(s.HashField) {
			if p, ok := pwdByName[s.Name]; ok && LoginShells[p.Shell] {
				out = append(out, scan.Finding{
					Severity: scan.SeverityNotice,
					Subject:  fmt.Sprintf("locked password but login shell: %s", s.Name),
					Detail:   fmt.Sprintf("hash=%q shell=%s — verify that any SSH keys or sudoers entries for this user are intentional.", s.HashField, p.Shell),
				})
			}
		}
	}
	return out
}

func isLockedHash(h string) bool {
	switch h {
	case "*", "!", "!!", "*LK*":
		return true
	}
	return strings.HasPrefix(h, "!")
}

func findFilePermAnomalies(stats map[string]os.FileInfo) []scan.Finding {
	out := []scan.Finding{}
	paths := []string{PathPasswd, PathGroup, PathShadow}
	for _, p := range paths {
		fi, ok := stats[p]
		if !ok {
			continue
		}
		want := expectedModes[p]
		mode := fi.Mode().Perm()
		// Any bits beyond want.maxMode are looser than expected.
		extra := mode &^ want.maxMode
		if extra != 0 {
			sev := scan.SeverityWarning
			if p == PathShadow {
				sev = scan.SeverityCritical
			}
			out = append(out, scan.Finding{
				Severity: sev,
				Subject:  fmt.Sprintf("%s has loose permissions: %#o", p, mode),
				Detail:   fmt.Sprintf("expected at most %#o; extra bits: %#o", want.maxMode, extra),
			})
		}
	}
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
	}
	return 0
}
