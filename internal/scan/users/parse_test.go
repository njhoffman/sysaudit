package users

import (
	"strings"
	"testing"
)

func TestParsePasswd(t *testing.T) {
	in := `root:x:0:0:root:/root:/bin/bash
# a comment
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
nicholas:x:1000:1000:Nicholas:/home/nicholas:/usr/bin/zsh
malformed-line-no-colons
`
	out := ParsePasswd(strings.NewReader(in))
	if len(out) != 3 {
		t.Fatalf("want 3 entries, got %d", len(out))
	}
	if out[0].Name != "root" || out[0].UID != 0 || !out[0].HasShadow {
		t.Errorf("root: %+v", out[0])
	}
	if out[2].Shell != "/usr/bin/zsh" || out[2].UID != 1000 {
		t.Errorf("regular user: %+v", out[2])
	}
}

func TestParseGroup(t *testing.T) {
	in := `root:x:0:
sudo:x:27:alice,bob
docker:x:998:nicholas
empty:x:1234:
`
	out := ParseGroup(strings.NewReader(in))
	if len(out) != 4 {
		t.Fatalf("want 4 entries, got %d", len(out))
	}
	sudo := out[1]
	if sudo.Name != "sudo" || sudo.GID != 27 {
		t.Errorf("sudo: %+v", sudo)
	}
	if len(sudo.Members) != 2 || sudo.Members[0] != "alice" || sudo.Members[1] != "bob" {
		t.Errorf("sudo members: %v", sudo.Members)
	}
	if len(out[3].Members) != 0 {
		t.Errorf("empty members: %v", out[3].Members)
	}
}

func TestParseShadow(t *testing.T) {
	in := `root:!:19000:0:99999:7:::
alice:$y$j9T$abc$xyz:19500:0:99999:7:30::
locked:!!:19500:0:99999:7:::
empty::19500:0:99999:7:::
`
	out := ParseShadow(strings.NewReader(in))
	if len(out) != 4 {
		t.Fatalf("want 4 entries, got %d", len(out))
	}
	if out[0].Name != "root" || out[0].HashField != "!" {
		t.Errorf("root: %+v", out[0])
	}
	if out[1].Name != "alice" || !strings.HasPrefix(out[1].HashField, "$y$") {
		t.Errorf("alice: %+v", out[1])
	}
	if out[2].HashField != "!!" {
		t.Errorf("locked: %+v", out[2])
	}
	if out[3].HashField != "" {
		t.Errorf("empty: %+v", out[3])
	}
}

func TestParseShadow_HandlesMissingNumericFields(t *testing.T) {
	in := `bob::::::::
`
	out := ParseShadow(strings.NewReader(in))
	if len(out) != 1 {
		t.Fatalf("got %d", len(out))
	}
	e := out[0]
	if e.LastChange != -1 || e.MinAge != -1 || e.MaxAge != -1 ||
		e.WarnDays != -1 || e.InactDays != -1 || e.ExpireDays != -1 {
		t.Errorf("expected -1 sentinels: %+v", e)
	}
}

func TestIsLockedHash(t *testing.T) {
	cases := map[string]bool{
		"":           false,
		"!":          true,
		"!!":         true,
		"*":          true,
		"!hash":      true,
		"$y$j9T$abc": false,
		"*LK*":       true,
	}
	for in, want := range cases {
		got := isLockedHash(in)
		if got != want {
			t.Errorf("isLockedHash(%q) = %v want %v", in, got, want)
		}
	}
}
