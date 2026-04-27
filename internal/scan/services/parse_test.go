package services

import (
	"reflect"
	"testing"
)

func TestStripANSI(t *testing.T) {
	in := "\x1b[0;32mhello\x1b[0m"
	got := string(stripANSI([]byte(in)))
	if got != "hello" {
		t.Errorf("stripANSI: got %q want %q", got, "hello")
	}
}

func TestParseUnits(t *testing.T) {
	raw := []byte(`[
		{"unit":"a.service","load":"loaded","active":"active","sub":"running","description":"A"},
		{"unit":"b.service","load":"masked","active":"inactive","sub":"dead","description":"B"}
	]`)
	out, err := parseUnits(raw)
	if err != nil {
		t.Fatal(err)
	}
	want := []Unit{
		{Name: "a.service", Load: "loaded", Active: "active", Sub: "running", Description: "A"},
		{Name: "b.service", Load: "masked", Active: "inactive", Sub: "dead", Description: "B"},
	}
	if !reflect.DeepEqual(out, want) {
		t.Errorf("parseUnits mismatch:\n got=%+v\nwant=%+v", out, want)
	}
}

func TestParseUnits_HandlesANSIInjection(t *testing.T) {
	raw := []byte("\x1b[0;32m[{\"unit\":\"a.service\",\"load\":\"loaded\",\"active\":\"active\",\"sub\":\"running\",\"description\":\"A\"}]\x1b[0m")
	out, err := parseUnits(raw)
	if err != nil {
		t.Fatalf("expected ANSI to be stripped, got: %v", err)
	}
	if len(out) != 1 || out[0].Name != "a.service" {
		t.Errorf("unexpected: %+v", out)
	}
}

func TestParseUnits_Empty(t *testing.T) {
	out, err := parseUnits([]byte(""))
	if err != nil {
		t.Fatal(err)
	}
	if out != nil {
		t.Errorf("expected nil for empty input, got %v", out)
	}
}

func TestParseShow(t *testing.T) {
	raw := []byte(`Type=notify
Restart=on-failure
Result=success
NRestarts=3
Description=OpenBSD Secure Shell server
LoadState=loaded
ActiveState=active
SubState=running
FragmentPath=/usr/lib/systemd/system/ssh.service
UnitFileState=enabled
SomeOtherKey=ignored-but-kept-in-raw
`)
	got := parseShow(raw)
	if got.Type != "notify" {
		t.Errorf("Type: %q", got.Type)
	}
	if got.NRestarts != 3 {
		t.Errorf("NRestarts: %d", got.NRestarts)
	}
	if got.FragmentPath != "/usr/lib/systemd/system/ssh.service" {
		t.Errorf("FragmentPath: %q", got.FragmentPath)
	}
	if got.UnitFileState != "enabled" {
		t.Errorf("UnitFileState: %q", got.UnitFileState)
	}
	if got.Raw["SomeOtherKey"] != "ignored-but-kept-in-raw" {
		t.Errorf("Raw should retain unknown keys, got %q", got.Raw["SomeOtherKey"])
	}
}

func TestParseShow_IgnoresMalformedLines(t *testing.T) {
	raw := []byte(`Type=simple
not-a-keyvalue-line
=leading-equals-no-key
Description=ok
`)
	got := parseShow(raw)
	if got.Type != "simple" || got.Description != "ok" {
		t.Errorf("got %+v", got)
	}
}

func TestParseShow_ValueWithEqualsSign(t *testing.T) {
	// Some Environment= lines contain =; we keep the first =
	raw := []byte(`Description=foo=bar=baz
`)
	got := parseShow(raw)
	if got.Description != "foo=bar=baz" {
		t.Errorf("Description with embedded =: %q", got.Description)
	}
}
