package logs

import (
	"context"
	"reflect"
	"testing"
)

func TestParseSources_KnownNames(t *testing.T) {
	got, err := ParseSources([]string{"auth", "boot", "journal"})
	if err != nil {
		t.Fatal(err)
	}
	want := []Source{SourceAuth, SourceBoot, SourceJournal}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v want %v", got, want)
	}
}

func TestParseSources_Dedupes(t *testing.T) {
	got, err := ParseSources([]string{"auth", "auth", "boot"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Errorf("expected dedupe to 2, got %v", got)
	}
}

func TestParseSources_RejectsUnknown(t *testing.T) {
	_, err := ParseSources([]string{"auth", "typo"})
	if err == nil {
		t.Error("expected error for unknown source")
	}
}

func TestParseSources_NilOnEmpty(t *testing.T) {
	got, err := ParseSources(nil)
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Errorf("expected nil, got %v", got)
	}
}

func TestScan_UnknownSource_MarkedNotRunYet(t *testing.T) {
	// Sources that are validated by ParseSources can never reach Scan
	// unregistered, but the dispatcher still has a NotRunYet code path
	// for forward compatibility. Inject a fake unregistered source to
	// exercise it.
	const fake Source = "_unregistered_for_test"
	res, err := Scan(context.Background(), Options{Sources: []Source{fake}})
	if err != nil {
		t.Fatal(err)
	}
	notRun, _ := res.Summary["sources_not_run_yet"].([]string)
	if len(notRun) != 1 || notRun[0] != string(fake) {
		t.Errorf("expected the fake source in NotRunYet, got %v", notRun)
	}
}

func TestSplitArgs(t *testing.T) {
	cases := map[string][]string{
		"":                          nil,
		"-p 4 -b -n 500 --no-pager": {"-p", "4", "-b", "-n", "500", "--no-pager"},
		"  -p   4  ":                {"-p", "4"},
	}
	for in, want := range cases {
		got := splitArgs(in)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("splitArgs(%q) = %v want %v", in, got, want)
		}
	}
}
