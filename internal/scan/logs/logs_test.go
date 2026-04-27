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

func TestScan_StubsUnimplementedSources(t *testing.T) {
	// Asking only for sources without scanners produces NotRunYet entries
	// rather than crashing or silently dropping them.
	res, err := Scan(context.Background(), Options{
		Sources: []Source{SourceAuth, SourceKern, SourceMisc},
	})
	if err != nil {
		t.Fatal(err)
	}
	notRun, _ := res.Summary["sources_not_run_yet"].([]string)
	if len(notRun) != 3 {
		t.Errorf("expected 3 stubbed sources, got %v", notRun)
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
