package log

import "testing"

func TestLevelFromFlags(t *testing.T) {
	cases := []struct {
		name                  string
		verbose, debug, quiet bool
		want                  Level
	}{
		{"none", false, false, false, LevelInfo},
		{"verbose", true, false, false, LevelVerbose},
		{"debug", false, true, false, LevelDebug},
		{"quiet", false, false, true, LevelQuiet},
		{"debug-wins-over-verbose", true, true, false, LevelDebug},
		{"debug-wins-over-quiet", false, true, true, LevelDebug},
		{"verbose-wins-over-quiet", true, false, true, LevelVerbose},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := LevelFromFlags(tc.verbose, tc.debug, tc.quiet)
			if got != tc.want {
				t.Errorf("LevelFromFlags(%v,%v,%v) = %v, want %v",
					tc.verbose, tc.debug, tc.quiet, got, tc.want)
			}
		})
	}
}

func TestNew_DoesNotPanic(t *testing.T) {
	for _, lvl := range []Level{LevelInfo, LevelVerbose, LevelDebug, LevelQuiet} {
		l := New(Options{Level: lvl})
		if l == nil {
			t.Fatalf("New returned nil for level %v", lvl)
		}
	}
}
