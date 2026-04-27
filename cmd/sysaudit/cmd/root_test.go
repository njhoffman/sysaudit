package cmd

import (
	"reflect"
	"testing"
)

func TestSelectScans(t *testing.T) {
	cases := []struct {
		name string
		in   globalFlags
		want []string
	}{
		{"default", globalFlags{}, []string{"procs", "services"}},
		{"all", globalFlags{all: true}, []string{"procs", "services", "users", "groups", "logs", "programs"}},
		{"procs only", globalFlags{procs: true}, []string{"procs"}},
		{"services only", globalFlags{services: true}, []string{"services"}},
		{"users implies users", globalFlags{users: true}, []string{"users"}},
		{"groups implies users", globalFlags{groups: true}, []string{"users"}},
		{"logs", globalFlags{logs: []string{"auth"}}, []string{"logs"}},
		{"programs", globalFlags{programs: []string{"nginx"}}, []string{"programs"}},
		{"combo", globalFlags{procs: true, services: true, logs: []string{"boot"}},
			[]string{"procs", "services", "logs"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := selectScans(tc.in)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("selectScans(%+v) = %v want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestNewRootCmd_FlagsRegistered(t *testing.T) {
	root := newRootCmd()
	for _, name := range []string{
		"verbose", "debug", "quiet", "output",
		"tokens", "model", "analysis-level", "claude-verbosity",
		"procs", "services", "users", "groups", "logs", "journal", "programs", "all",
	} {
		if root.PersistentFlags().Lookup(name) == nil {
			t.Errorf("missing flag: %s", name)
		}
	}
}
