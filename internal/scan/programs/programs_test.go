package programs

import (
	"context"
	"reflect"
	"testing"
)

func TestParsePrograms_KnownNames(t *testing.T) {
	got, err := ParsePrograms([]string{"sshd", "nginx"})
	if err != nil {
		t.Fatal(err)
	}
	want := []Program{ProgramSSHD, ProgramNginx}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v want %v", got, want)
	}
}

func TestParsePrograms_RejectsUnknown(t *testing.T) {
	_, err := ParsePrograms([]string{"sshd", "typo"})
	if err == nil {
		t.Error("expected error for unknown program")
	}
}

func TestParsePrograms_Dedupes(t *testing.T) {
	got, err := ParsePrograms([]string{"sshd", "sshd"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Errorf("expected dedupe to 1, got %v", got)
	}
}

func TestScan_UnknownProgram_Skipped(t *testing.T) {
	const fake Program = "_unregistered_for_test"
	res, err := Scan(context.Background(), Options{Programs: []Program{fake}})
	if err != nil {
		t.Fatal(err)
	}
	skipped, _ := res.Summary["skipped"].([]string)
	if len(skipped) != 1 || skipped[0] != string(fake) {
		t.Errorf("expected fake program to be skipped, got %v", skipped)
	}
}
