package version

import (
	"strings"
	"testing"
)

func TestGetMatchesVars(t *testing.T) {
	info := Get()
	if info.Version != Version {
		t.Errorf("Get().Version = %q, want %q", info.Version, Version)
	}
	if info.Commit != Commit {
		t.Errorf("Get().Commit = %q, want %q", info.Commit, Commit)
	}
	if info.BuildTime != BuildTime {
		t.Errorf("Get().BuildTime = %q, want %q", info.BuildTime, BuildTime)
	}
}

func TestStringContainsFields(t *testing.T) {
	oldVersion, oldCommit := Version, Commit
	t.Cleanup(func() { Version, Commit = oldVersion, oldCommit })

	Version, Commit = "9.9.9-test", "abc1234"
	got := String()
	for _, want := range []string{"9.9.9-test", "abc1234"} {
		if !strings.Contains(got, want) {
			t.Errorf("String() = %q, missing %q", got, want)
		}
	}
}
