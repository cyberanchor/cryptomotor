package config

import (
	"os"
	"strings"
	"testing"
)

// CM-16: the version printed by the binary, the Makefile (which reads this
// constant) and the newest CHANGELOG section must agree; the release
// workflow also checks the tag against it.
func TestProgramVersionMatchesChangelog(t *testing.T) {
	data, err := os.ReadFile("../../CHANGELOG.md")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "## [") {
			if want := "## [" + ProgramVersion + "]"; !strings.HasPrefix(line, want) {
				t.Fatalf("newest CHANGELOG section is %q, ProgramVersion is %s", line, ProgramVersion)
			}
			return
		}
	}
	t.Fatal("CHANGELOG.md has no version section")
}
