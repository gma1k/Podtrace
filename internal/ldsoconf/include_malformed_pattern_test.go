package ldsoconf

import (
	"path/filepath"
	"reflect"
	"testing"
)

func TestSearchPaths_MalformedIncludePatternIsSkipped(t *testing.T) {
	dir := t.TempDir()
	writeConf(t, filepath.Join(dir, "ld.so.conf"),
		"include /etc/extra/[.conf\n/usr/local/lib\n")
	writeConf(t, filepath.Join(dir, "extra", "[.conf"), "/opt/bracket/lib\n")
	withBase(t, dir)

	got := SearchPaths()
	want := []string{"/usr/local/lib"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("SearchPaths = %v, want %v", got, want)
	}
}
