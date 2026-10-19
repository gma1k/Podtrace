package ldsoconf

import (
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
)

func writeConf(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestSearchPaths_FollowsIncludeAndSkipsDirectives(t *testing.T) {
	dir := t.TempDir()
	writeConf(t, filepath.Join(dir, "ld.so.conf"),
		"include /etc/ld.so.conf.d/*.conf\nhwcap 0 nosegneg\n/usr/local/lib # trailing comment\n")
	writeConf(t, filepath.Join(dir, "ld.so.conf.d", "b.conf"), "/usr/lib/b\n")
	writeConf(t, filepath.Join(dir, "ld.so.conf.d", "a.conf"), "/usr/lib/a\n")
	withBase(t, dir)

	got := SearchPaths()
	want := []string{"/usr/lib/a", "/usr/lib/b", "/usr/local/lib"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("SearchPaths = %v, want %v", got, want)
	}
	for _, p := range got {
		if strings.HasPrefix(p, "include") || strings.HasPrefix(p, "hwcap") || strings.Contains(p, "#") {
			t.Errorf("directive leaked as a search path: %q", p)
		}
	}
}

func TestSearchPaths_FollowsIncludeOutsideConfD(t *testing.T) {
	dir := t.TempDir()
	writeConf(t, filepath.Join(dir, "ld.so.conf"), "include extra/*.conf /etc/single.conf\n")
	writeConf(t, filepath.Join(dir, "extra", "x.conf"), "/opt/x/lib\n")
	writeConf(t, filepath.Join(dir, "single.conf"), "/opt/single/lib\n")
	withBase(t, dir)

	got := SearchPaths()
	want := []string{"/opt/x/lib", "/opt/single/lib"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("SearchPaths = %v, want %v", got, want)
	}
}

func TestSearchPaths_IncludeCannotEscapeTheRoot(t *testing.T) {
	outer := t.TempDir()
	base := filepath.Join(outer, "etc")
	writeConf(t, filepath.Join(outer, "secret.conf"), "/leaked/outside\n")
	writeConf(t, filepath.Join(base, "ld.so.conf"),
		"include ../secret.conf\ninclude /secret.conf\ninclude /etc/../secret.conf\ninclude "+filepath.Join(outer, "secret.conf")+"\n")
	withBase(t, base)

	if got := SearchPaths(); slices.Contains(got, "/leaked/outside") {
		t.Errorf("include escaped the root: %v", got)
	}
}

func TestSearchPaths_IncludeCycleTerminates(t *testing.T) {
	dir := t.TempDir()
	writeConf(t, filepath.Join(dir, "ld.so.conf"), "include /etc/loop.conf\n/first\n")
	writeConf(t, filepath.Join(dir, "loop.conf"), "include ld.so.conf\ninclude loop.conf\n/second\n")
	withBase(t, dir)

	got := SearchPaths()
	want := []string{"/second", "/first"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("SearchPaths = %v, want %v", got, want)
	}
}

func TestSearchPaths_IncludeChainDepthIsBounded(t *testing.T) {
	dir := t.TempDir()
	writeConf(t, filepath.Join(dir, "ld.so.conf"), "include c0.conf\n")
	for i := 0; i < 20; i++ {
		body := "/depth/" + strconv.Itoa(i) + "\ninclude c" + strconv.Itoa(i+1) + ".conf\n"
		writeConf(t, filepath.Join(dir, "c"+strconv.Itoa(i)+".conf"), body)
	}
	withBase(t, dir)

	got := SearchPaths()
	if len(got) == 0 || len(got) > maxIncludeDepth {
		t.Errorf("got %d paths, want between 1 and %d", len(got), maxIncludeDepth)
	}
}

func TestSearchPaths_DeduplicatesAndDropsRelativeEntries(t *testing.T) {
	dir := t.TempDir()
	writeConf(t, filepath.Join(dir, "ld.so.conf"), "/usr/lib/\n/usr/lib\nrelative/lib\n/usr/lib64=libc6\n")
	writeConf(t, filepath.Join(dir, "ld.so.conf.d", "dup.conf"), "/usr/lib\n")
	withBase(t, dir)

	got := SearchPaths()
	want := []string{"/usr/lib", "/usr/lib64"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("SearchPaths = %v, want %v", got, want)
	}
}

func TestScopedPattern(t *testing.T) {
	cases := []struct {
		pattern   string
		including string
		want      string
		ok        bool
	}{
		{"/etc/ld.so.conf.d/*.conf", "ld.so.conf", "ld.so.conf.d/*.conf", true},
		{"sub/*.conf", "ld.so.conf.d/a.conf", "ld.so.conf.d/sub/*.conf", true},
		{"/usr/lib/x.conf", "ld.so.conf", "", false},
		{"/etc", "ld.so.conf", "", false},
		{"../x.conf", "ld.so.conf", "", false},
		{"../../x.conf", "ld.so.conf.d/a.conf", "", false},
		{"/etc/../x.conf", "ld.so.conf", "", false},
	}
	for _, c := range cases {
		got, ok := scopedPattern(c.pattern, c.including)
		if got != c.want || ok != c.ok {
			t.Errorf("scopedPattern(%q, %q) = (%q, %v), want (%q, %v)", c.pattern, c.including, got, ok, c.want, c.ok)
		}
	}
}
