// Package ldsoconf reads dynamic-linker search-path configuration from
// /etc/ld.so.conf and /etc/ld.so.conf.d/*.conf using a scoped os.Root.
//
// The probe-attachment code needs the same set of search paths the
// dynamic linker would consider when resolving libc, libssl, etc., so
// it can find a matching shared object on the host or under a
// container's /proc/<pid>/root view. The base directory is whatever
// config.LdSoConfBasePath points to (default /etc).
//
// All exported helpers operate inside the configured base; absolute
// paths and ".." traversals are rejected by os.Root.
package ldsoconf

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/gma1k/podtrace/internal/config"
)

var (
	rootMu  sync.RWMutex
	rootImp atomic.Pointer[os.Root]
)

func openRoot() (*os.Root, error) {
	want := config.LdSoConfBasePath
	if r := rootImp.Load(); r != nil && r.Name() == want {
		return r, nil
	}
	rootMu.Lock()
	defer rootMu.Unlock()
	if r := rootImp.Load(); r != nil && r.Name() == want {
		return r, nil
	}
	r, err := os.OpenRoot(want)
	if err != nil {
		return nil, err
	}
	if old := rootImp.Swap(r); old != nil {
		_ = old.Close()
	}
	return r, nil
}

// ResetForTesting forces the next call to reopen the root. Use in
// tests that mutate config.LdSoConfBasePath.
func ResetForTesting() {
	rootMu.Lock()
	defer rootMu.Unlock()
	if old := rootImp.Swap(nil); old != nil {
		_ = old.Close()
	}
}

func readScoped(rel string) ([]byte, error) {
	r, err := openRoot()
	if err != nil {
		return nil, fmt.Errorf("ldsoconf: open %s: %w", config.LdSoConfBasePath, err)
	}
	f, err := r.Open(rel)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return io.ReadAll(f)
}

const confDir = "/etc"

const maxIncludeDepth = 8

const maxIncludedFiles = 256

// SearchPaths returns the dynamic-linker search paths assembled from
// ld.so.conf (following its include directives) plus every *.conf entry
// under ld.so.conf.d/. Comments, blank lines, hwcap directives and relative
// paths are skipped, and each directory is returned once in first-seen order.
// Errors reading individual files are silently ignored — a missing
// /etc/ld.so.conf on minimal containers is normal, and the caller falls back
// to architecture defaults.
func SearchPaths() []string {
	r, err := openRoot()
	if err != nil {
		return nil
	}
	p := &parser{root: r, visited: map[string]struct{}{}, seen: map[string]struct{}{}}
	p.parseFile("ld.so.conf", 0)
	p.includeGlob("ld.so.conf.d/*.conf", 0)
	return p.out
}

type parser struct {
	root    *os.Root
	visited map[string]struct{}
	seen    map[string]struct{}
	out     []string
}

func (p *parser) parseFile(rel string, depth int) {
	if depth > maxIncludeDepth || len(p.visited) >= maxIncludedFiles {
		return
	}
	if _, done := p.visited[rel]; done {
		return
	}
	p.visited[rel] = struct{}{}
	data, err := readScoped(rel)
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		if hash := strings.IndexByte(line, '#'); hash >= 0 {
			line = line[:hash]
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "include":
			for _, pattern := range fields[1:] {
				if relPattern, ok := scopedPattern(pattern, rel); ok {
					p.includeGlob(relPattern, depth+1)
				}
			}
			continue
		case "hwcap":
			continue
		}
		dir := strings.TrimSpace(line)
		if eq := strings.IndexByte(dir, '='); eq >= 0 {
			dir = strings.TrimSpace(dir[:eq])
		}
		if !filepath.IsAbs(dir) {
			continue
		}
		dir = filepath.Clean(dir)
		if _, dup := p.seen[dir]; dup {
			continue
		}
		p.seen[dir] = struct{}{}
		p.out = append(p.out, dir)
	}
}

// includeGlob reads every file matching a root-relative pattern. Wildcards
// are honoured in the final path component only.
func (p *parser) includeGlob(relPattern string, depth int) {
	dir, filePattern := filepath.Split(relPattern)
	dir = filepath.Clean(dir)
	if _, err := filepath.Match(filePattern, ""); err != nil {
		return
	}
	if !hasGlobMeta(filePattern) {
		p.parseFile(filepath.Join(dir, filePattern), depth)
		return
	}
	names, err := fs.readDir(p.root, dir)
	if err != nil {
		return
	}
	sort.Strings(names)
	for _, name := range names {
		if ok, _ := filepath.Match(filePattern, name); ok {
			p.parseFile(filepath.Join(dir, name), depth)
		}
	}
}

// scopedPattern maps an include pattern onto a path relative to the root. An
// absolute pattern must lie under confDir.
func scopedPattern(pattern, includingRel string) (string, bool) {
	var rel string
	if filepath.IsAbs(pattern) {
		clean := filepath.Clean(pattern)
		prefix := confDir + "/"
		if !strings.HasPrefix(clean, prefix) {
			return "", false
		}
		rel = strings.TrimPrefix(clean, prefix)
	} else {
		rel = filepath.Clean(filepath.Join(filepath.Dir(includingRel), pattern))
	}
	if rel == "." || rel == ".." || strings.HasPrefix(rel, "../") || filepath.IsAbs(rel) {
		return "", false
	}
	return rel, true
}

func hasGlobMeta(s string) bool {
	return strings.ContainsAny(s, "*?[\\")
}

// fs holds tiny utilities used internally so the file does not depend
// on filepath.Glob (which gosec also flags) and stays inside os.Root.
var fs = struct {
	readDir func(r *os.Root, name string) ([]string, error)
}{
	readDir: func(r *os.Root, name string) ([]string, error) {
		f, err := r.Open(name)
		if err != nil {
			return nil, err
		}
		defer func() { _ = f.Close() }()
		entries, err := f.Readdirnames(-1)
		if err != nil {
			return nil, err
		}
		return entries, nil
	},
}
