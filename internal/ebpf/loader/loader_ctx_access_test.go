package loader

import (
	"os/exec"
	"regexp"
	"strings"
	"testing"
)

var (
	funcHeader  = regexp.MustCompile(`^[0-9a-f]+ <([^>]+)>:`)
	insnLine    = regexp.MustCompile(`^\s*(\d+):\s+(.*)$`)
	loadThrough = regexp.MustCompile(`^r\d+ = \*\(u\d+ \*\)\((r\d+) [+-] ?-?\w+\)`)
	regCopy     = regexp.MustCompile(`^(r\d+) = (r\d+)$`)
	regAdjust   = regexp.MustCompile(`^(r\d+) [+-]= `)
	regAssign   = regexp.MustCompile(`^(r\d+) = `)
)

func objdump(t *testing.T) string {
	t.Helper()
	for _, name := range []string{"llvm-objdump", "llvm-objdump-21", "llvm-objdump-20", "llvm-objdump-19", "llvm-objdump-18"} {
		if path, err := exec.LookPath(name); err == nil {
			return path
		}
	}
	t.Skip("llvm-objdump not installed")
	return ""
}

// modifiedCtxLoads finds loads through a copy of the program's context
// pointer that was moved with += or -= first. The verifier rejects them
// ("dereference of modified ctx ptr"), but only for some clang versions'
// code, and a local kernel may accept what CI's rejects.
func modifiedCtxLoads(disasm string) []string {
	var hits []string
	var fn string
	ctx, mod := map[string]bool{}, map[string]bool{}
	for _, line := range strings.Split(disasm, "\n") {
		if m := funcHeader.FindStringSubmatch(line); m != nil {
			fn = m[1]
			ctx, mod = map[string]bool{"r1": true}, map[string]bool{}
			continue
		}
		m := insnLine.FindStringSubmatch(line)
		if m == nil || fn == "" {
			continue
		}
		ins := strings.TrimSpace(strings.SplitN(m[2], ";", 2)[0])
		if l := loadThrough.FindStringSubmatch(ins); l != nil && mod[l[1]] {
			hits = append(hits, fn+" @"+m[1]+": "+ins)
		}
		switch {
		case strings.HasPrefix(ins, "call"):
			for _, r := range []string{"r0", "r1", "r2", "r3", "r4", "r5"} {
				delete(ctx, r)
				delete(mod, r)
			}
		case regCopy.MatchString(ins):
			c := regCopy.FindStringSubmatch(ins)
			dst, src := c[1], c[2]
			srcCtx, srcMod := ctx[src], mod[src]
			delete(ctx, dst)
			delete(mod, dst)
			if srcCtx {
				ctx[dst] = true
			}
			if srcMod {
				mod[dst] = true
			}
		case regAdjust.MatchString(ins):
			r := regAdjust.FindStringSubmatch(ins)[1]
			if ctx[r] || mod[r] {
				delete(ctx, r)
				mod[r] = true
			}
		case regAssign.MatchString(ins):
			r := regAssign.FindStringSubmatch(ins)[1]
			delete(ctx, r)
			delete(mod, r)
		}
	}
	return hits
}

func TestModifiedCtxLoadsFindsTheClang21Pattern(t *testing.T) {
	disasm := strings.Join([]string{
		"0000000000000000 <uprobe_SSL_read>:",
		"       0:	r6 = r1",
		"      21:	r1 = 0x70",
		"      29:	r2 = r6",
		"      30:	r2 += r1",
		"      31:	r8 = *(u64 *)(r2 + 0x0)",
		"0000000000000100 <uprobe_ok>:",
		"       0:	r6 = r1",
		"       1:	r8 = *(u64 *)(r6 + 0x70)",
		"       2:	r2 = r10",
		"       3:	r2 += -0x10",
		"       4:	r3 = *(u64 *)(r2 + 0x0)",
	}, "\n")
	hits := modifiedCtxLoads(disasm)
	if len(hits) != 1 || !strings.HasPrefix(hits[0], "uprobe_SSL_read @31") {
		t.Fatalf("modifiedCtxLoads = %v, want only uprobe_SSL_read @31", hits)
	}
}

func TestCompiledObjectHasNoLoadsThroughAModifiedCtx(t *testing.T) {
	tool := objdump(t)
	obj := findBPFObjectPath()
	if !fileExists(obj) {
		t.Skipf("BPF object not built at %s", obj)
	}
	out, err := exec.Command(tool, "-d", "--no-show-raw-insn", obj).Output()
	if err != nil {
		t.Fatalf("%s: %v", tool, err)
	}
	if hits := modifiedCtxLoads(string(out)); len(hits) > 0 {
		t.Fatalf("loads through a modified ctx pointer; the verifier rejects these (read each ctx field "+
			"once into a local before branching):\n  %s", strings.Join(hits, "\n  "))
	}
}
