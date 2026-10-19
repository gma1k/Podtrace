package usdt

import (
	"debug/elf"
	"runtime"
	"strconv"
	"strings"
)

// MaxArgs bounds how many decoded operands are carried per probe.
const MaxArgs = 4

// ArgKind classifies how a decoded USDT operand yields its value at probe time.
type ArgKind uint8

const (
	ArgUnsupported ArgKind = 0
	ArgReg         ArgKind = 1
	ArgMem         ArgKind = 2
	ArgConst       ArgKind = 3
)

// Arg is a single decoded USDT operand from the stapsdt argument descriptor.
type Arg struct {
	Size   int8
	Kind   ArgKind
	RegOff uint16
	Disp   int64
}

// argArch selects the operand grammar and pt_regs layout for decoding a
// stapsdt argument descriptor.
type argArch uint8

const (
	argArchUnknown argArch = iota
	argArchAMD64
	argArchARM64
)

// hostArgArch is the architecture whose pt_regs the BPF program reads, i.e.
// the one the agent runs on.
func hostArgArch() argArch {
	return argArchForGOARCH(runtime.GOARCH)
}

// argArchForGOARCH maps a GOARCH value to the operand grammar of its pt_regs.
func argArchForGOARCH(goarch string) argArch {
	switch goarch {
	case "amd64":
		return argArchAMD64
	case "arm64":
		return argArchARM64
	default:
		return argArchUnknown
	}
}

// argArchForMachine maps an ELF e_machine to the operand grammar its stapsdt
// notes use. A binary built for another architecture than the host cannot
// have its operands resolved against the host's pt_regs, so it yields
// argArchUnknown and every operand decodes as ArgUnsupported.
func argArchForMachine(m elf.Machine) argArch {
	var arch argArch
	switch m {
	case elf.EM_X86_64:
		arch = argArchAMD64
	case elf.EM_AARCH64:
		arch = argArchARM64
	default:
		return argArchUnknown
	}
	if arch != hostArgArch() {
		return argArchUnknown
	}
	return arch
}

// parseArgDesc decodes a stapsdt argument descriptor for the host
// architecture.
func parseArgDesc(desc string) []Arg {
	return parseArgDescFor(desc, hostArgArch())
}

// parseArgDescFor decodes a stapsdt argument descriptor, a space-separated
// list of `N@operand` specs in the given architecture's assembler syntax, into
// at most MaxArgs operands.
func parseArgDescFor(desc string, arch argArch) []Arg {
	desc = strings.TrimSpace(desc)
	if desc == "" {
		return nil
	}
	var args []Arg
	for _, tok := range splitArgTokens(desc) {
		if len(args) >= MaxArgs {
			break
		}
		args = append(args, parseArgTokenFor(tok, arch))
	}
	return args
}

// splitArgTokens splits a descriptor on whitespace outside brackets, since an
// arm64 memory operand such as `-4@[sp, 12]` contains a space.
func splitArgTokens(desc string) []string {
	var toks []string
	depth := 0
	start := -1
	for i := 0; i < len(desc); i++ {
		c := desc[i]
		switch {
		case c == '[' || c == '(':
			depth++
		case (c == ']' || c == ')') && depth > 0:
			depth--
		case (c == ' ' || c == '\t' || c == '\n' || c == '\r') && depth == 0:
			if start >= 0 {
				toks = append(toks, desc[start:i])
				start = -1
			}
			continue
		}
		if start < 0 {
			start = i
		}
	}
	if start >= 0 {
		toks = append(toks, desc[start:])
	}
	return toks
}

// parseArgTokenFor decodes one `N@operand` spec.
func parseArgTokenFor(tok string, arch argArch) Arg {
	at := strings.IndexByte(tok, '@')
	if at <= 0 || at == len(tok)-1 {
		return Arg{Kind: ArgUnsupported}
	}
	size, err := strconv.ParseInt(tok[:at], 10, 8)
	if err != nil || size == 0 {
		return Arg{Kind: ArgUnsupported}
	}
	op := tok[at+1:]
	a := Arg{Size: int8(size), Kind: ArgUnsupported}

	switch arch {
	case argArchAMD64:
		parseAMD64Operand(op, &a)
	case argArchARM64:
		parseARM64Operand(op, &a)
	default:
		if v, ok := parseConstOperand(op, "$"); ok {
			a.Kind = ArgConst
			a.Disp = v
		}
	}
	return a
}

// parseConstOperand decodes an immediate written with the given prefix.
func parseConstOperand(op, prefix string) (int64, bool) {
	if !strings.HasPrefix(op, prefix) {
		return 0, false
	}
	v, err := strconv.ParseInt(op[len(prefix):], 10, 64)
	return v, err == nil
}

// parseAMD64Operand decodes an AT&T operand: `$imm`, `%reg`, or
// `disp(%reg)`. Index/scale forms are unsupported.
func parseAMD64Operand(op string, a *Arg) {
	switch {
	case strings.HasPrefix(op, "$"):
		if v, ok := parseConstOperand(op, "$"); ok {
			a.Kind = ArgConst
			a.Disp = v
		}
	case strings.HasPrefix(op, "%"):
		if off, ok := amd64Regs[strings.ToLower(op[1:])]; ok {
			a.Kind = ArgReg
			a.RegOff = off
		}
	case strings.Contains(op, "("):
		openIdx := strings.IndexByte(op, '(')
		closeIdx := strings.IndexByte(op, ')')
		if closeIdx > openIdx {
			inner := op[openIdx+1 : closeIdx]
			if !strings.ContainsAny(inner, ",") && strings.HasPrefix(inner, "%") {
				if off, ok := amd64Regs[strings.ToLower(inner[1:])]; ok {
					disp := int64(0)
					if d := strings.TrimSpace(op[:openIdx]); d != "" {
						if v, err := strconv.ParseInt(d, 10, 64); err == nil {
							disp = v
						} else {
							return
						}
					}
					a.Kind = ArgMem
					a.RegOff = off
					a.Disp = disp
				}
			}
		}
	}
}

// parseARM64Operand decodes an AArch64 stapsdt operand as GCC and Clang emit
// it: `imm` (optionally `#imm`), `xN`/`wN`/`sp`, `[reg]`, or `[reg, imm]`
// (optionally `[reg, #imm]`). Register-offset and pre/post-index forms are
// unsupported.
func parseARM64Operand(op string, a *Arg) {
	if strings.HasPrefix(op, "[") {
		if !strings.HasSuffix(op, "]") {
			return
		}
		inner := op[1 : len(op)-1]
		regName, dispStr, hasDisp := strings.Cut(inner, ",")
		off, ok := arm64Regs[strings.ToLower(strings.TrimSpace(regName))]
		if !ok {
			return
		}
		disp := int64(0)
		if hasDisp {
			d := strings.TrimPrefix(strings.TrimSpace(dispStr), "#")
			v, err := strconv.ParseInt(d, 10, 64)
			if err != nil {
				return
			}
			disp = v
		}
		a.Kind = ArgMem
		a.RegOff = off
		a.Disp = disp
		return
	}
	if off, ok := arm64Regs[strings.ToLower(op)]; ok {
		a.Kind = ArgReg
		a.RegOff = off
		return
	}
	if v, err := strconv.ParseInt(strings.TrimPrefix(op, "#"), 10, 64); err == nil {
		a.Kind = ArgConst
		a.Disp = v
	}
}

// amd64Regs mirrors the field order of the kernel's x86_64 struct pt_regs (each
// entry 8 bytes). Sub-register names (eax/ax/al ...) alias their 64-bit parent.
var amd64Regs = func() map[string]uint16 {
	base := []struct {
		off   uint16
		names []string
	}{
		{0, []string{"r15", "r15d", "r15w", "r15b"}},
		{8, []string{"r14", "r14d", "r14w", "r14b"}},
		{16, []string{"r13", "r13d", "r13w", "r13b"}},
		{24, []string{"r12", "r12d", "r12w", "r12b"}},
		{32, []string{"rbp", "ebp", "bp", "bpl"}},
		{40, []string{"rbx", "ebx", "bx", "bl"}},
		{48, []string{"r11", "r11d", "r11w", "r11b"}},
		{56, []string{"r10", "r10d", "r10w", "r10b"}},
		{64, []string{"r9", "r9d", "r9w", "r9b"}},
		{72, []string{"r8", "r8d", "r8w", "r8b"}},
		{80, []string{"rax", "eax", "ax", "al"}},
		{88, []string{"rcx", "ecx", "cx", "cl"}},
		{96, []string{"rdx", "edx", "dx", "dl"}},
		{104, []string{"rsi", "esi", "si", "sil"}},
		{112, []string{"rdi", "edi", "di", "dil"}},
		{128, []string{"rip"}},
		{152, []string{"rsp", "esp", "sp", "spl"}},
	}
	m := make(map[string]uint16)
	for _, r := range base {
		for _, n := range r.names {
			m[n] = r.off
		}
	}
	return m
}()

// arm64Regs mirrors struct user_pt_regs: regs[0..30] (x0..x30) then sp. wN names
// alias their 64-bit xN parent; the BPF side masks the read to the operand
// width.
var arm64Regs = func() map[string]uint16 {
	m := make(map[string]uint16)
	for i := 0; i <= 30; i++ {
		off := uint16(i * 8)
		m["x"+strconv.Itoa(i)] = off
		m["w"+strconv.Itoa(i)] = off
	}
	m["sp"] = 31 * 8
	return m
}()
