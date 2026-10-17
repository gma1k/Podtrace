package stacktrace

import (
	"debug/elf"
	"debug/gosym"
	"os"
	"sort"
	"sync"
	"syscall"
	"unsafe"

	"github.com/gma1k/podtrace/internal/ebpf/safeelf"
	"github.com/gma1k/podtrace/internal/hostfs"
)

// symbolTable names instruction pointers from an executable's own symbols,
// so a frame can be resolved without addr2line on PATH.
type symbolTable struct {
	id   fileID
	path string

	pcln    *pclnIndex
	goTable *gosym.Table
	goBytes int64

	elfMu     sync.Mutex
	elfLazy   bool
	elfLoaded bool
	elfSyms   []elf.Symbol
}

// lookup returns the function containing addr in the file the table was
// loaded from.
func (t *symbolTable) lookup(addr uint64) string {
	if t == nil {
		return ""
	}
	return t.lookupAt(t.path, addr)
}

// lookupAt returns the function containing addr, reading names on demand
// from path, which must be the same executable (same device and inode) the
// table was built from. "" means nothing covers addr.
func (t *symbolTable) lookupAt(path string, addr uint64) string {
	if t == nil {
		return ""
	}
	if t.pcln != nil && t.pcln.covers(addr) {
		if name := t.pclnName(path, addr); name != "" {
			return name
		}
	}
	if t.goTable != nil {
		if fn := t.goTable.PCToFunc(addr); fn != nil && fn.Name != "" {
			return fn.Name
		}
	}
	return elfSymbolAt(t.elfSymbols(path), addr)
}

// pclnName opens path and reads one name, refusing a file that is no longer
// the one the index describes: offsets from one build are garbage in another.
func (t *symbolTable) pclnName(path string, addr uint64) string {
	f, _, err := safeelf.OpenRegular(path)
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()
	if id, ok := fileIDOf(f); !ok || id != t.id {
		return ""
	}
	return t.pcln.name(f, addr)
}

func (t *symbolTable) elfSymbols(path string) []elf.Symbol {
	t.elfMu.Lock()
	defer t.elfMu.Unlock()
	if t.elfLazy && !t.elfLoaded {
		t.loadELFSymbolsLocked(path)
	}
	return t.elfSyms
}

// loadELFSymbolsLocked reads the symbols from path if it is still the indexed
// executable.
func (t *symbolTable) loadELFSymbolsLocked(path string) {
	defer safeelf.RecoverParse("stacktrace.loadELFSymbols")
	raw, _, err := safeelf.OpenRegular(path)
	if err != nil {
		return
	}
	defer func() { _ = raw.Close() }()
	if id, ok := fileIDOf(raw); !ok || id != t.id {
		return
	}
	t.elfLoaded = true
	if f, err := elf.NewFile(raw); err == nil {
		t.elfSyms = functionSymbols(f)
	}
}

func elfSymbolAt(syms []elf.Symbol, addr uint64) string {
	i := sort.Search(len(syms), func(i int) bool {
		return syms[i].Value > addr
	})
	if i == 0 {
		return ""
	}
	s := syms[i-1]
	if s.Size > 0 && addr >= s.Value+s.Size {
		return ""
	}
	return s.Name
}

// approxBytes estimates what the table holds on the heap, for the cache's
// budget.
func (t *symbolTable) approxBytes() int64 {
	if t == nil {
		return 0
	}
	n := t.goBytes
	if t.pcln != nil {
		n += int64(len(t.pcln.functab))
	}
	t.elfMu.Lock()
	for i := range t.elfSyms {
		n += int64(unsafe.Sizeof(t.elfSyms[i])) + int64(len(t.elfSyms[i].Name))
	}
	t.elfMu.Unlock()
	return n
}

// Bounds of the process-wide table cache.
const (
	maxCachedSymbolTables   = 16
	maxCachedSymbolBytes    = 64 << 20
	goTableBytesPerPCLNByte = 2
)

// sharedSymbolTables is the cache every Resolver uses.
var sharedSymbolTables = &symbolTableCache{}

// fileID identifies an executable by device and inode rather than by path.
type fileID struct {
	dev uint64
	ino uint64
}

type cachedTable struct {
	id    fileID
	table *symbolTable
}

// symbolTableCache keeps a bounded set of parsed tables, most recently used
// first. It is safe for concurrent use.
type symbolTableCache struct {
	mu       sync.Mutex
	entries  []cachedTable
	limit    int
	maxBytes int64
	statID   func(path string) (fileID, bool)
	load     func(path string) *symbolTable
	loading  map[fileID]*pendingTable
}

// pendingTable is a table one caller is parsing; others wanting the same
// file wait for it instead of parsing it again.
type pendingTable struct {
	done  chan struct{}
	table *symbolTable
}

func (c *symbolTableCache) get(exePath string) *symbolTable {
	stat := c.statID
	if stat == nil {
		stat = statFileID
	}
	load := c.load
	if load == nil {
		load = loadSymbolTable
	}

	id, ok := stat(exePath)
	if !ok {
		return load(exePath)
	}

	c.mu.Lock()
	for i, e := range c.entries {
		if e.id == id {
			if i > 0 {
				copy(c.entries[1:i+1], c.entries[:i])
				c.entries[0] = e
			}
			c.trimLocked()
			c.mu.Unlock()
			return e.table
		}
	}
	if p, ok := c.loading[id]; ok {
		c.mu.Unlock()
		<-p.done
		return p.table
	}
	if c.loading == nil {
		c.loading = make(map[fileID]*pendingTable)
	}
	p := &pendingTable{done: make(chan struct{})}
	c.loading[id] = p
	c.mu.Unlock()

	defer func() {
		c.mu.Lock()
		delete(c.loading, id)
		c.entries = append([]cachedTable{{id: id, table: p.table}}, c.entries...)
		c.trimLocked()
		c.mu.Unlock()
		close(p.done)
	}()
	p.table = load(exePath)
	return p.table
}

// trimLocked evicts from the least recently used end until both bounds hold,
// never evicting the most recent entry.
func (c *symbolTableCache) trimLocked() {
	limit := c.limit
	if limit <= 0 {
		limit = maxCachedSymbolTables
	}
	budget := c.maxBytes
	if budget <= 0 {
		budget = maxCachedSymbolBytes
	}
	if len(c.entries) > limit {
		c.entries = c.entries[:limit]
	}
	var total int64
	for i, e := range c.entries {
		total += e.table.approxBytes()
		if i > 0 && total > budget {
			c.entries = c.entries[:i]
			return
		}
	}
}

// len reports how many tables are held.
func (c *symbolTableCache) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

var indexPCLN = loadPCLNIndex

// loadSymbolTable reads whichever symbol source the binary carries, preferring
// Go's pclntab because it survives -ldflags=-s and names generics and methods
// the ELF symbol table renders less usefully.
func loadSymbolTable(exePath string) *symbolTable {
	defer safeelf.RecoverParse("stacktrace.loadSymbolTable")
	raw, _, err := safeelf.OpenRegular(exePath)
	if err != nil {
		return nil
	}
	defer func() { _ = raw.Close() }()
	f, err := elf.NewFile(raw)
	if err != nil {
		return nil
	}

	t := &symbolTable{path: exePath}
	t.id, _ = fileIDOf(raw)

	if idx, ok := indexPCLN(f); ok {
		t.pcln = idx
		t.elfLazy = true
		return t
	}

	if pclntab := f.Section(".gopclntab"); pclntab != nil {
		if text := f.Section(".text"); text != nil {
			if pclnData, derr := safeelf.SectionData(pclntab); derr == nil {
				if tbl, terr := gosym.NewTable(nil, gosym.NewLineTable(pclnData, text.Addr)); terr == nil {
					t.goTable = tbl
					t.goBytes = goTableBytesPerPCLNByte * int64(len(pclnData))
				}
			}
		}
	}

	t.elfSyms = functionSymbols(f)

	if t.goTable == nil && len(t.elfSyms) == 0 {
		return nil
	}
	return t
}

// functionSymbols returns f's named function symbols, sorted by address.
func functionSymbols(f *elf.File) []elf.Symbol {
	if !safeelf.SymbolSectionWithinCap(f, ".symtab") {
		return nil
	}
	syms, err := f.Symbols()
	if err != nil {
		return nil
	}
	var out []elf.Symbol
	for _, s := range syms {
		if elf.ST_TYPE(s.Info) != elf.STT_FUNC || s.Value == 0 || s.Name == "" {
			continue
		}
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Value < out[j].Value })
	return boundSizelessSymbols(out, f.Sections)
}

// boundSizelessSymbols gives each symbol with no size an extent: up to the
// next symbol, and never past the end of its own section. One that ends up
// covering nothing is dropped.
func boundSizelessSymbols(syms []elf.Symbol, sections []*elf.Section) []elf.Symbol {
	out := syms[:0]
	for i, s := range syms {
		if s.Size == 0 {
			end := uint64(0)
			if idx := int(s.Section); idx > 0 && idx < len(sections) {
				sect := sections[idx]
				end = sect.Addr + sect.Size
			}
			if i+1 < len(syms) && (end == 0 || syms[i+1].Value < end) {
				end = syms[i+1].Value
			}
			if end <= s.Value {
				continue
			}
			s.Size = end - s.Value
		}
		out = append(out, s)
	}
	return out
}

// statFileID reads an executable's device and inode through the host view.
func statFileID(path string) (fileID, bool) {
	info, err := hostfs.Stat(path)
	if err != nil {
		return fileID{}, false
	}
	return fileIDFromInfo(info)
}

// fileIDOf reads the identity of an already-open file, so a table can confirm
// the file it is about to read is the one it indexed.
func fileIDOf(f *os.File) (fileID, bool) {
	info, err := f.Stat()
	if err != nil {
		return fileID{}, false
	}
	return fileIDFromInfo(info)
}

func fileIDFromInfo(info os.FileInfo) (fileID, bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fileID{}, false
	}
	return fileID{dev: uint64(st.Dev), ino: st.Ino}, true
}
