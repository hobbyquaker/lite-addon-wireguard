// Package addrmap maps the addresses of devices that reach this system through a tunnel whose
// network is not this addon's own - the client mode, where the server hands out its addresses -
// onto addresses of a block this addon declared as its web ingress (10.77.1.0/24), one to one and
// stably. The PROXY header carries the mapped address, so the system's ingress stays narrow (it
// accepts the declared ranges alone), the login lockout and an API token's address ranges keep
// working per device, and the journal shows the mapped address; the page shows the real one next to
// it. The table is kept in a file beside the configuration (in the backup), so a device keeps its
// mapped address across restarts and restores.
//
// The block holds 254 addresses. When it is full, the entry not seen for the longest time is given
// up and its mapped address reused - a device coming back after that gets another address, which
// at worst ends a lockout or token range that was keyed on the old one.
package addrmap

import (
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"sort"
	"sync"
	"time"
)

// Entry is one mapping as the page sees it.
type Entry struct {
	Real     string `json:"real"`
	Mapped   string `json:"mapped"`
	LastSeen int64  `json:"last_seen"`
}

type file struct {
	Block   string  `json:"block"`
	Entries []Entry `json:"entries"`
}

// Table is the mapping.
type Table struct {
	mu       sync.Mutex
	path     string
	block    netip.Prefix
	byReal   map[netip.Addr]*Entry
	byMapped map[netip.Addr]netip.Addr
	now      func() time.Time
}

// Open reads the table at path (none: empty) for the block; a file for another block starts anew.
func Open(path string, block netip.Prefix) (*Table, error) {
	if !block.Addr().Is4() || block.Bits() < 16 || block.Bits() > 30 {
		return nil, errors.New("the block is an IPv4 network of /16 to /30")
	}
	t := &Table{path: path, block: block.Masked(), byReal: map[netip.Addr]*Entry{}, byMapped: map[netip.Addr]netip.Addr{}, now: time.Now}
	b, err := os.ReadFile(path)
	if err == nil {
		var f file
		if json.Unmarshal(b, &f) == nil && f.Block == t.block.String() {
			for i := range f.Entries {
				e := f.Entries[i]
				r, err1 := netip.ParseAddr(e.Real)
				m, err2 := netip.ParseAddr(e.Mapped)
				if err1 != nil || err2 != nil || !t.block.Contains(m) {
					continue
				}
				if _, dup := t.byMapped[m]; dup {
					continue
				}
				t.byReal[r] = &Entry{Real: e.Real, Mapped: e.Mapped, LastSeen: e.LastSeen}
				t.byMapped[m] = r
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return t, nil
}

// Capacity is the number of addresses the block offers (its hosts without the network and the
// broadcast address).
func (t *Table) Capacity() int { return (1 << (32 - t.block.Bits())) - 2 }

// Block is the mapped block.
func (t *Table) Block() netip.Prefix { return t.block }

// Map answers the mapped address of real, assigning the lowest free one when it is new (and
// evicting the stalest entry when the block is full), and notes the moment.
func (t *Table) Map(real netip.Addr) netip.Addr {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now().UnixMilli()
	if e, ok := t.byReal[real]; ok {
		e.LastSeen = now
		t.save()
		return netip.MustParseAddr(e.Mapped)
	}
	if len(t.byReal) >= t.Capacity() {
		var stalest netip.Addr
		var oldest int64 = 1<<63 - 1
		for r, e := range t.byReal {
			if e.LastSeen < oldest {
				oldest, stalest = e.LastSeen, r
			}
		}
		if e := t.byReal[stalest]; e != nil {
			delete(t.byMapped, netip.MustParseAddr(e.Mapped))
			delete(t.byReal, stalest)
		}
	}
	base := t.block.Addr().As4()
	v := uint32(base[0])<<24 | uint32(base[1])<<16 | uint32(base[2])<<8 | uint32(base[3])
	for n := uint32(1); int(n) <= t.Capacity(); n++ {
		x := v + n
		m := netip.AddrFrom4([4]byte{byte(x >> 24), byte(x >> 16), byte(x >> 8), byte(x)})
		if _, taken := t.byMapped[m]; taken {
			continue
		}
		t.byReal[real] = &Entry{Real: real.String(), Mapped: m.String(), LastSeen: now}
		t.byMapped[m] = real
		t.save()
		return m
	}
	// cannot happen: the eviction made room
	return netip.Addr{}
}

// Entries answers the table, most recently seen first.
func (t *Table) Entries() []Entry {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]Entry, 0, len(t.byReal))
	for _, e := range t.byReal {
		out = append(out, *e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeen > out[j].LastSeen })
	return out
}

// save writes the file (the caller holds the lock); a failure is kept silent - the mapping goes on
// in memory and is written again next time.
func (t *Table) save() {
	if t.path == "" {
		return
	}
	f := file{Block: t.block.String()}
	for _, e := range t.byReal {
		f.Entries = append(f.Entries, *e)
	}
	sort.Slice(f.Entries, func(i, j int) bool { return f.Entries[i].Mapped < f.Entries[j].Mapped })
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return
	}
	tmp := t.path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return
	}
	_ = os.Rename(tmp, t.path)
}
