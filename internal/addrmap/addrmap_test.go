package addrmap

import (
	"net/netip"
	"path/filepath"
	"testing"
	"time"
)

func TestTable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "addrmap.json")
	block := netip.MustParsePrefix("10.77.1.0/24")
	tb, err := Open(path, block)
	if err != nil {
		t.Fatal(err)
	}
	if tb.Capacity() != 254 {
		t.Fatal(tb.Capacity())
	}
	a := tb.Map(netip.MustParseAddr("10.8.0.3"))
	b := tb.Map(netip.MustParseAddr("192.168.50.7"))
	if a.String() != "10.77.1.1" || b.String() != "10.77.1.2" {
		t.Fatalf("%s %s", a, b)
	}
	if tb.Map(netip.MustParseAddr("10.8.0.3")) != a {
		t.Fatal("not stable")
	}
	// persisted: the same mapping after a reopen
	tb2, err := Open(path, block)
	if err != nil || tb2.Map(netip.MustParseAddr("192.168.50.7")) != b || tb2.Map(netip.MustParseAddr("10.8.0.3")) != a || len(tb2.Entries()) != 2 {
		t.Fatalf("reopen: %v", err)
	}
	// another block starts anew
	tb3, _ := Open(path, netip.MustParsePrefix("10.77.2.0/24"))
	if tb3.Map(netip.MustParseAddr("10.8.0.3")).String() != "10.77.2.1" {
		t.Fatal("a new block kept the old table")
	}
	// full: the stalest goes
	small, _ := Open("", netip.MustParsePrefix("10.77.3.0/30"))
	clock := time.Unix(1000, 0)
	small.now = func() time.Time { clock = clock.Add(time.Second); return clock }
	x := small.Map(netip.MustParseAddr("10.8.0.1"))
	y := small.Map(netip.MustParseAddr("10.8.0.2"))
	if x.String() != "10.77.3.1" || y.String() != "10.77.3.2" || small.Capacity() != 2 {
		t.Fatalf("%s %s %d", x, y, small.Capacity())
	}
	small.Map(netip.MustParseAddr("10.8.0.1")) // seen again: .2 is the stalest now
	z := small.Map(netip.MustParseAddr("10.8.0.9"))
	if z != y {
		t.Fatalf("the stalest was not reused: %s", z)
	}
	if small.Map(netip.MustParseAddr("10.8.0.2")) != x && small.Map(netip.MustParseAddr("10.8.0.2")) != y {
		t.Fatal("an evicted device gets an address again")
	}
	if _, err := Open("", netip.MustParsePrefix("10.0.0.0/8")); err == nil {
		t.Fatal("a /8 block accepted")
	}
}
