package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hobbyquaker/lite-addon-wireguard/internal/wgkeys"
)

func open(t *testing.T) *Store {
	t.Helper()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestOpenMakesAKey(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	c := s.Get()
	if c.Server.ListenPort != DefaultPort || c.Server.Network != DefaultNetwork || !c.Server.Enabled || c.Server.Keepalive != DefaultKeepalive {
		t.Fatalf("defaults: %+v", c.Server)
	}
	if _, err := wgkeys.Parse(c.Server.PrivateKey); err != nil {
		t.Fatal("no key")
	}
	fi, err := os.Stat(filepath.Join(dir, "wireguard.json"))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("file mode: %v %v", err, fi.Mode())
	}
	// opened again: the same key
	s2, err := Open(dir)
	if err != nil || s2.Get().Server.PrivateKey != c.Server.PrivateKey {
		t.Fatal("the key changed on reopen")
	}
	if _, err := ServerAddress(c.Server.Network); err != nil {
		t.Fatal(err)
	}
	if a, _ := ServerAddress("10.77.0.0/24"); a.String() != "10.77.0.1" {
		t.Fatalf("server address %s", a)
	}
}

func TestDevices(t *testing.T) {
	s := open(t)
	var changes int
	s.OnChange = func(Config) { changes++ }
	d, issued, err := s.AddDevice(NewDevice{Name: "Pixel 7"})
	if err != nil {
		t.Fatal(err)
	}
	if d.ID != "pixel-7" || d.Address != "10.77.0.2" || !d.Enabled || d.KeySource != KeySourceSystem || d.PresharedKey == "" {
		t.Fatalf("%+v", d)
	}
	if issued.PrivateKey.IsZero() || issued.PrivateKey.Public().String() != d.PublicKey || issued.PresharedKey.String() != d.PresharedKey {
		t.Fatal("the issued keys do not match the stored device")
	}
	// the private key is nowhere in the file
	b, _ := os.ReadFile(s.Path())
	if strings.Contains(string(b), issued.PrivateKey.String()) {
		t.Fatal("the private key was stored")
	}
	// a second device: the next address, a unique id
	no := false
	d2, issued2, err := s.AddDevice(NewDevice{Name: "Pixel 7", PSK: &no})
	if err != nil || d2.ID != "pixel-7-2" || d2.Address != "10.77.0.3" || d2.PresharedKey != "" || !issued2.PresharedKey.IsZero() {
		t.Fatalf("%v %+v", err, d2)
	}
	// imported
	priv, _ := wgkeys.NewPrivateKey()
	d3, issued3, err := s.AddDevice(NewDevice{Name: "Laptop", KeySource: KeySourceImport, PublicKey: priv.Public().String()})
	if err != nil || d3.KeySource != KeySourceImport || d3.PublicKey != priv.Public().String() || !issued3.PrivateKey.IsZero() || d3.Address != "10.77.0.4" {
		t.Fatalf("%v %+v", err, d3)
	}
	// refusals
	for _, c := range []struct {
		in   NewDevice
		want string
	}{
		{NewDevice{Name: ""}, "name"},
		{NewDevice{Name: strings.Repeat("x", 65)}, "name"},
		{NewDevice{Name: "dup", KeySource: KeySourceImport, PublicKey: priv.Public().String()}, "exists"},
		{NewDevice{Name: "bad", KeySource: KeySourceImport, PublicKey: "nope"}, "public key"},
		{NewDevice{Name: "bad", KeySource: KeySourceImport, PublicKey: priv.String(), PresharedKey: "x"}, "preshared"},
		{NewDevice{Name: "own", KeySource: KeySourceImport, PublicKey: s.ServerKey().Public().String()}, "own public key"},
		{NewDevice{Name: "x", KeySource: "magic"}, "key_source"},
	} {
		if _, _, err := s.AddDevice(c.in); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%+v: got %v, want %q", c.in, err, c.want)
		}
	}
	// update, remove, the freed address is taken again
	if _, err := s.UpdateDevice("pixel-7-2", DeviceUpdate{Name: "Tablet", Enabled: false}); err != nil {
		t.Fatal(err)
	}
	u, _ := s.Device("pixel-7-2")
	if u.Name != "Tablet" || u.Enabled {
		t.Fatalf("%+v", u)
	}
	if _, err := s.UpdateDevice("ghost", DeviceUpdate{Name: "x", Enabled: true}); err != ErrNotFound {
		t.Fatal(err)
	}
	if err := s.RemoveDevice("pixel-7-2"); err != nil {
		t.Fatal(err)
	}
	if err := s.RemoveDevice("pixel-7-2"); err != ErrNotFound {
		t.Fatal(err)
	}
	d4, _, err := s.AddDevice(NewDevice{Name: "Next"})
	if err != nil || d4.Address != "10.77.0.3" {
		t.Fatalf("freed address: %v %s", err, d4.Address)
	}
	if changes < 6 {
		t.Fatalf("OnChange calls: %d", changes)
	}
	// reopen: all there, valid
	s2, err := Open(filepath.Dir(s.Path()))
	if err != nil || len(s2.Get().Devices) != 3 {
		t.Fatalf("reopen: %v", err)
	}
}

func TestServerSettings(t *testing.T) {
	s := open(t)
	if _, _, err := s.AddDevice(NewDevice{Name: "a"}); err != nil {
		t.Fatal(err)
	}
	ok := ServerSettings{Enabled: true, ListenPort: 51821, Network: "10.9.0.0/24", Endpoint: "ccu.example.org", Keepalive: 0}
	if err := s.SetServer(ok); err != nil {
		t.Fatal(err)
	}
	c := s.Get()
	if c.Server.ListenPort != 51821 || c.Server.Network != "10.9.0.0/24" || c.Devices[0].Address != "10.9.0.2" {
		t.Fatalf("%+v %+v", c.Server, c.Devices[0])
	}
	if EndpointFor(c.Server) != "ccu.example.org:51821" {
		t.Fatal(EndpointFor(c.Server))
	}
	c.Server.Endpoint = "ccu.example.org:443"
	if EndpointFor(c.Server) != "ccu.example.org:443" {
		t.Fatal(EndpointFor(c.Server))
	}
	c.Server.Endpoint = "[2001:db8::1]"
	if EndpointFor(c.Server) != "[2001:db8::1]:51821" {
		t.Fatal(EndpointFor(c.Server))
	}
	c.Server.Endpoint = ""
	if EndpointFor(c.Server) != "" {
		t.Fatal("empty endpoint")
	}
	for _, bad := range []ServerSettings{
		{Enabled: true, ListenPort: 80, Network: "10.9.0.0/24"},
		{Enabled: true, ListenPort: 70000, Network: "10.9.0.0/24"},
		{Enabled: true, ListenPort: 51820, Network: "10.9.0.1/24"},
		{Enabled: true, ListenPort: 51820, Network: "10.0.0.0/8"},
		{Enabled: true, ListenPort: 51820, Network: "10.9.0.0/30"},
		{Enabled: true, ListenPort: 51820, Network: "fd00::/64"},
		{Enabled: true, ListenPort: 51820, Network: "10.9.0.0/24", Endpoint: "bad host!"},
		{Enabled: true, ListenPort: 51820, Network: "10.9.0.0/24", Keepalive: -1},
		{Enabled: true, ListenPort: 51820, Network: "10.9.0.0/24", Keepalive: 9999},
	} {
		if err := s.SetServer(bad); err == nil {
			t.Errorf("%+v accepted", bad)
		}
	}
	// the key stays across a settings change; regenerate changes it
	k := s.Get().Server.PrivateKey
	if err := s.SetServer(ServerSettings{Enabled: false, ListenPort: 51820, Network: "10.9.0.0/24"}); err != nil || s.Get().Server.PrivateKey != k {
		t.Fatal("the key changed")
	}
	if err := s.RegenerateServerKey(); err != nil || s.Get().Server.PrivateKey == k {
		t.Fatal("the key did not change")
	}
}

func TestNetworkFull(t *testing.T) {
	s := open(t)
	if err := s.SetServer(ServerSettings{Enabled: true, ListenPort: 51820, Network: "10.9.0.0/29"}); err != nil {
		t.Fatal(err)
	}
	// /29: .1 the server, .2 to .6 devices, .7 the broadcast
	for i := 0; i < 5; i++ {
		if _, _, err := s.AddDevice(NewDevice{Name: "d"}); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := s.AddDevice(NewDevice{Name: "one too many"}); err == nil || !strings.Contains(err.Error(), "full") {
		t.Fatal(err)
	}
	// shrinking the network below the devices is refused
	if err := s.SetServer(ServerSettings{Enabled: true, ListenPort: 51820, Network: "10.9.0.0/30"}); err == nil {
		t.Fatal("a network without room was accepted")
	}
}

func TestBrokenFile(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "wireguard.json"), []byte("{"), 0o600)
	if _, err := Open(dir); err == nil {
		t.Fatal("a broken file opened")
	}
	b, _ := json.Marshal(Config{Server: Server{PrivateKey: "bad", ListenPort: 51820, Network: DefaultNetwork}})
	_ = os.WriteFile(filepath.Join(dir, "wireguard.json"), b, 0o600)
	if _, err := Open(dir); err == nil {
		t.Fatal("a bad key opened")
	}
}
