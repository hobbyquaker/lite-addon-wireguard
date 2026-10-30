package tunnel

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"github.com/hobbyquaker/lite-addon-wireguard/internal/config"
	"github.com/hobbyquaker/lite-addon-wireguard/internal/fakesys"
	"github.com/hobbyquaker/lite-addon-wireguard/internal/wgkeys"
)

// freeUDPPort finds a UDP port to listen on.
func freeUDPPort(t *testing.T) int {
	t.Helper()
	c, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := c.LocalAddr().(*net.UDPAddr).Port
	c.Close()
	return p
}

// peer is a second, independent wireguard-go with its own netstack: the "phone".
type peer struct {
	dev  *device.Device
	tnet *netstack.Net
}

func newPeer(t *testing.T, priv wgkeys.Key, addr string, serverPub wgkeys.Key, psk wgkeys.Key, endpoint string, allowed string) *peer {
	t.Helper()
	tdev, tnet, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr(addr)}, nil, 1420)
	if err != nil {
		t.Fatal(err)
	}
	dev := device.NewDevice(tdev, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, "peer "))
	cfg := fmt.Sprintf("private_key=%s\npublic_key=%s\nendpoint=%s\nallowed_ip=%s\npersistent_keepalive_interval=5\n", priv.Hex(), serverPub.Hex(), endpoint, allowed)
	if !psk.IsZero() {
		cfg = strings.Replace(cfg, "endpoint=", "preshared_key="+psk.Hex()+"\nendpoint=", 1)
	}
	if err := dev.IpcSet(cfg); err != nil {
		t.Fatal(err)
	}
	if err := dev.Up(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(dev.Close)
	return &peer{dev: dev, tnet: tnet}
}

func (p *peer) get(t *testing.T, url string) (*http.Response, string) {
	t.Helper()
	cl := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		return p.tnet.DialContext(ctx, network, addr)
	}}, Timeout: 15 * time.Second}
	res, err := cl.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res, string(b)
}

// The whole path: a device's tunnel ends in the addon's netstack, its request to the system's
// tunnel address goes to the ingress stub with a PROXY header naming the device's tunnel address,
// and the status shows the handshake and the traffic. A second device whose key is not configured
// never gets through; a disabled device neither.
func TestTunnelEndToEnd(t *testing.T) {
	dir := t.TempDir()
	store, err := config.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	port := freeUDPPort(t)
	if err := store.SetServer(config.ServerSettings{Enabled: true, ListenPort: port, Network: "10.77.0.0/24", Endpoint: "127.0.0.1", Keepalive: 25}); err != nil {
		t.Fatal(err)
	}
	d, issued, err := store.AddDevice(config.NewDevice{Name: "phone"})
	if err != nil {
		t.Fatal(err)
	}
	stub, err := fakesys.ListenProxyStub(filepath.Join(t.TempDir(), "proxy.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer stub.Close()
	var lines []string
	tun := New(Options{Socket: stub.Path, Log: func(f string, a ...any) { lines = append(lines, fmt.Sprintf(f, a...)) }})
	defer tun.Close()
	if err := tun.Apply(store.Get()); err != nil {
		t.Fatal(err)
	}
	st := tun.Status()
	if !st.Running || st.ListenPort != port || st.Address != "10.77.0.1" || st.PublicKey != store.ServerKey().Public().String() {
		t.Fatalf("status %+v", st)
	}

	phone := newPeer(t, issued.PrivateKey, d.Address, store.ServerKey().Public(), issued.PresharedKey, fmt.Sprintf("127.0.0.1:%d", port), "10.77.0.1/32")
	res, body := phone.get(t, "http://10.77.0.1/api/x")
	if res.StatusCode != 200 || res.Header.Get("X-Claimed-Address") != "10.77.0.2" || !strings.Contains(body, `"remote":"10.77.0.2"`) {
		t.Fatalf("through the tunnel: %d %s %s", res.StatusCode, res.Header.Get("X-Claimed-Address"), body)
	}
	if got := stub.Claimed(); len(got) != 1 || got[0].Addr().String() != "10.77.0.2" || got[0].Port() == 0 {
		t.Fatalf("claimed %v", got)
	}
	st = tun.Status()
	p, ok := st.Peers[d.PublicKey]
	if !ok || p.LastHandshake == 0 || p.RxBytes == 0 || p.TxBytes == 0 || !strings.HasPrefix(p.Endpoint, "127.0.0.1:") || st.Forwarded != 1 {
		t.Fatalf("peer status %+v forwarded %d", p, st.Forwarded)
	}

	// a device the server does not know: no handshake, the request fails
	stranger, _ := wgkeys.NewPrivateKey()
	s2 := newPeer(t, stranger, "10.77.0.9", store.ServerKey().Public(), wgkeys.Key{}, fmt.Sprintf("127.0.0.1:%d", port), "10.77.0.1/32")
	cl := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		return s2.tnet.DialContext(ctx, network, addr)
	}}, Timeout: 3 * time.Second}
	if _, err := cl.Get("http://10.77.0.1/"); err == nil {
		t.Fatal("a stranger got through")
	}

	// the device disabled: its peer is gone, the next request times out; enabled again: works
	if _, err := store.UpdateDevice(d.ID, config.DeviceUpdate{Name: d.Name, Enabled: false}); err != nil {
		t.Fatal(err)
	}
	if err := tun.Apply(store.Get()); err != nil {
		t.Fatal(err)
	}
	if _, ok := tun.Status().Peers[d.PublicKey]; ok {
		t.Fatal("a disabled device is still a peer")
	}
	cl2 := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		return phone.tnet.DialContext(ctx, network, addr)
	}}, Timeout: 3 * time.Second}
	if _, err := cl2.Get("http://10.77.0.1/"); err == nil {
		t.Fatal("a disabled device got through")
	}
	if _, err := store.UpdateDevice(d.ID, config.DeviceUpdate{Name: d.Name, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := tun.Apply(store.Get()); err != nil {
		t.Fatal(err)
	}
	// the app reconnects (a fresh handshake; the old session's keys are gone on the server side
	// and WireGuard's own rekey after a silence takes a while)
	phone2 := newPeer(t, issued.PrivateKey, d.Address, store.ServerKey().Public(), issued.PresharedKey, fmt.Sprintf("127.0.0.1:%d", port), "10.77.0.1/32")
	res, _ = phone2.get(t, "http://10.77.0.1/again")
	if res.StatusCode != 200 || res.Header.Get("X-Claimed-Address") != "10.77.0.2" {
		t.Fatalf("enabled again: %d", res.StatusCode)
	}
	// a second device added: the first one's session is untouched - its next request needs no
	// handshake and answers at once
	_, issued3, err := store.AddDevice(config.NewDevice{Name: "laptop"})
	if err != nil {
		t.Fatal(err)
	}
	if err := tun.Apply(store.Get()); err != nil {
		t.Fatal(err)
	}
	fast := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		return phone2.tnet.DialContext(ctx, network, addr)
	}}, Timeout: 3 * time.Second}
	if res, err := fast.Get("http://10.77.0.1/still"); err != nil || res.StatusCode != 200 {
		t.Fatalf("the first device after a second was added: %v", err)
	}
	_ = issued3

	// the server switched off: down, no port; on again: up
	if err := store.SetServer(config.ServerSettings{Enabled: false, ListenPort: port, Network: "10.77.0.0/24", Endpoint: "127.0.0.1", Keepalive: 25}); err != nil {
		t.Fatal(err)
	}
	if err := tun.Apply(store.Get()); err != nil || tun.Status().Running {
		t.Fatalf("off: %v %+v", err, tun.Status())
	}
	if err := store.SetServer(config.ServerSettings{Enabled: true, ListenPort: port, Network: "10.77.0.0/24", Endpoint: "127.0.0.1", Keepalive: 25}); err != nil {
		t.Fatal(err)
	}
	if err := tun.Apply(store.Get()); err != nil || !tun.Status().Running {
		t.Fatalf("on: %v", err)
	}
	if len(lines) == 0 {
		t.Fatal("nothing logged")
	}
}

// The port in use: Apply reports it, the status carries it, the tunnel stays down.
func TestTunnelPortInUse(t *testing.T) {
	c, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	port := c.LocalAddr().(*net.UDPAddr).Port
	// wireguard-go binds 0.0.0.0 and [::], so a socket on 127.0.0.1 alone may not clash; bind
	// both to be sure
	c6, err := net.ListenPacket("udp6", fmt.Sprintf("[::]:%d", port))
	if err != nil {
		t.Skip("no IPv6 or the port is taken differently")
	}
	defer c6.Close()
	store, _ := config.Open(t.TempDir())
	_ = store.SetServer(config.ServerSettings{Enabled: true, ListenPort: port, Network: "10.77.0.0/24"})
	tun := New(Options{Socket: "/nonexistent"})
	defer tun.Close()
	err = tun.Apply(store.Get())
	st := tun.Status()
	if err == nil || st.Running || st.Error == "" {
		t.Fatalf("port in use: err %v, status %+v", err, st)
	}
}

func TestParsePeers(t *testing.T) {
	out := "private_key=aa\nlisten_port=51820\npublic_key=0011\nendpoint=1.2.3.4:5\nlast_handshake_time_sec=1700000000\nlast_handshake_time_nsec=500000000\ntx_bytes=10\nrx_bytes=20\nprotocol_version=1\npublic_key=2233\nlast_handshake_time_sec=0\nlast_handshake_time_nsec=0\ntx_bytes=0\nrx_bytes=0\nerrno=0\n"
	p := parsePeers(out)
	if len(p) != 2 || p["0011"].Endpoint != "1.2.3.4:5" || p["0011"].LastHandshake != 1700000000500 || p["0011"].TxBytes != 10 || p["0011"].RxBytes != 20 || p["2233"].LastHandshake != 0 {
		t.Fatalf("%+v", p)
	}
}
