// Package peer runs the official WireGuard tools as the peer: wireguard-go and wg-quick in an
// Alpine container (--network host, NET_ADMIN and /dev/net/tun for the container's own tunnel
// interface) connect to the addon's tunnel on the host's loopback, and curl fetches a page through
// it from the ingress stub, which answers with the address the addon claimed. Needs docker and the
// network (apk); run with WG_DOCKER=1.
package peer

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hobbyquaker/lite-addon-wireguard/internal/addrmap"
	"github.com/hobbyquaker/lite-addon-wireguard/internal/config"
	"github.com/hobbyquaker/lite-addon-wireguard/internal/fakesys"
	"github.com/hobbyquaker/lite-addon-wireguard/internal/tunnel"
	"github.com/hobbyquaker/lite-addon-wireguard/internal/wgkeys"
)

func TestRealPeerInDocker(t *testing.T) {
	if os.Getenv("WG_DOCKER") == "" {
		t.Skip("WG_DOCKER=1 runs the official WireGuard tools in a container as the peer")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("no docker")
	}
	dir := t.TempDir()
	store, err := config.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	c, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := c.LocalAddr().(*net.UDPAddr).Port
	c.Close()
	if err := store.SetServer(config.ServerSettings{Enabled: true, ListenPort: port, Network: "10.77.0.0/24", Endpoint: "127.0.0.1", Keepalive: 25}); err != nil {
		t.Fatal(err)
	}
	d, issued, err := store.AddDevice(config.NewDevice{Name: "container"})
	if err != nil {
		t.Fatal(err)
	}
	stub, err := fakesys.ListenProxyStub(filepath.Join(dir, "proxy.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer stub.Close()
	tun := tunnel.New(tunnel.Options{Socket: stub.Path, Log: t.Logf})
	defer tun.Close()
	if err := tun.Apply(store.Get()); err != nil {
		t.Fatal(err)
	}
	// the device's configuration as the page would hand it out
	cc := wgkeys.ClientConfig{PrivateKey: issued.PrivateKey, Address: d.Address + "/32", ServerPublicKey: store.ServerKey().Public(), PresharedKey: issued.PresharedKey, Endpoint: fmt.Sprintf("127.0.0.1:%d", port), AllowedIPs: "10.77.0.1/32", Keepalive: 25}
	conf := cc.Render()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	script := `set -e
apk add --no-cache wireguard-tools wireguard-go iproute2 curl openresolv >/tmp/apk.log 2>&1 || { cat /tmp/apk.log; exit 1; }
mkdir -p /etc/wireguard
cat >/etc/wireguard/wgtest.conf <<'EOF'
` + conf + `EOF
chmod 600 /etc/wireguard/wgtest.conf
export WG_QUICK_USERSPACE_IMPLEMENTATION=wireguard-go
export WG_SUDO=1
wg-quick up wgtest
sleep 1
echo "--- wg show"
wg show wgtest
echo "--- curl through the tunnel"
curl -sS -m 20 -D /tmp/headers http://10.77.0.1/api/ping
echo
cat /tmp/headers
echo "--- a second request on the same tunnel"
curl -sS -m 20 http://10.77.0.1/second
echo
echo "--- wg show after"
wg show wgtest transfer
wg-quick down wgtest
`
	args := []string{"run", "--rm", "-i", "--network", "host", "--cap-add", "NET_ADMIN", "--device", "/dev/net/tun"}
	if img := os.Getenv("ALPINE_IMAGE"); img != "" {
		args = append(args, img)
	} else {
		args = append(args, "alpine:3.22")
	}
	args = append(args, "sh", "-s")
	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.CombinedOutput()
	t.Logf("container:\n%s", out)
	if err != nil {
		t.Fatalf("the container: %v", err)
	}
	if !strings.Contains(string(out), `"remote":"10.77.0.2"`) || !strings.Contains(string(out), "X-Claimed-Address: 10.77.0.2") {
		t.Fatal("the stub did not see the device's tunnel address")
	}
	if !strings.Contains(string(out), "latest handshake") {
		t.Fatal("wg show reports no handshake")
	}
	claimed := stub.Claimed()
	if len(claimed) < 2 || claimed[0].Addr().String() != "10.77.0.2" {
		t.Fatalf("claimed %v", claimed)
	}
	st := tun.Status()
	p, ok := st.Peers[d.PublicKey]
	if !ok || p.LastHandshake == 0 || p.RxBytes == 0 || !strings.HasPrefix(p.Endpoint, "127.0.0.1:") {
		t.Fatalf("peer status %+v", p)
	}
}

// The client mode against the official tools: the container runs the WireGuard server (wg-quick
// with a ListenPort and this system as its peer), the addon connects to it, and curl from the
// server's side reaches the ingress stub - with the server's address mapped into the declared
// block.
func TestRealServerInDocker(t *testing.T) {
	if os.Getenv("WG_DOCKER") == "" {
		t.Skip("WG_DOCKER=1 runs the official WireGuard tools in a container as the server")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("no docker")
	}
	dir := t.TempDir()
	store, err := config.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	c, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := c.LocalAddr().(*net.UDPAddr).Port
	c.Close()
	serverPriv, _ := wgkeys.NewPrivateKey()
	ourPriv, _ := wgkeys.NewPrivateKey()
	psk, _ := wgkeys.NewPresharedKey()
	// what the server's administrator would hand this system
	conf := fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = 10.8.0.5/32\n\n[Peer]\nPublicKey = %s\nPresharedKey = %s\nEndpoint = 127.0.0.1:%d\nAllowedIPs = 10.8.0.0/24\nPersistentKeepalive = 5\n", ourPriv, serverPriv.Public(), psk, port)
	if err := store.ImportClient(conf); err != nil {
		t.Fatal(err)
	}
	stub, err := fakesys.ListenProxyStub(filepath.Join(dir, "proxy.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer stub.Close()
	amap, err := addrmap.Open(filepath.Join(dir, "addrmap.json"), netip.MustParsePrefix(config.MappedBlock))
	if err != nil {
		t.Fatal(err)
	}
	tun := tunnel.New(tunnel.Options{Socket: stub.Path, Log: t.Logf, Declared: []netip.Prefix{netip.MustParsePrefix(config.DefaultNetwork)}, Map: amap})
	defer tun.Close()
	// the server comes up in the container first; the tunnel is applied while the container waits
	serverConf := fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = 10.8.0.1/24\nListenPort = %d\n\n[Peer]\nPublicKey = %s\nPresharedKey = %s\nAllowedIPs = 10.8.0.5/32\n", serverPriv, port, ourPriv.Public(), psk)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	script := `set -e
apk add --no-cache wireguard-tools wireguard-go iproute2 curl openresolv >/tmp/apk.log 2>&1 || { cat /tmp/apk.log; exit 1; }
mkdir -p /etc/wireguard
cat >/etc/wireguard/wgsrv.conf <<'EOF'
` + serverConf + `EOF
chmod 600 /etc/wireguard/wgsrv.conf
export WG_QUICK_USERSPACE_IMPLEMENTATION=wireguard-go WG_SUDO=1
wg-quick up wgsrv
echo SERVER-UP
# the client connects within the next seconds (its keepalive); wait for the handshake
for i in $(seq 1 30); do wg show wgsrv latest-handshakes | grep -qv '\s0$' && break; sleep 1; done
echo "--- wg show"
wg show wgsrv
echo "--- curl from the server's side through the tunnel"
curl -sS -m 20 -D /tmp/headers http://10.8.0.5/api/ping
echo
cat /tmp/headers
curl -sS -m 20 http://10.8.0.5/second
echo
wg-quick down wgsrv
`
	args := []string{"run", "--rm", "-i", "--network", "host", "--cap-add", "NET_ADMIN", "--device", "/dev/net/tun"}
	if img := os.Getenv("ALPINE_IMAGE"); img != "" {
		args = append(args, img)
	} else {
		args = append(args, "alpine:3.22")
	}
	args = append(args, "sh", "-s")
	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Stdin = strings.NewReader(script)
	var out strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	// the tunnel's first handshake attempt happens on apply; the server may not be up yet, so the
	// keepalive (5 s) carries the retries
	if err := tun.Apply(store.Get()); err != nil {
		t.Fatal(err)
	}
	err = cmd.Wait()
	t.Logf("container:\n%s", out.String())
	if err != nil {
		t.Fatalf("the container: %v", err)
	}
	s := out.String()
	if !strings.Contains(s, `"remote":"10.77.1.1"`) || !strings.Contains(s, "X-Claimed-Address: 10.77.1.1") {
		t.Fatal("the stub did not see the mapped address 10.77.1.1")
	}
	st := tun.Status()
	if st.Client == nil || st.Client.LastHandshake == 0 || len(st.Mapped) != 1 || st.Mapped[0].Real != "10.8.0.1" {
		t.Fatalf("status %+v mapped %+v", st.Client, st.Mapped)
	}
}
