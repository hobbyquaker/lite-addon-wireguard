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
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
