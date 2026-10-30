// Package tunnel is the WireGuard end on the system: wireguard-go with its gVisor netstack, so no
// TUN device, no kernel interface, no route and no capability - the tunnel ends inside this
// process. It applies the configuration (the key, the port, the devices as peers), accepts TCP on
// the system's tunnel address, port 80, and hands every connection to the web server's PROXY
// Unix socket with the device's tunnel address in front, so lighttpd and the system see the
// device, not the loopback. It reports every peer's handshake, endpoint and traffic from the
// device's UAPI.
package tunnel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"github.com/hobbyquaker/lite-addon-wireguard/internal/addrmap"
	"github.com/hobbyquaker/lite-addon-wireguard/internal/config"
	"github.com/hobbyquaker/lite-addon-wireguard/internal/proxyproto"
	"github.com/hobbyquaker/lite-addon-wireguard/internal/wgkeys"
)

// DefaultSocket is the web server's PROXY-protocol Unix socket on openccu-lite.
const DefaultSocket = "/run/lighttpd-addons/wireguard/proxy.sock"

// WebPort is the port the devices reach the web server on, inside the tunnel.
const WebPort = 80

// Options configure the tunnel.
type Options struct {
	// Socket is the web server's PROXY socket (DefaultSocket).
	Socket string
	// Log takes the tunnel's lines.
	Log func(format string, args ...any)
	// MTU of the tunnel interface, 1420 by default.
	MTU int
	// DialTimeout for the socket, 5 s by default.
	DialTimeout time.Duration
	// Declared are the address ranges the addon's manifest declares for its ingress: a device
	// whose address lies in one of them is claimed as it is. Any other address - the client
	// mode's, where the server hands out its own network - is mapped into Map's block.
	Declared []netip.Prefix
	// Map is the address table for the devices outside Declared (nil: no mapping, every address
	// is claimed as it is - the tests' default).
	Map *addrmap.Table
}

// Mapping is one device as the page sees it in the client mode: its real tunnel address, the
// address the system sees, and the open connections.
type Mapping struct {
	addrmap.Entry
	Connections int `json:"connections"`
}

// PeerStatus is one device as the WireGuard device sees it.
type PeerStatus struct {
	// Endpoint is the device's public address and port, as last seen ("" before any packet).
	Endpoint string `json:"endpoint,omitempty"`
	// LastHandshake is unix milliseconds of the newest handshake, 0 for none.
	LastHandshake int64 `json:"last_handshake"`
	RxBytes       int64 `json:"rx_bytes"`
	TxBytes       int64 `json:"tx_bytes"`
	// Connections is the number of web connections open through the tunnel right now.
	Connections int `json:"connections"`
}

// Status is the tunnel's state.
type Status struct {
	// Running: the device is up and listening.
	Running bool `json:"running"`
	// Error: why it is not (the port in use, say); "" when running or switched off.
	Error string `json:"error,omitempty"`
	// ListenPort is the UDP port in use.
	ListenPort int `json:"listen_port"`
	// Address is the system's tunnel address.
	Address string `json:"address"`
	// PublicKey is the system's public key.
	PublicKey string `json:"public_key"`
	// Peers by the device's public key.
	Peers map[string]PeerStatus `json:"peers"`
	// Connections is the number of web connections open through the tunnel.
	Connections int `json:"connections"`
	// Forwarded is the number of web connections handed to the web server since the start.
	Forwarded int64 `json:"forwarded"`
	// SocketOK says whether the web server's socket could be reached the last time a device
	// connected (nil: not tried yet).
	SocketError string `json:"socket_error,omitempty"`
	// Since is unix milliseconds of the device's start.
	Since int64 `json:"since,omitempty"`
	// Mode is server or client.
	Mode string `json:"mode"`
	// Client is the server peer's state in the client mode (nil in the server mode).
	Client *PeerStatus `json:"client,omitempty"`
	// Mapped are the devices whose addresses are mapped into the declared block (the client mode),
	// most recently seen first.
	Mapped []Mapping `json:"mapped,omitempty"`
}

// Tunnel is the WireGuard end.
type Tunnel struct {
	o  Options
	mu sync.Mutex
	// the running device
	dev   *device.Device
	tnet  *netstack.Net
	tdev  tun.Device
	ln    net.Listener
	cfg   config.Config
	since time.Time
	err   string
	// peers is the set configured on the device, by public key (hex), with the UAPI lines each
	// was set with: a change is applied per peer, never with replace_peers, so that a new or
	// disabled device never drops the other devices' sessions
	peers map[string]string
	// counters
	open      map[netip.Addr]*int32
	openMu    sync.Mutex
	forwarded atomic.Int64
	sockErr   atomic.Value // string
	closed    bool
}

// New makes a tunnel that is not running yet; Apply starts it.
func New(o Options) *Tunnel {
	if o.Socket == "" {
		o.Socket = DefaultSocket
	}
	if o.Log == nil {
		o.Log = func(string, ...any) {}
	}
	if o.MTU == 0 {
		o.MTU = 1420
	}
	if o.DialTimeout == 0 {
		o.DialTimeout = 5 * time.Second
	}
	t := &Tunnel{o: o, open: map[netip.Addr]*int32{}, peers: map[string]string{}}
	t.sockErr.Store("")
	return t
}

// Apply brings the tunnel to the configuration: off when the server is disabled; a new device
// when the key, the port or the network changed; otherwise the peers are replaced in place. The
// error is also kept in the status; Apply itself never panics the caller's loop.
func (t *Tunnel) Apply(c config.Config) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return errors.New("closed")
	}
	if !c.Server.Enabled || (c.IsClient() && c.Client == nil) {
		t.stopLocked()
		t.cfg = c
		t.err = ""
		return nil
	}
	needNew := t.dev == nil || t.cfg.IsClient() != c.IsClient() || identity(t.cfg) != identity(c)
	if needNew {
		t.stopLocked()
		if err := t.startLocked(c); err != nil {
			t.err = err.Error()
			t.cfg = c
			t.o.Log("tunnel: %v", err)
			return err
		}
	}
	want := peerLines(c)
	if uapi := peersDelta(t.peers, want); uapi != "" {
		if i := strings.Index(uapi, "endpoint_error="); i >= 0 {
			msg := uapi[i+len("endpoint_error="):]
			msg = msg[:strings.IndexByte(msg, '\n')]
			t.err = "the server's endpoint: " + msg
			t.cfg = c
			t.o.Log("tunnel: %s", t.err)
			return errors.New(t.err)
		}
		if err := t.dev.IpcSet(uapi); err != nil {
			t.err = err.Error()
			t.cfg = c
			t.o.Log("tunnel: peers: %v", err)
			return err
		}
	}
	t.peers = want
	t.cfg = c
	t.err = ""
	return nil
}

// identity is what a new device is needed for: the key, the address and the port of the mode.
func identity(c config.Config) string {
	if c.IsClient() && c.Client != nil {
		return "client|" + c.Client.PrivateKey + "|" + c.Client.Address
	}
	return fmt.Sprintf("server|%s|%d|%s", c.Server.PrivateKey, c.Server.ListenPort, c.Server.Network)
}

func (t *Tunnel) startLocked(c config.Config) error {
	var addr netip.Addr
	var priv wgkeys.Key
	var err error
	if c.IsClient() {
		addr, err = netip.ParseAddr(c.Client.Address)
		if err != nil {
			return fmt.Errorf("client address: %w", err)
		}
		if priv, err = wgkeys.Parse(c.Client.PrivateKey); err != nil {
			return fmt.Errorf("client private key: %w", err)
		}
	} else {
		if addr, err = config.ServerAddress(c.Server.Network); err != nil {
			return err
		}
		if priv, err = wgkeys.Parse(c.Server.PrivateKey); err != nil {
			return fmt.Errorf("private key: %w", err)
		}
	}
	tdev, tnet, err := netstack.CreateNetTUN([]netip.Addr{addr}, nil, t.o.MTU)
	if err != nil {
		return fmt.Errorf("netstack: %w", err)
	}
	logger := &device.Logger{
		Verbosef: func(string, ...any) {},
		Errorf:   func(format string, args ...any) { t.o.Log("wireguard: "+format, args...) },
	}
	dev := device.NewDevice(tdev, conn.NewDefaultBind(), logger)
	uapi := fmt.Sprintf("private_key=%s\n", priv.Hex())
	if !c.IsClient() {
		uapi += fmt.Sprintf("listen_port=%d\n", c.Server.ListenPort)
	}
	if err := dev.IpcSet(uapi); err != nil {
		dev.Close()
		return fmt.Errorf("listen on UDP %d: %w", c.Server.ListenPort, cleanIpcErr(err))
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return fmt.Errorf("up: %w", err)
	}
	ln, err := tnet.ListenTCP(&net.TCPAddr{IP: addr.AsSlice(), Port: WebPort})
	if err != nil {
		dev.Close()
		return fmt.Errorf("listen on %s:%d in the tunnel: %w", addr, WebPort, err)
	}
	t.dev, t.tnet, t.tdev, t.ln = dev, tnet, tdev, ln
	t.since = time.Now()
	go t.accept(ln)
	if c.IsClient() {
		t.o.Log("tunnel up as a client: %s, the server %s, the web server through %s", addr, c.Client.Endpoint, t.o.Socket)
	} else {
		t.o.Log("tunnel up: %s on UDP %d, the web server through %s", addr, c.Server.ListenPort, t.o.Socket)
	}
	return nil
}

func cleanIpcErr(err error) error {
	s := err.Error()
	if i := strings.Index(s, ": "); i >= 0 && strings.HasPrefix(s, "IPC error") {
		return errors.New(s[i+2:])
	}
	return err
}

func (t *Tunnel) stopLocked() {
	if t.dev == nil {
		return
	}
	if t.ln != nil {
		t.ln.Close()
	}
	t.dev.Close() // closes the tun too
	t.dev, t.tnet, t.tdev, t.ln = nil, nil, nil, nil
	t.peers = map[string]string{}
	t.o.Log("tunnel down")
}

// Close stops the tunnel for good.
func (t *Tunnel) Close() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.stopLocked()
	t.closed = true
}

// peerLines is the UAPI block of every enabled device, by its public key (hex) - or, in the client
// mode, of the one server peer, with its endpoint resolved now.
func peerLines(c config.Config) map[string]string {
	out := map[string]string{}
	if c.IsClient() {
		if c.Client == nil {
			return out
		}
		pub, err := wgkeys.Parse(c.Client.PeerPublicKey)
		if err != nil {
			return out
		}
		var b strings.Builder
		fmt.Fprintf(&b, "public_key=%s\n", pub.Hex())
		if c.Client.PresharedKey != "" {
			if psk, err := wgkeys.Parse(c.Client.PresharedKey); err == nil {
				fmt.Fprintf(&b, "preshared_key=%s\n", psk.Hex())
			}
		}
		if ep, err := resolveEndpoint(c.Client.Endpoint); err == nil {
			fmt.Fprintf(&b, "endpoint=%s\n", ep)
		} else {
			// the name does not resolve right now: no endpoint, the peer waits; the caller sees the
			// error in Apply's result through peersDelta's check below
			fmt.Fprintf(&b, "endpoint_error=%s\n", err.Error())
		}
		b.WriteString("replace_allowed_ips=true\n")
		for _, a := range c.Client.AllowedIPs {
			if !strings.Contains(a, "/") {
				a += "/32"
			}
			fmt.Fprintf(&b, "allowed_ip=%s\n", a)
		}
		if c.Client.Keepalive > 0 {
			fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", c.Client.Keepalive)
		}
		out[pub.Hex()] = b.String()
		return out
	}
	for _, d := range c.Devices {
		if !d.Enabled {
			continue
		}
		pub, err := wgkeys.Parse(d.PublicKey)
		if err != nil {
			continue
		}
		var b strings.Builder
		fmt.Fprintf(&b, "public_key=%s\n", pub.Hex())
		if d.PresharedKey != "" {
			if psk, err := wgkeys.Parse(d.PresharedKey); err == nil {
				fmt.Fprintf(&b, "preshared_key=%s\n", psk.Hex())
			}
		}
		fmt.Fprintf(&b, "replace_allowed_ips=true\nallowed_ip=%s/32\n", d.Address)
		out[pub.Hex()] = b.String()
	}
	return out
}

// peersDelta is the UAPI text that takes the device from have to want: peers that are gone are
// removed, new or changed ones set; an unchanged peer is not touched, so its session stays.
func peersDelta(have, want map[string]string) string {
	var b strings.Builder
	for k := range have {
		if _, ok := want[k]; !ok {
			fmt.Fprintf(&b, "public_key=%s\nremove=true\n", k)
		}
	}
	keys := make([]string, 0, len(want))
	for k := range want {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if have[k] != want[k] {
			b.WriteString(want[k])
		}
	}
	return b.String()
}

// resolveEndpoint turns "name-or-address:port" into "ip:port" (wireguard-go takes no name).
func resolveEndpoint(ep string) (string, error) {
	ua, err := net.ResolveUDPAddr("udp", ep)
	if err != nil {
		return "", err
	}
	if ua.IP == nil {
		return "", fmt.Errorf("%s has no address", ep)
	}
	return ua.String(), nil
}

// accept hands every tunnel connection to the web server's socket.
func (t *Tunnel) accept(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go t.forward(c)
	}
}

func (t *Tunnel) forward(c net.Conn) {
	defer c.Close()
	src := proxyproto.AddrPortOf(c.RemoteAddr())
	dst := proxyproto.AddrPortOf(c.LocalAddr())
	claimed := src
	if t.o.Map != nil && !t.declared(src.Addr()) {
		claimed = netip.AddrPortFrom(t.o.Map.Map(src.Addr().Unmap()), src.Port())
	}
	d := net.Dialer{Timeout: t.o.DialTimeout}
	up, err := d.DialContext(context.Background(), "unix", t.o.Socket)
	if err != nil {
		t.sockErr.Store(err.Error())
		t.o.Log("web server socket %s: %v", t.o.Socket, err)
		return
	}
	defer up.Close()
	t.sockErr.Store("")
	if _, err := up.Write(proxyproto.Header(claimed, dst)); err != nil {
		return
	}
	t.forwarded.Add(1)
	t.count(src.Addr(), 1)
	defer t.count(src.Addr(), -1)
	_ = dst
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(up, c); closeWrite(up); done <- struct{}{} }()
	go func() { _, _ = io.Copy(c, up); closeWrite(c); done <- struct{}{} }()
	<-done
	<-done
}

// declared says whether the address lies in one of the manifest's ranges.
func (t *Tunnel) declared(a netip.Addr) bool {
	a = a.Unmap()
	for _, p := range t.o.Declared {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}

func (t *Tunnel) count(a netip.Addr, delta int32) {
	t.openMu.Lock()
	defer t.openMu.Unlock()
	n, ok := t.open[a]
	if !ok {
		n = new(int32)
		t.open[a] = n
	}
	*n += delta
}

func (t *Tunnel) openFor(a netip.Addr) int {
	t.openMu.Lock()
	defer t.openMu.Unlock()
	if n, ok := t.open[a]; ok {
		return int(*n)
	}
	return 0
}

// Status reads the device's state.
func (t *Tunnel) Status() Status {
	t.mu.Lock()
	defer t.mu.Unlock()
	st := Status{Peers: map[string]PeerStatus{}, ListenPort: t.cfg.Server.ListenPort, Error: t.err, Mode: config.ModeServer}
	if a, err := config.ServerAddress(t.cfg.Server.Network); err == nil {
		st.Address = a.String()
	}
	if k, err := wgkeys.Parse(t.cfg.Server.PrivateKey); err == nil {
		st.PublicKey = k.Public().String()
	}
	if t.cfg.IsClient() && t.cfg.Client != nil {
		st.Mode = config.ModeClient
		st.Address = t.cfg.Client.Address
		st.ListenPort = 0
		if k, err := wgkeys.Parse(t.cfg.Client.PrivateKey); err == nil {
			st.PublicKey = k.Public().String()
		}
	}
	st.SocketError, _ = t.sockErr.Load().(string)
	st.Forwarded = t.forwarded.Load()
	if t.dev == nil {
		return st
	}
	st.Running = true
	st.Since = t.since.UnixMilli()
	out, err := t.dev.IpcGet()
	if err != nil {
		st.Error = err.Error()
		return st
	}
	byHex := map[string]config.Device{}
	for _, d := range t.cfg.Devices {
		if k, err := wgkeys.Parse(d.PublicKey); err == nil {
			byHex[k.Hex()] = d
		}
	}
	peers := parsePeers(out)
	if t.cfg.IsClient() && t.cfg.Client != nil {
		if k, err := wgkeys.Parse(t.cfg.Client.PeerPublicKey); err == nil {
			if p, ok := peers[k.Hex()]; ok {
				p.Connections = 0
				t.openMu.Lock()
				for _, n := range t.open {
					p.Connections += int(*n)
				}
				t.openMu.Unlock()
				st.Connections = p.Connections
				st.Client = &p
				st.Peers[t.cfg.Client.PeerPublicKey] = p
			}
		}
		if t.o.Map != nil {
			for _, e := range t.o.Map.Entries() {
				m := Mapping{Entry: e}
				if a, err := netip.ParseAddr(e.Real); err == nil {
					m.Connections = t.openFor(a)
				}
				st.Mapped = append(st.Mapped, m)
			}
		}
		return st
	}
	for hexKey, p := range peers {
		d, ok := byHex[hexKey]
		if !ok {
			continue
		}
		if a, err := netip.ParseAddr(d.Address); err == nil {
			p.Connections = t.openFor(a)
		}
		st.Peers[d.PublicKey] = p
		st.Connections += p.Connections
	}
	return st
}

// parsePeers reads the peer blocks of a UAPI get.
func parsePeers(out string) map[string]PeerStatus {
	peers := map[string]PeerStatus{}
	var cur string
	var p PeerStatus
	var sec, nsec int64
	flush := func() {
		if cur != "" {
			if sec > 0 {
				p.LastHandshake = sec*1000 + nsec/1_000_000
			}
			peers[cur] = p
		}
		cur, p, sec, nsec = "", PeerStatus{}, 0, 0
	}
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch k {
		case "public_key":
			flush()
			cur = v
		case "endpoint":
			p.Endpoint = v
		case "last_handshake_time_sec":
			sec, _ = strconv.ParseInt(v, 10, 64)
		case "last_handshake_time_nsec":
			nsec, _ = strconv.ParseInt(v, 10, 64)
		case "rx_bytes":
			p.RxBytes, _ = strconv.ParseInt(v, 10, 64)
		case "tx_bytes":
			p.TxBytes, _ = strconv.ParseInt(v, 10, 64)
		}
	}
	flush()
	return peers
}

// Net is the netstack of the running tunnel (the tests dial through it); nil when down.
func (t *Tunnel) Net() *netstack.Net {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.tnet
}
