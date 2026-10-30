// Package config is the addon's configuration: the server (the system's private key, the listen
// port, the tunnel network, the public endpoint the devices dial, the keepalive) and the devices
// (name, public key, tunnel address, an optional preshared key, enabled). One JSON file,
// wireguard.json, in the configuration directory the system gives the addon (0700); the file is
// 0600 as it holds the private key and the preshared keys. It is in the system's backup (no
// .nobackup marker), so a restore brings the same public key back and no device needs a new
// configuration. Reads are copies; a write validates, writes a temporary file and renames.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/hobbyquaker/lite-addon-wireguard/internal/wgkeys"
)

// Server is the system's end of the tunnels.
type Server struct {
	// Enabled switches the tunnel on; off, no UDP socket is open and no device connects.
	Enabled bool `json:"enabled"`
	// PrivateKey is the system's private key, base64. Never answered by the API.
	PrivateKey string `json:"private_key"`
	// ListenPort is the UDP port, 51820 by default.
	ListenPort int `json:"listen_port"`
	// Network is the tunnel network, "10.77.0.0/24" by default; the system takes its first
	// address, the devices the following ones.
	Network string `json:"network"`
	// Endpoint is what the devices dial: a DNS name or address, with an optional port (the listen
	// port when none). Empty until the user sets it.
	Endpoint string `json:"endpoint"`
	// Keepalive is the PersistentKeepalive the device configurations carry, in seconds; 0 is none.
	Keepalive int `json:"keepalive"`
}

// Device is one peer: a phone, a laptop, a program elsewhere.
type Device struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	PublicKey string `json:"public_key"`
	// PresharedKey is optional, base64. Never answered by the API (has_psk says whether there is one).
	PresharedKey string `json:"preshared_key,omitempty"`
	// Address is the device's tunnel address, "10.77.0.2".
	Address string `json:"address"`
	Enabled bool   `json:"enabled"`
	// KeySource is "system" (the key pair was made here and handed out once) or "imported" (the
	// device's own public key was pasted).
	KeySource string `json:"key_source"`
	// Created is unix milliseconds.
	Created int64 `json:"created"`
}

// Client is the system's end of a tunnel to a WireGuard server elsewhere (the client mode, 0.2.0):
// a VPS, a router, OPNsense. The server's configuration file for this system is imported on the
// page; the devices connect to that server, and the server routes them to this system.
type Client struct {
	// PrivateKey is this system's key in that tunnel, from the imported file (base64). Never
	// answered by the API.
	PrivateKey string `json:"private_key"`
	// Address is this system's tunnel address the server gave it, "10.8.0.5".
	Address string `json:"address"`
	// PeerPublicKey is the server's key.
	PeerPublicKey string `json:"peer_public_key"`
	// PresharedKey is optional, base64. Never answered by the API.
	PresharedKey string `json:"preshared_key,omitempty"`
	// Endpoint is the server, "name-or-address:port".
	Endpoint string `json:"endpoint"`
	// AllowedIPs are the server's networks: the source addresses whose connections this system
	// accepts through the tunnel (the devices behind the server).
	AllowedIPs []string `json:"allowed_ips"`
	// Keepalive is the persistent keepalive towards the server, seconds; 0 is none.
	Keepalive int `json:"keepalive"`
	// Imported is unix milliseconds of the import.
	Imported int64 `json:"imported"`
}

// Modes of the tunnel.
const (
	ModeServer = "server"
	ModeClient = "client"
)

// Config is the whole file.
type Config struct {
	// Mode is ModeServer (this system listens, the devices connect to it) or ModeClient (this
	// system connects to a server, the devices come through it). Empty reads as server.
	Mode    string   `json:"mode,omitempty"`
	Server  Server   `json:"server"`
	Client  *Client  `json:"client,omitempty"`
	Devices []Device `json:"devices"`
}

// IsClient says whether the tunnel runs in the client mode.
func (c Config) IsClient() bool { return c.Mode == ModeClient }

// Defaults.
const (
	DefaultPort      = 51820
	DefaultNetwork   = "10.77.0.0/24"
	DefaultKeepalive = 25
	// MappedBlock is the second range the manifest declares for the ingress: the addresses of
	// devices outside the own network (the client mode) are mapped into it, one to one and stably
	// (internal/addrmap).
	MappedBlock     = "10.77.1.0/24"
	KeySourceSystem = "system"
	KeySourceImport = "imported"
	MaxDevices      = 200
)

// DefaultServer is a new server, without its key.
var DefaultServer = Server{Enabled: true, ListenPort: DefaultPort, Network: DefaultNetwork, Keepalive: DefaultKeepalive}

// ErrNotFound is answered for an unknown id.
var ErrNotFound = errors.New("not found")

// ValidationError is a refused change.
type ValidationError struct{ Msg string }

func (e *ValidationError) Error() string { return e.Msg }

func invalid(format string, args ...any) error {
	return &ValidationError{Msg: fmt.Sprintf(format, args...)}
}

var (
	idRe       = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,39}$`)
	endpointRe = regexp.MustCompile(`^[A-Za-z0-9.\-]{1,253}(:[0-9]{1,5})?$|^\[[0-9A-Fa-f:.]+\](:[0-9]{1,5})?$`)
)

// Store holds the configuration and the file.
type Store struct {
	mu   sync.RWMutex
	path string
	c    Config
	// OnChange is called after every successful write, with the new configuration (the tunnel
	// applies it).
	OnChange func(Config)
	// Now is the clock (tests set it).
	Now func() time.Time
}

// Open reads dir/wireguard.json, or starts with the defaults and a new key when there is none.
func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	s := &Store{path: filepath.Join(dir, "wireguard.json"), Now: time.Now}
	b, err := os.ReadFile(s.path)
	switch {
	case err == nil:
		if err := json.Unmarshal(b, &s.c); err != nil {
			return nil, fmt.Errorf("%s: %w", s.path, err)
		}
		if s.c.Devices == nil {
			s.c.Devices = []Device{}
		}
		if s.c.Server.ListenPort == 0 {
			s.c.Server.ListenPort = DefaultPort
		}
		if s.c.Server.Network == "" {
			s.c.Server.Network = DefaultNetwork
		}
	case errors.Is(err, os.ErrNotExist):
		s.c = Config{Server: DefaultServer, Devices: []Device{}}
	default:
		return nil, err
	}
	if s.c.Server.PrivateKey == "" {
		k, err := wgkeys.NewPrivateKey()
		if err != nil {
			return nil, err
		}
		s.c.Server.PrivateKey = k.String()
		if err := s.write(); err != nil {
			return nil, err
		}
	} else if _, err := wgkeys.Parse(s.c.Server.PrivateKey); err != nil {
		return nil, fmt.Errorf("%s: the private key does not parse", s.path)
	}
	if err := validate(s.c); err != nil {
		return nil, fmt.Errorf("%s: %w", s.path, err)
	}
	return s, nil
}

// Path is the file.
func (s *Store) Path() string { return s.path }

// Get is a copy of the configuration.
func (s *Store) Get() Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return clone(s.c)
}

func clone(c Config) Config {
	out := c
	out.Devices = append([]Device{}, c.Devices...)
	return out
}

// write stores the configuration (the caller holds the lock) and tells the listener.
func (s *Store) write() error {
	b, err := json.MarshalIndent(s.c, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, s.path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

func (s *Store) commit(next Config) error {
	if err := validate(next); err != nil {
		return err
	}
	s.c = next
	if err := s.write(); err != nil {
		return err
	}
	if s.OnChange != nil {
		s.OnChange(clone(next))
	}
	return nil
}

// ServerKey is the system's private key.
func (s *Store) ServerKey() wgkeys.Key {
	s.mu.RLock()
	defer s.mu.RUnlock()
	k, _ := wgkeys.Parse(s.c.Server.PrivateKey)
	return k
}

// ServerSettings is what the page may change of the server: everything but the key.
type ServerSettings struct {
	Enabled    bool   `json:"enabled"`
	ListenPort int    `json:"listen_port"`
	Network    string `json:"network"`
	Endpoint   string `json:"endpoint"`
	Keepalive  int    `json:"keepalive"`
}

// SetServer changes the server's settings. A changed network moves every device to the same
// host number in the new network when it fits, else refuses.
func (s *Store) SetServer(in ServerSettings) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := clone(s.c)
	next.Server.Enabled = in.Enabled
	next.Server.ListenPort = in.ListenPort
	next.Server.Network = strings.TrimSpace(in.Network)
	next.Server.Endpoint = strings.TrimSpace(in.Endpoint)
	next.Server.Keepalive = in.Keepalive
	if next.Server.Network != s.c.Server.Network {
		oldNet, err := netip.ParsePrefix(s.c.Server.Network)
		if err != nil {
			return invalid("the stored network does not parse")
		}
		newNet, err := parseNetwork(next.Server.Network)
		if err != nil {
			return err
		}
		next.Server.Network = newNet.String()
		for i, d := range next.Devices {
			old, err := netip.ParseAddr(d.Address)
			if err != nil {
				return invalid("device %s has no address", d.Name)
			}
			n, err := hostNumber(oldNet, old)
			if err != nil {
				return err
			}
			a, err := addressOf(newNet, n)
			if err != nil {
				return invalid("the network %s has no room for device %s (host %d)", newNet, d.Name, n)
			}
			next.Devices[i].Address = a.String()
		}
	}
	return s.commit(next)
}

// SetMode switches between the server and the client mode. The client mode needs an imported
// configuration.
func (s *Store) SetMode(mode string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch mode {
	case ModeServer, "":
		mode = ModeServer
	case ModeClient:
		if s.c.Client == nil {
			return invalid("the client mode needs an imported server configuration first")
		}
	default:
		return invalid("mode is server or client")
	}
	next := clone(s.c)
	next.Mode = mode
	if mode == ModeServer {
		next.Mode = ""
	}
	return s.commit(next)
}

// ImportClient takes a server's configuration file for this system (the client mode) and
// switches to the client mode.
func (s *Store) ImportClient(text string) error {
	ic, err := wgkeys.ParseImported(text)
	if err != nil {
		return invalid("the configuration: %v", err)
	}
	addr, _, ok := strings.Cut(ic.Address, "/")
	a, aerr := netip.ParseAddr(addr)
	if aerr != nil || !a.Is4() {
		return invalid("the configuration: Address %q is not an IPv4 address", ic.Address)
	}
	_ = ok
	if !endpointRe.MatchString(ic.Endpoint) || !strings.Contains(ic.Endpoint, ":") {
		return invalid("the configuration: Endpoint %q is not name-or-address:port", ic.Endpoint)
	}
	for _, r := range ic.AllowedIPs {
		if _, err := netip.ParsePrefix(r); err != nil {
			if _, err2 := netip.ParseAddr(r); err2 != nil {
				return invalid("the configuration: AllowedIPs %q is not a network", r)
			}
		}
	}
	if ic.Keepalive < 0 || ic.Keepalive > 3600 {
		return invalid("the configuration: PersistentKeepalive is 0 to 3600")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	next := clone(s.c)
	next.Client = &Client{PrivateKey: ic.PrivateKey.String(), Address: a.String(), PeerPublicKey: ic.PeerKey.String(), Endpoint: ic.Endpoint, AllowedIPs: append([]string{}, ic.AllowedIPs...), Keepalive: ic.Keepalive, Imported: s.Now().UnixMilli()}
	if !ic.PresharedKey.IsZero() {
		next.Client.PresharedKey = ic.PresharedKey.String()
	}
	next.Mode = ModeClient
	return s.commit(next)
}

// RemoveClient forgets the imported configuration and returns to the server mode.
func (s *Store) RemoveClient() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := clone(s.c)
	next.Client = nil
	next.Mode = ""
	return s.commit(next)
}

// RegenerateServerKey makes a new private key for the system: every device configuration made
// before stops working, which is the point of it (a leaked key).
func (s *Store) RegenerateServerKey() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, err := wgkeys.NewPrivateKey()
	if err != nil {
		return err
	}
	next := clone(s.c)
	next.Server.PrivateKey = k.String()
	return s.commit(next)
}

// NewDevice is what the page sends for a device.
type NewDevice struct {
	Name string `json:"name"`
	// KeySource: "system" makes the key pair here, "imported" takes PublicKey (and an optional
	// PresharedKey) as given.
	KeySource    string `json:"key_source"`
	PublicKey    string `json:"public_key"`
	PresharedKey string `json:"preshared_key"`
	// PSK: with KeySource system, whether a preshared key is made as well (default on).
	PSK *bool `json:"psk"`
}

// Issued is what AddDevice hands out exactly once for a key made on the system.
type Issued struct {
	PrivateKey   wgkeys.Key
	PresharedKey wgkeys.Key
}

// AddDevice adds a device with the next free tunnel address. For a key made on the system the
// private key (and the preshared key) are returned once and never kept.
func (s *Store) AddDevice(in NewDevice) (Device, Issued, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	name := strings.TrimSpace(in.Name)
	if name == "" || len(name) > 64 {
		return Device{}, Issued{}, invalid("a name of 1 to 64 characters")
	}
	if len(s.c.Devices) >= MaxDevices {
		return Device{}, Issued{}, invalid("no more than %d devices", MaxDevices)
	}
	d := Device{Name: name, Enabled: true, Created: s.Now().UnixMilli()}
	var issued Issued
	switch in.KeySource {
	case KeySourceSystem, "":
		priv, err := wgkeys.NewPrivateKey()
		if err != nil {
			return Device{}, Issued{}, err
		}
		d.KeySource = KeySourceSystem
		d.PublicKey = priv.Public().String()
		issued.PrivateKey = priv
		if in.PSK == nil || *in.PSK {
			psk, err := wgkeys.NewPresharedKey()
			if err != nil {
				return Device{}, Issued{}, err
			}
			d.PresharedKey = psk.String()
			issued.PresharedKey = psk
		}
	case KeySourceImport:
		pub, err := wgkeys.Parse(in.PublicKey)
		if err != nil {
			return Device{}, Issued{}, invalid("public key: %v", err)
		}
		d.KeySource = KeySourceImport
		d.PublicKey = pub.String()
		if strings.TrimSpace(in.PresharedKey) != "" {
			psk, err := wgkeys.Parse(in.PresharedKey)
			if err != nil {
				return Device{}, Issued{}, invalid("preshared key: %v", err)
			}
			d.PresharedKey = psk.String()
		}
	default:
		return Device{}, Issued{}, invalid("key_source is system or imported")
	}
	if d.PublicKey == s.serverPublic() {
		return Device{}, Issued{}, invalid("that is the system's own public key")
	}
	for _, o := range s.c.Devices {
		if o.PublicKey == d.PublicKey {
			return Device{}, Issued{}, invalid("a device with this public key exists: %s", o.Name)
		}
	}
	next := clone(s.c)
	addr, err := s.nextAddress()
	if err != nil {
		return Device{}, Issued{}, err
	}
	d.Address = addr.String()
	d.ID = s.newID(name)
	next.Devices = append(next.Devices, d)
	if err := s.commit(next); err != nil {
		return Device{}, Issued{}, err
	}
	return d, issued, nil
}

func (s *Store) serverPublic() string {
	k, err := wgkeys.Parse(s.c.Server.PrivateKey)
	if err != nil {
		return ""
	}
	return k.Public().String()
}

// DeviceUpdate is what the page may change of a device.
type DeviceUpdate struct {
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
}

// UpdateDevice renames or switches a device.
func (s *Store) UpdateDevice(id string, in DeviceUpdate) (Device, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	name := strings.TrimSpace(in.Name)
	if name == "" || len(name) > 64 {
		return Device{}, invalid("a name of 1 to 64 characters")
	}
	next := clone(s.c)
	for i := range next.Devices {
		if next.Devices[i].ID == id {
			next.Devices[i].Name = name
			next.Devices[i].Enabled = in.Enabled
			if err := s.commit(next); err != nil {
				return Device{}, err
			}
			return next.Devices[i], nil
		}
	}
	return Device{}, ErrNotFound
}

// RemoveDevice forgets a device; its address is free again.
func (s *Store) RemoveDevice(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := clone(s.c)
	for i, d := range next.Devices {
		if d.ID == id {
			next.Devices = append(next.Devices[:i], next.Devices[i+1:]...)
			return s.commit(next)
		}
	}
	return ErrNotFound
}

// Device answers one device.
func (s *Store) Device(id string) (Device, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, d := range s.c.Devices {
		if d.ID == id {
			return d, true
		}
	}
	return Device{}, false
}

func (s *Store) newID(name string) string {
	base := strings.ToLower(name)
	var b strings.Builder
	for _, r := range base {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == ' ', r == '-', r == '_', r == '.':
			b.WriteByte('-')
		}
	}
	id := strings.Trim(b.String(), "-")
	if len(id) > 24 {
		id = id[:24]
	}
	if id == "" || !idRe.MatchString(id) {
		id = "device"
	}
	taken := map[string]bool{}
	for _, d := range s.c.Devices {
		taken[d.ID] = true
	}
	if !taken[id] {
		return id
	}
	for n := 2; ; n++ {
		c := fmt.Sprintf("%s-%d", id, n)
		if !taken[c] {
			return c
		}
	}
}

// ServerAddress is the system's tunnel address: the network's first host.
func ServerAddress(network string) (netip.Addr, error) {
	p, err := parseNetwork(network)
	if err != nil {
		return netip.Addr{}, err
	}
	return addressOf(p, 1)
}

// nextAddress is the lowest free host from 2 up.
func (s *Store) nextAddress() (netip.Addr, error) {
	p, err := parseNetwork(s.c.Server.Network)
	if err != nil {
		return netip.Addr{}, err
	}
	used := map[string]bool{}
	for _, d := range s.c.Devices {
		used[d.Address] = true
	}
	for n := 2; ; n++ {
		a, err := addressOf(p, n)
		if err != nil {
			return netip.Addr{}, invalid("the network %s is full", p)
		}
		if !used[a.String()] {
			return a, nil
		}
	}
}

// parseNetwork takes an IPv4 network of /16 to /29 in its canonical form.
func parseNetwork(s string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(strings.TrimSpace(s))
	if err != nil || !p.Addr().Is4() {
		return netip.Prefix{}, invalid("the tunnel network is an IPv4 network, e.g. 10.77.0.0/24")
	}
	if p.Bits() < 16 || p.Bits() > 29 {
		return netip.Prefix{}, invalid("the tunnel network has a prefix of /16 to /29")
	}
	if p.Masked() != p {
		return netip.Prefix{}, invalid("%s is not a network address; use %s", p, p.Masked())
	}
	return p, nil
}

// addressOf is host number n of the network, below its broadcast address.
func addressOf(p netip.Prefix, n int) (netip.Addr, error) {
	size := 1 << (32 - p.Bits())
	if n < 1 || n >= size-1 {
		return netip.Addr{}, fmt.Errorf("host %d is outside %s", n, p)
	}
	b := p.Addr().As4()
	v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	v += uint32(n)
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}), nil
}

func hostNumber(p netip.Prefix, a netip.Addr) (int, error) {
	if !p.Contains(a) {
		return 0, invalid("%s is not in %s", a, p)
	}
	nb, ab := p.Addr().As4(), a.As4()
	nv := uint32(nb[0])<<24 | uint32(nb[1])<<16 | uint32(nb[2])<<8 | uint32(nb[3])
	av := uint32(ab[0])<<24 | uint32(ab[1])<<16 | uint32(ab[2])<<8 | uint32(ab[3])
	return int(av - nv), nil
}

// EndpointFor is what a device dials: the endpoint with the listen port appended when it names
// no port; "" without an endpoint.
func EndpointFor(s Server) string {
	e := strings.TrimSpace(s.Endpoint)
	if e == "" {
		return ""
	}
	if strings.HasPrefix(e, "[") {
		if strings.Contains(e, "]:") {
			return e
		}
		return fmt.Sprintf("%s:%d", e, s.ListenPort)
	}
	if strings.Count(e, ":") == 1 {
		return e
	}
	return fmt.Sprintf("%s:%d", e, s.ListenPort)
}

func validate(c Config) error {
	if c.Mode != "" && c.Mode != ModeServer && c.Mode != ModeClient {
		return invalid("mode %q", c.Mode)
	}
	if c.Mode == ModeClient && c.Client == nil {
		return invalid("the client mode without an imported configuration")
	}
	if cl := c.Client; cl != nil {
		if _, err := wgkeys.Parse(cl.PrivateKey); err != nil {
			return invalid("client: private key")
		}
		if _, err := wgkeys.Parse(cl.PeerPublicKey); err != nil {
			return invalid("client: the server's public key")
		}
		if cl.PresharedKey != "" {
			if _, err := wgkeys.Parse(cl.PresharedKey); err != nil {
				return invalid("client: preshared key")
			}
		}
		if a, err := netip.ParseAddr(cl.Address); err != nil || !a.Is4() {
			return invalid("client: address %q", cl.Address)
		}
		if cl.Endpoint == "" || len(cl.AllowedIPs) == 0 {
			return invalid("client: endpoint and allowed IPs")
		}
	}
	s := c.Server
	if s.ListenPort < 1024 || s.ListenPort > 65535 {
		return invalid("the listen port is 1024 to 65535")
	}
	if _, err := parseNetwork(s.Network); err != nil {
		return err
	}
	if s.Endpoint != "" && !endpointRe.MatchString(s.Endpoint) {
		return invalid("the endpoint is a DNS name or address, with an optional :port")
	}
	if s.Endpoint != "" {
		if _, port, ok := strings.Cut(strings.TrimPrefix(EndpointFor(s), "["), ":"); ok && strings.HasPrefix(s.Endpoint, "[") {
			_ = port
		}
	}
	if s.Keepalive < 0 || s.Keepalive > 3600 {
		return invalid("the keepalive is 0 (off) to 3600 seconds")
	}
	p, _ := parseNetwork(s.Network)
	ids := map[string]bool{}
	addrs := map[string]bool{}
	keys := map[string]bool{}
	for _, d := range c.Devices {
		if !idRe.MatchString(d.ID) || ids[d.ID] {
			return invalid("device id %q", d.ID)
		}
		ids[d.ID] = true
		if strings.TrimSpace(d.Name) == "" || len(d.Name) > 64 {
			return invalid("device %s: a name of 1 to 64 characters", d.ID)
		}
		if _, err := wgkeys.Parse(d.PublicKey); err != nil || keys[d.PublicKey] {
			return invalid("device %s: public key", d.Name)
		}
		keys[d.PublicKey] = true
		if d.PresharedKey != "" {
			if _, err := wgkeys.Parse(d.PresharedKey); err != nil {
				return invalid("device %s: preshared key", d.Name)
			}
		}
		a, err := netip.ParseAddr(d.Address)
		if err != nil || !p.Contains(a) || addrs[d.Address] {
			return invalid("device %s: address %s", d.Name, d.Address)
		}
		if n, _ := hostNumber(p, a); n < 2 {
			return invalid("device %s: address %s is the system's", d.Name, d.Address)
		}
		addrs[d.Address] = true
		if d.KeySource != KeySourceSystem && d.KeySource != KeySourceImport {
			return invalid("device %s: key source", d.Name)
		}
	}
	return nil
}

// SortedDevices are the devices by name, for a stable page.
func SortedDevices(ds []Device) []Device {
	out := append([]Device{}, ds...)
	sort.SliceStable(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
	return out
}
