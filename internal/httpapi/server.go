// Package httpapi is the addon's own HTTP server: the Svelte page's files and its JSON API under
// one base path (/addons/wireguard/), which lighttpd proxies to the loopback port. Every request
// carries the shell's session, confirmed through the kit (administrators only); writes carry the
// kit's CSRF header. docs/api.md documents the routes.
package httpapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/hobbyquaker/ccu-addon-kit/go/addonkit"

	"github.com/hobbyquaker/lite-addon-wireguard/internal/config"
	"github.com/hobbyquaker/lite-addon-wireguard/internal/sysinfo"
	"github.com/hobbyquaker/lite-addon-wireguard/internal/tunnel"
	"github.com/hobbyquaker/lite-addon-wireguard/internal/wgkeys"
)

// FactsReader answers the system's facts (sysinfo.Client; a fake in the tests).
type FactsReader interface {
	Facts(ctx context.Context, force bool) sysinfo.Facts
}

// Options configure the server.
type Options struct {
	// BasePath is where the page is served, /addons/wireguard (no trailing slash).
	BasePath string
	// WWW is the directory with the built page.
	WWW    string
	Store  *config.Store
	Tunnel *tunnel.Tunnel
	Facts  FactsReader
	// Wrap is the session check; nil: none (development only).
	Wrap    func(http.Handler) http.Handler
	Version string
	Started time.Time
	// QRSize is the QR code's edge in pixels (320 by default).
	QRSize int
}

// Routes lists every "METHOD /path" the API serves; the readme's table is held to it by a test.
var Routes []string

type server struct {
	o Options
}

func handle(mux *http.ServeMux, pattern string, h http.HandlerFunc) {
	Routes = append(Routes, pattern)
	mux.HandleFunc(pattern, h)
}

// New builds the handler.
func New(o Options) http.Handler {
	o.BasePath = strings.TrimRight(o.BasePath, "/")
	if o.QRSize == 0 {
		o.QRSize = 320
	}
	s := &server{o: o}
	Routes = nil
	api := http.NewServeMux()
	handle(api, "GET /api/v1/health", s.health)
	handle(api, "GET /api/v1/config", s.config)
	handle(api, "PUT /api/v1/server", s.putServer)
	handle(api, "POST /api/v1/server/regenerate-key", s.regenerate)
	handle(api, "PUT /api/v1/mode", s.putMode)
	handle(api, "POST /api/v1/client/import", s.importClient)
	handle(api, "DELETE /api/v1/client", s.deleteClient)
	handle(api, "POST /api/v1/devices", s.addDevice)
	handle(api, "PUT /api/v1/devices/{id}", s.updateDevice)
	handle(api, "DELETE /api/v1/devices/{id}", s.deleteDevice)
	handle(api, "GET /api/v1/status", s.status)
	handle(api, "GET /api/v1/system", s.system)
	api.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		addonkit.WriteError(w, http.StatusNotFound, "not-found", r.URL.Path)
	})

	root := http.NewServeMux()
	root.Handle("/api/", addonkit.CSRF(api))
	root.Handle("/", addonkit.AppFiles(o.WWW))

	var h http.Handler = http.StripPrefix(o.BasePath, root)
	if o.Wrap != nil {
		h = o.Wrap(h)
	}
	return guard(h)
}

func guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p := r.URL.Path; p != "/" && (path.Clean(p) != strings.TrimSuffix(p, "/") && path.Clean(p) != p) {
			http.NotFound(w, r)
			return
		}
		if strings.Contains(r.URL.Path, "/api/") {
			w.Header().Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(v); err != nil {
		addonkit.WriteError(w, http.StatusBadRequest, "invalid", err.Error())
		return false
	}
	return true
}

func writeErr(w http.ResponseWriter, err error) {
	var ve *config.ValidationError
	switch {
	case errors.Is(err, config.ErrNotFound):
		addonkit.WriteError(w, http.StatusNotFound, "not-found", err.Error())
	case errors.As(err, &ve):
		addonkit.WriteError(w, http.StatusUnprocessableEntity, "invalid", err.Error())
	default:
		addonkit.WriteError(w, http.StatusInternalServerError, "internal", err.Error())
	}
}

// ServerView is the server as the page sees it: without the private key.
type ServerView struct {
	Enabled    bool   `json:"enabled"`
	PublicKey  string `json:"public_key"`
	ListenPort int    `json:"listen_port"`
	Network    string `json:"network"`
	Address    string `json:"address"`
	Endpoint   string `json:"endpoint"`
	// EndpointFor is what a device dials (the endpoint with the port), "" without an endpoint.
	EndpointFor string `json:"endpoint_for"`
	Keepalive   int    `json:"keepalive"`
}

// DeviceView is a device as the page sees it: without the preshared key.
type DeviceView struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	PublicKey string `json:"public_key"`
	Address   string `json:"address"`
	Enabled   bool   `json:"enabled"`
	HasPSK    bool   `json:"has_psk"`
	KeySource string `json:"key_source"`
	Created   int64  `json:"created"`
}

// ClientView is the imported server configuration as the page sees it: without the keys.
type ClientView struct {
	// PublicKey is this system's public key in that tunnel (the server knows it as the peer).
	PublicKey     string   `json:"public_key"`
	Address       string   `json:"address"`
	PeerPublicKey string   `json:"peer_public_key"`
	HasPSK        bool     `json:"has_psk"`
	Endpoint      string   `json:"endpoint"`
	AllowedIPs    []string `json:"allowed_ips"`
	Keepalive     int      `json:"keepalive"`
	Imported      int64    `json:"imported"`
}

// ConfigView is GET /api/v1/config.
type ConfigView struct {
	// Mode is server or client.
	Mode     string       `json:"mode"`
	Server   ServerView   `json:"server"`
	Client   *ClientView  `json:"client,omitempty"`
	Devices  []DeviceView `json:"devices"`
	Defaults struct {
		ListenPort int    `json:"listen_port"`
		Network    string `json:"network"`
		Keepalive  int    `json:"keepalive"`
	} `json:"defaults"`
	Version string `json:"version"`
}

func serverView(c config.Config) ServerView {
	v := ServerView{Enabled: c.Server.Enabled, ListenPort: c.Server.ListenPort, Network: c.Server.Network, Endpoint: c.Server.Endpoint, Keepalive: c.Server.Keepalive, EndpointFor: config.EndpointFor(c.Server)}
	if k, err := wgkeys.Parse(c.Server.PrivateKey); err == nil {
		v.PublicKey = k.Public().String()
	}
	if a, err := config.ServerAddress(c.Server.Network); err == nil {
		v.Address = a.String()
	}
	return v
}

func deviceView(d config.Device) DeviceView {
	return DeviceView{ID: d.ID, Name: d.Name, PublicKey: d.PublicKey, Address: d.Address, Enabled: d.Enabled, HasPSK: d.PresharedKey != "", KeySource: d.KeySource, Created: d.Created}
}

func (s *server) view() ConfigView {
	c := s.o.Store.Get()
	v := ConfigView{Mode: config.ModeServer, Server: serverView(c), Devices: []DeviceView{}, Version: s.o.Version}
	if c.IsClient() {
		v.Mode = config.ModeClient
	}
	if cl := c.Client; cl != nil {
		cv := &ClientView{Address: cl.Address, PeerPublicKey: cl.PeerPublicKey, HasPSK: cl.PresharedKey != "", Endpoint: cl.Endpoint, AllowedIPs: append([]string{}, cl.AllowedIPs...), Keepalive: cl.Keepalive, Imported: cl.Imported}
		if k, err := wgkeys.Parse(cl.PrivateKey); err == nil {
			cv.PublicKey = k.Public().String()
		}
		v.Client = cv
	}
	for _, d := range config.SortedDevices(c.Devices) {
		v.Devices = append(v.Devices, deviceView(d))
	}
	v.Defaults.ListenPort, v.Defaults.Network, v.Defaults.Keepalive = config.DefaultPort, config.DefaultNetwork, config.DefaultKeepalive
	return v
}

func (s *server) health(w http.ResponseWriter, r *http.Request) {
	st := s.o.Tunnel.Status()
	c := s.o.Store.Get()
	ready := st.Running || !c.Server.Enabled || (c.IsClient() && c.Client == nil)
	if r.URL.Query().Get("ready") == "1" && !ready {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"ok": false, "ready": false, "version": s.o.Version, "error": st.Error})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "version": s.o.Version, "uptime_s": int(time.Since(s.o.Started).Seconds()), "ready": ready})
}

func (s *server) config(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.view())
}

func (s *server) putServer(w http.ResponseWriter, r *http.Request) {
	var in config.ServerSettings
	if !decode(w, r, &in) {
		return
	}
	if err := s.o.Store.SetServer(in); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, s.view())
}

func (s *server) putMode(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Mode string `json:"mode"`
	}
	if !decode(w, r, &in) {
		return
	}
	if err := s.o.Store.SetMode(in.Mode); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, s.view())
}

func (s *server) importClient(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Conf string `json:"conf"`
	}
	if !decode(w, r, &in) {
		return
	}
	if len(in.Conf) > 16384 {
		addonkit.WriteError(w, http.StatusUnprocessableEntity, "invalid", "the configuration is too large")
		return
	}
	if err := s.o.Store.ImportClient(in.Conf); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, s.view())
}

func (s *server) deleteClient(w http.ResponseWriter, r *http.Request) {
	if err := s.o.Store.RemoveClient(); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, s.view())
}

func (s *server) regenerate(w http.ResponseWriter, r *http.Request) {
	if err := s.o.Store.RegenerateServerKey(); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, s.view())
}

// Issued is the answer of POST /api/v1/devices: the device, and - for a key made on the system,
// exactly once - its configuration file and QR code.
type Issued struct {
	Device DeviceView `json:"device"`
	Config ConfigView `json:"config"`
	// Client is present for a key made on the system: the configuration text the apps import, its
	// file name, and the QR code as a PNG data URL. Nothing of it is kept.
	Client *ClientIssue `json:"client,omitempty"`
}

// ClientIssue is the device's configuration, handed out once.
type ClientIssue struct {
	Conf     string `json:"conf"`
	FileName string `json:"file_name"`
	QR       string `json:"qr"`
	// EndpointMissing: the server has no public endpoint yet, so the configuration carries none.
	EndpointMissing bool `json:"endpoint_missing"`
}

func (s *server) addDevice(w http.ResponseWriter, r *http.Request) {
	var in config.NewDevice
	if !decode(w, r, &in) {
		return
	}
	d, issued, err := s.o.Store.AddDevice(in)
	if err != nil {
		writeErr(w, err)
		return
	}
	out := Issued{Device: deviceView(d), Config: s.view()}
	if !issued.PrivateKey.IsZero() {
		c := s.o.Store.Get()
		serverAddr, _ := config.ServerAddress(c.Server.Network)
		cc := wgkeys.ClientConfig{
			PrivateKey:      issued.PrivateKey,
			Address:         d.Address + "/32",
			ServerPublicKey: s.o.Store.ServerKey().Public(),
			PresharedKey:    issued.PresharedKey,
			Endpoint:        config.EndpointFor(c.Server),
			AllowedIPs:      serverAddr.String() + "/32",
			Keepalive:       c.Server.Keepalive,
		}
		conf := cc.Render()
		ci := &ClientIssue{Conf: conf, FileName: confFileName(d.Name), EndpointMissing: cc.Endpoint == ""}
		if png, err := wgkeys.QRPNG(conf, s.o.QRSize); err == nil {
			ci.QR = "data:image/png;base64," + base64.StdEncoding.EncodeToString(png)
		}
		out.Client = ci
	}
	writeJSON(w, http.StatusCreated, out)
}

// confFileName is the download's name: the device's name reduced to what WireGuard accepts as an
// interface name (15 characters of letters, digits, - and _), "wg-device" when nothing is left.
func confFileName(name string) string {
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		case r == ' ', r == '.':
			b.WriteByte('-')
		}
	}
	n := strings.Trim(b.String(), "-_")
	if len(n) > 15 {
		n = n[:15]
	}
	if n == "" {
		n = "wg-device"
	}
	return n + ".conf"
}

func (s *server) updateDevice(w http.ResponseWriter, r *http.Request) {
	var in config.DeviceUpdate
	if !decode(w, r, &in) {
		return
	}
	if _, err := s.o.Store.UpdateDevice(r.PathValue("id"), in); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, s.view())
}

func (s *server) deleteDevice(w http.ResponseWriter, r *http.Request) {
	if err := s.o.Store.RemoveDevice(r.PathValue("id")); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, s.view())
}

// StatusView is GET /api/v1/status: the tunnel with every device's live state.
type StatusView struct {
	tunnel.Status
	Devices []DeviceStatus `json:"devices"`
	Now     int64          `json:"now"`
}

// DeviceStatus is one device's live state.
type DeviceStatus struct {
	ID      string `json:"id"`
	Enabled bool   `json:"enabled"`
	tunnel.PeerStatus
	// Connected: a handshake within the last three minutes (WireGuard rekeys every two).
	Connected bool `json:"connected"`
}

func (s *server) status(w http.ResponseWriter, r *http.Request) {
	st := s.o.Tunnel.Status()
	c := s.o.Store.Get()
	now := time.Now()
	out := StatusView{Status: st, Devices: []DeviceStatus{}, Now: now.UnixMilli()}
	for _, d := range config.SortedDevices(c.Devices) {
		ds := DeviceStatus{ID: d.ID, Enabled: d.Enabled}
		if p, ok := st.Peers[d.PublicKey]; ok {
			ds.PeerStatus = p
			ds.Connected = p.LastHandshake > 0 && now.UnixMilli()-p.LastHandshake < 3*60*1000
		}
		out.Devices = append(out.Devices, ds)
	}
	writeJSON(w, 200, out)
}

func (s *server) system(w http.ResponseWriter, r *http.Request) {
	if s.o.Facts == nil {
		writeJSON(w, 200, sysinfo.Facts{Scopes: []string{}, Addresses: []string{}})
		return
	}
	writeJSON(w, 200, s.o.Facts.Facts(r.Context(), r.URL.Query().Get("refresh") == "1"))
}
