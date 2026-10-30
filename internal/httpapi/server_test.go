package httpapi

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hobbyquaker/ccu-addon-kit/go/addonkit"

	"github.com/hobbyquaker/lite-addon-wireguard/internal/config"
	"github.com/hobbyquaker/lite-addon-wireguard/internal/fakesys"
	"github.com/hobbyquaker/lite-addon-wireguard/internal/sysinfo"
	"github.com/hobbyquaker/lite-addon-wireguard/internal/tunnel"
)

type world struct {
	t     *testing.T
	ts    *httptest.Server
	sys   *fakesys.Server
	store *config.Store
	tun   *tunnel.Tunnel
}

func freePort(t *testing.T) int {
	t.Helper()
	c, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port
}

// setup wires the addon end to end: the fake system, the store, the real tunnel (on a free port,
// its web forward to a stub socket) and the API on a test server.
func setup(t *testing.T) *world {
	t.Helper()
	sys := fakesys.New("tok", "system:read")
	sysTS := httptest.NewServer(sys.Handler())
	t.Cleanup(sysTS.Close)
	store, err := config.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetServer(config.ServerSettings{Enabled: true, ListenPort: freePort(t), Network: "10.77.0.0/24", Keepalive: 25}); err != nil {
		t.Fatal(err)
	}
	stub, err := fakesys.ListenProxyStub(filepath.Join(t.TempDir(), "p.sock"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(stub.Close)
	tun := tunnel.New(tunnel.Options{Socket: stub.Path, Log: t.Logf})
	t.Cleanup(tun.Close)
	store.OnChange = func(c config.Config) { _ = tun.Apply(c) }
	if err := tun.Apply(store.Get()); err != nil {
		t.Fatal(err)
	}
	www := t.TempDir()
	_ = os.WriteFile(filepath.Join(www, "index.html"), []byte("<!doctype html><title>WG</title>"), 0o644)
	facts := &sysinfo.Client{Base: sysTS.URL, HTTP: &http.Client{Transport: &addonkit.AuthTransport{Source: addonkit.StaticToken("tok")}}, AddonID: "wireguard", Port: func() int { return store.Get().Server.ListenPort }, TTL: time.Millisecond}
	h := New(Options{BasePath: "/addons/wireguard", WWW: www, Store: store, Tunnel: tun, Facts: facts, Version: "test", Started: time.Now(), QRSize: 120})
	ts := httptest.NewServer(h)
	t.Cleanup(ts.Close)
	return &world{t: t, ts: ts, sys: sys, store: store, tun: tun}
}

func (w *world) do(method, path string, body any, into any) *http.Response {
	w.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, w.ts.URL+"/addons/wireguard"+path, rd)
	req.Header.Set("Content-Type", "application/json")
	if method != "GET" {
		req.Header.Set("X-CCU-Addon-Request", "1")
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		w.t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	if into != nil && res.StatusCode < 300 {
		if err := json.Unmarshal(b, into); err != nil {
			w.t.Fatalf("%s %s: %v: %s", method, path, err, b)
		}
	}
	if res.StatusCode >= 300 {
		w.t.Logf("%s %s: %d %s", method, path, res.StatusCode, b)
	}
	return res
}

func TestAPI(t *testing.T) {
	w := setup(t)
	// the page and health
	res, _ := http.Get(w.ts.URL + "/addons/wireguard/")
	if res.StatusCode != 200 {
		t.Fatalf("page %d", res.StatusCode)
	}
	var health map[string]any
	if res := w.do("GET", "/api/v1/health?ready=1", nil, &health); res.StatusCode != 200 || health["ready"] != true {
		t.Fatalf("health %d %v", res.StatusCode, health)
	}
	// the configuration: no private key anywhere
	var cfg ConfigView
	w.do("GET", "/api/v1/config", nil, &cfg)
	if cfg.Server.PublicKey == "" || cfg.Server.Address != "10.77.0.1" || len(cfg.Devices) != 0 || cfg.Server.EndpointFor != "" {
		t.Fatalf("%+v", cfg)
	}
	// a writing request without the CSRF header is refused
	req, _ := http.NewRequest("PUT", w.ts.URL+"/addons/wireguard/api/v1/server", strings.NewReader(`{}`))
	if res, _ := http.DefaultClient.Do(req); res.StatusCode != 403 {
		t.Fatalf("without the header: %d", res.StatusCode)
	}
	// the server settings
	port := w.store.Get().Server.ListenPort
	if res := w.do("PUT", "/api/v1/server", config.ServerSettings{Enabled: true, ListenPort: port, Network: "10.77.0.0/24", Endpoint: "ccu.example.org", Keepalive: 25}, &cfg); res.StatusCode != 200 || cfg.Server.EndpointFor != "ccu.example.org:"+itoa(port) {
		t.Fatalf("server: %d %+v", res.StatusCode, cfg.Server)
	}
	if res := w.do("PUT", "/api/v1/server", config.ServerSettings{Enabled: true, ListenPort: 80, Network: "10.77.0.0/24"}, nil); res.StatusCode != 422 {
		t.Fatalf("a bad port: %d", res.StatusCode)
	}
	// a device made on the system: issued once, with QR and conf; the private key is not stored
	var issued Issued
	if res := w.do("POST", "/api/v1/devices", config.NewDevice{Name: "Pixel 7"}, &issued); res.StatusCode != 201 {
		t.Fatalf("add: %d", res.StatusCode)
	}
	if issued.Client == nil || !strings.HasPrefix(issued.Client.QR, "data:image/png;base64,") || !strings.Contains(issued.Client.Conf, "Endpoint = ccu.example.org:") || !strings.Contains(issued.Client.Conf, "PresharedKey = ") || issued.Client.FileName != "Pixel-7.conf" || issued.Client.EndpointMissing {
		t.Fatalf("issued: %+v", issued.Client)
	}
	if issued.Device.Address != "10.77.0.2" || !issued.Device.HasPSK || issued.Device.KeySource != "system" || len(issued.Config.Devices) != 1 {
		t.Fatalf("device: %+v", issued.Device)
	}
	priv := strings.TrimSpace(strings.Split(strings.Split(issued.Client.Conf, "PrivateKey = ")[1], "\n")[0])
	b, _ := os.ReadFile(w.store.Path())
	if strings.Contains(string(b), priv) {
		t.Fatal("the private key is in the file")
	}
	// GET config never answers a preshared key or the private key
	raw := w.ts.URL + "/addons/wireguard/api/v1/config"
	res, _ = http.Get(raw)
	body, _ := io.ReadAll(res.Body)
	if strings.Contains(string(body), "preshared") || strings.Contains(string(body), "private_key") {
		t.Fatalf("secrets in the config view: %s", body)
	}
	// an imported key: no client issue
	var imported Issued
	pub := strings.TrimSpace(strings.Split(strings.Split(issued.Client.Conf, "PublicKey = ")[1], "\n")[0]) // the server's key: refused as a device
	if res := w.do("POST", "/api/v1/devices", config.NewDevice{Name: "own", KeySource: "imported", PublicKey: pub}, nil); res.StatusCode != 422 {
		t.Fatalf("the system's own key accepted: %d", res.StatusCode)
	}
	if res := w.do("POST", "/api/v1/devices", config.NewDevice{Name: "Laptop", KeySource: "imported", PublicKey: "bmPCoiV1OzK4UGZprBgXfZtdTtq0dfqPIVRQ9zi3SD8="}, &imported); res.StatusCode != 201 || imported.Client != nil || imported.Device.HasPSK {
		t.Fatalf("imported: %d %+v", res.StatusCode, imported.Device)
	}
	// update, status, delete
	if res := w.do("PUT", "/api/v1/devices/laptop", config.DeviceUpdate{Name: "Laptop (work)", Enabled: false}, &cfg); res.StatusCode != 200 || cfg.Devices[0].Name != "Laptop (work)" || cfg.Devices[0].Enabled {
		t.Fatalf("update: %d %+v", res.StatusCode, cfg.Devices)
	}
	var st StatusView
	w.do("GET", "/api/v1/status", nil, &st)
	if !st.Running || len(st.Devices) != 2 || st.Devices[0].Connected || st.Now == 0 {
		t.Fatalf("status %+v", st)
	}
	if res := w.do("DELETE", "/api/v1/devices/laptop", nil, &cfg); res.StatusCode != 200 || len(cfg.Devices) != 1 {
		t.Fatalf("delete: %d", res.StatusCode)
	}
	if res := w.do("DELETE", "/api/v1/devices/laptop", nil, nil); res.StatusCode != 404 {
		t.Fatalf("delete again: %d", res.StatusCode)
	}
	// the system facts
	var f sysinfo.Facts
	w.do("GET", "/api/v1/system", nil, &f)
	if !f.Checked || !f.TokenOK || f.PortOpen == nil || *f.PortOpen || f.BackupUnencrypted || f.Hostname != "ccu" || len(f.Addresses) != 1 {
		t.Fatalf("facts %+v", f)
	}
	w.sys.Set(func(s *fakesys.Server) { s.PortOpen = true; s.Port = port; s.BackupUnencrypted = true })
	time.Sleep(2 * time.Millisecond)
	w.do("GET", "/api/v1/system?refresh=1", nil, &f)
	if f.PortOpen == nil || !*f.PortOpen || !f.BackupUnencrypted {
		t.Fatalf("facts after the change %+v", f)
	}
	// regenerate the key: a new public key
	before := cfg.Server.PublicKey
	if res := w.do("POST", "/api/v1/server/regenerate-key", nil, &cfg); res.StatusCode != 200 || cfg.Server.PublicKey == before {
		t.Fatalf("regenerate: %d", res.StatusCode)
	}
	// unknown routes
	if res := w.do("GET", "/api/v1/nothing", nil, nil); res.StatusCode != 404 {
		t.Fatalf("unknown: %d", res.StatusCode)
	}
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}

// Every route the server registers is in docs/api.md.
func TestRoutesDocumented(t *testing.T) {
	setup(t)
	doc, err := os.ReadFile("../../docs/api.md")
	if err != nil {
		t.Skip("docs/api.md not found")
	}
	for _, r := range Routes {
		parts := strings.SplitN(r, " ", 2)
		if !strings.Contains(string(doc), "`"+parts[0]+" "+strings.TrimPrefix(parts[1], "/")) && !strings.Contains(string(doc), parts[0]+" "+strings.TrimPrefix(parts[1], "/")) {
			t.Errorf("route %s is not in docs/api.md", r)
		}
	}
}

func TestConfFileName(t *testing.T) {
	for in, want := range map[string]string{"Pixel 7": "Pixel-7.conf", "Mein Laptop (Büro)": "Mein-Laptop-Bro.conf", "": "wg-device.conf", "a very long device name indeed": "a-very-long-dev.conf", "..": "wg-device.conf"} {
		if got := confFileName(in); got != want {
			t.Errorf("%q: %s", in, got)
		}
	}
}
