// Package fakesys is the slice of openccu-lite the addon talks to, for the tests and the page's
// development: the auth state of the token (its scopes), the firewall's rules (whether the addon's
// UDP port is open), the system's warnings (backup encryption) and its network. Plus a stand-in for
// the web server's PROXY-protocol Unix socket: it reads the PROXY v2 header and answers every HTTP
// request with a page that names the address the addon claimed (X-Claimed-Address, and in the
// body), so a test can see what lighttpd would have seen.
package fakesys

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"

	"github.com/hobbyquaker/lite-addon-wireguard/internal/proxyproto"
)

// Server is the fake system.
type Server struct {
	mu sync.Mutex
	// Token is the one the addon must send; "" accepts any bearer.
	Token string
	// Scopes is what /api/auth/v1/state answers for the token.
	Scopes []string
	// PortOpen: the firewall holds the addon's rule for Port.
	PortOpen bool
	Port     int
	// BackupUnencrypted raises the system warning.
	BackupUnencrypted bool
	Hostname          string
	Domain            string
	Addresses         []string
}

// New makes a fake that accepts the token with the scopes.
func New(token string, scopes ...string) *Server {
	return &Server{Token: token, Scopes: scopes, Port: 51820, Hostname: "ccu", Domain: "example.lan", Addresses: []string{"192.0.2.10"}}
}

// Set changes the fake's state under its lock.
func (s *Server) Set(f func(*Server)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f(s)
}

// Handler is the fake's routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/meta/v1/version", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"api": "meta", "version": 1, "product": "openccu-lite", "capabilities": map[string]any{"system": 1}})
	})
	mux.HandleFunc("GET /api/auth/v1/state", func(w http.ResponseWriter, r *http.Request) {
		if !s.authed(r) {
			writeJSON(w, 401, map[string]any{"error": "unauthenticated", "authenticated": false})
			return
		}
		s.mu.Lock()
		scopes := append([]string{}, s.Scopes...)
		s.mu.Unlock()
		writeJSON(w, 200, map[string]any{"authenticated": true, "sid": "", "user": "token:addon:wireguard", "scopes": scopes, "level": "read", "role": "user"})
	})
	mux.HandleFunc("GET /api/system/v1/firewall", func(w http.ResponseWriter, r *http.Request) {
		if !s.authed(r) {
			writeJSON(w, 401, map[string]any{"error": "unauthenticated"})
			return
		}
		s.mu.Lock()
		rules := []map[string]any{{"id": "web-80", "port": 80, "proto": "tcp", "source": "local networks", "owner": "web", "target": "ACCEPT"}}
		if s.PortOpen {
			rules = append(rules, map[string]any{"id": "addon-wireguard-" + fmt.Sprint(s.Port), "port": s.Port, "proto": "udp", "source": "0/0", "owner": "addon:wireguard", "target": "ACCEPT"})
		}
		s.mu.Unlock()
		writeJSON(w, 200, map[string]any{"config": map[string]any{"version": 1, "rules": rules}})
	})
	mux.HandleFunc("GET /api/system/v1/warnings", func(w http.ResponseWriter, r *http.Request) {
		if !s.authed(r) {
			writeJSON(w, 401, map[string]any{"error": "unauthenticated"})
			return
		}
		s.mu.Lock()
		var ws []map[string]any
		if s.BackupUnencrypted {
			ws = append(ws, map[string]any{"id": "backup-unencrypted", "variant": "plain", "severity": "warning", "href": "/backup#encryption"})
		}
		s.mu.Unlock()
		if ws == nil {
			ws = []map[string]any{}
		}
		writeJSON(w, 200, map[string]any{"warnings": ws})
	})
	mux.HandleFunc("GET /api/system/v1/network", func(w http.ResponseWriter, r *http.Request) {
		if !s.authed(r) {
			writeJSON(w, 401, map[string]any{"error": "unauthenticated"})
			return
		}
		s.mu.Lock()
		var v4, v6 []map[string]any
		for _, a := range s.Addresses {
			if strings.Contains(a, ":") {
				v6 = append(v6, map[string]any{"address": a, "prefix": 64, "scope": "global"})
			} else {
				v4 = append(v4, map[string]any{"address": a, "prefix": 24})
			}
		}
		host, dom := s.Hostname, s.Domain
		s.mu.Unlock()
		if v4 == nil {
			v4 = []map[string]any{}
		}
		if v6 == nil {
			v6 = []map[string]any{}
		}
		writeJSON(w, 200, map[string]any{"network": map[string]any{"hostname": host, "domain": dom, "interfaces": []map[string]any{{"name": "eth0", "ipv4": v4, "ipv6": v6}}}})
	})
	// the dev routes drive the fake: /dev/set?port_open=1&backup_unencrypted=1
	mux.HandleFunc("/dev/set", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		s.mu.Lock()
		if v := q.Get("port_open"); v != "" {
			s.PortOpen = v == "1"
		}
		if v := q.Get("backup_unencrypted"); v != "" {
			s.BackupUnencrypted = v == "1"
		}
		s.mu.Unlock()
		writeJSON(w, 200, map[string]any{"ok": true})
	})
	return mux
}

func (s *Server) authed(r *http.Request) bool {
	if s.Token == "" {
		return true
	}
	return strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ") == s.Token
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// ProxyStub stands in for the web server's PROXY socket: a Unix socket that reads one PROXY v2
// header per connection and then serves HTTP, answering every request with the claimed address.
type ProxyStub struct {
	Path string
	ln   net.Listener
	mu   sync.Mutex
	// Seen records every claimed source address, in order.
	Seen []netip.AddrPort
	// TLS records whether the PROXY header carried the SSL TLV, per connection.
	srv *http.Server
}

// ListenProxyStub opens the stub at path (removing a stale socket first).
func ListenProxyStub(path string) (*ProxyStub, error) {
	_ = os.Remove(path)
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	_ = os.Chmod(path, 0o666)
	p := &ProxyStub{Path: path, ln: ln}
	p.srv = &http.Server{Handler: http.HandlerFunc(p.serve)}
	go p.accept()
	return p, nil
}

type claimedConn struct {
	net.Conn
	src, dst netip.AddrPort
}

func (c *claimedConn) RemoteAddr() net.Addr { return net.TCPAddrFromAddrPort(c.src) }
func (c *claimedConn) LocalAddr() net.Addr  { return net.TCPAddrFromAddrPort(c.dst) }

// proxyListener hands the HTTP server connections whose addresses are the claimed ones.
type proxyListener struct {
	ch   chan net.Conn
	done chan struct{}
	addr net.Addr
}

func (l *proxyListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}
func (l *proxyListener) Close() error   { return nil }
func (l *proxyListener) Addr() net.Addr { return l.addr }

func (p *ProxyStub) accept() {
	pl := &proxyListener{ch: make(chan net.Conn), done: make(chan struct{}), addr: p.ln.Addr()}
	go func() { _ = p.srv.Serve(pl) }()
	for {
		c, err := p.ln.Accept()
		if err != nil {
			close(pl.done)
			return
		}
		go func() {
			br := bufio.NewReader(c)
			src, dst, err := proxyproto.Read(br)
			if err != nil {
				c.Close()
				return
			}
			p.mu.Lock()
			p.Seen = append(p.Seen, src)
			p.mu.Unlock()
			pl.ch <- &claimedConn{Conn: &bufferedConn{Conn: c, r: br}, src: src, dst: dst}
		}()
	}
}

type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) { return b.r.Read(p) }

func (p *ProxyStub) serve(w http.ResponseWriter, r *http.Request) {
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	w.Header().Set("X-Claimed-Address", host)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if strings.HasPrefix(r.URL.Path, "/api/") {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"ok":true,"remote":%q,"path":%q}`+"\n", host, r.URL.Path)
		return
	}
	fmt.Fprintf(w, "<!doctype html><title>stub</title><p>The web server stand-in: your address is <b>%s</b>, path %s</p>\n", host, r.URL.Path)
}

// Claimed answers the claimed addresses so far.
func (p *ProxyStub) Claimed() []netip.AddrPort {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]netip.AddrPort{}, p.Seen...)
}

// Close stops the stub.
func (p *ProxyStub) Close() {
	p.ln.Close()
	_ = p.srv.Close()
	_ = os.Remove(p.Path)
}
