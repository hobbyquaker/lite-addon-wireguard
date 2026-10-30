// wireguard is the lite-addon-wireguard daemon: WireGuard in userspace (wireguard-go with a
// netstack, no TUN device, no capability) that ends the devices' tunnels inside this process and
// forwards their web requests to the system's web server through its PROXY-protocol ingress socket,
// so the system sees each device's tunnel address. It serves its page and API on the loopback
// behind lighttpd's proxy of /addons/wireguard/. openccu-lite only.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/hobbyquaker/ccu-addon-kit/go/addonkit"

	"github.com/hobbyquaker/lite-addon-wireguard/internal/config"
	"github.com/hobbyquaker/lite-addon-wireguard/internal/httpapi"
	"github.com/hobbyquaker/lite-addon-wireguard/internal/sysinfo"
	"github.com/hobbyquaker/lite-addon-wireguard/internal/tunnel"
)

// version is set by the build (-ldflags "-X main.version=…").
var version = "dev"

func main() {
	log.SetFlags(0) // the journal adds the time
	addonDir := flag.String("addon-dir", "/usr/local/addons/wireguard", "the addon's directory (app/)")
	confDir := flag.String("conf-dir", "/usr/local/etc/config/addons/wireguard", "the configuration's directory (wireguard.json; mode 0700)")
	id := flag.String("id", "wireguard", "the addon id (token file, base path)")
	port := flag.Int("port", 8298, "the loopback port lighttpd proxies to")
	base := flag.String("system", "http://127.0.0.1", "openccu-lite's URL")
	basePath := flag.String("base-path", "", "the path the page is served at (/addons/<id> by default)")
	www := flag.String("www", "", "the built page (<addon-dir>/app by default)")
	socket := flag.String("ingress-socket", tunnel.DefaultSocket, "the web server's PROXY-protocol ingress socket")
	tokenFile := flag.String("token-file", "", "a token file for the system's API (the addon's own token by default)")
	noSession := flag.Bool("no-session-check", false, "serve the page without the session check (development only)")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return
	}
	if *basePath == "" {
		*basePath = "/addons/" + *id
	}
	if *www == "" {
		*www = filepath.Join(*addonDir, "app")
	}
	if err := run(*confDir, *id, *port, *base, *basePath, *www, *socket, *tokenFile, *noSession); err != nil {
		log.Fatalf("wireguard: %v", err)
	}
}

func run(confDir, id string, port int, base, basePath, www, socket, tokenFile string, noSession bool) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	logf := func(format string, args ...any) { log.Printf("wireguard: "+format, args...) }

	store, err := config.Open(confDir)
	if err != nil {
		return err
	}
	tun := tunnel.New(tunnel.Options{Socket: socket, Log: logf})
	defer tun.Close()
	store.OnChange = func(c config.Config) {
		if err := tun.Apply(c); err != nil {
			logf("the tunnel could not follow the configuration: %v", err)
		}
	}
	if err := tun.Apply(store.Get()); err != nil {
		// the port in use, say: the page shows it, the daemon stays up and serves the page
		logf("the tunnel is not up: %v", err)
	}

	var token addonkit.TokenSource
	if tokenFile != "" {
		token = &addonkit.FileToken{Path: tokenFile}
	} else {
		token = addonkit.AddonToken(id)
	}
	facts := &sysinfo.Client{Base: base, HTTP: &http.Client{Transport: &addonkit.AuthTransport{Source: token}, Timeout: 30 * time.Second}, AddonID: id, Port: func() int { return store.Get().Server.ListenPort }, Log: logf}
	go func() {
		// wait for the system in the background: at boot its web server answers 503 until the
		// system service is up, and the token may not exist yet; the tunnel runs regardless
		if f, err := facts.Await(ctx); err == nil {
			logf("the system accepts the token (%v)", f.Scopes)
		}
	}()

	wrap := func(h http.Handler) http.Handler { return h }
	if !noSession {
		c := addonkit.NewChecker(addonkit.SessionOptions{Base: base, Need: addonkit.LevelAdmin, AddonID: id, OnRefused: func(r *http.Request, reason string) {
			logf("refused %s %s: %s", r.Method, r.URL.Path, reason)
		}})
		wrap = c.Handler
	}
	h := httpapi.New(httpapi.Options{BasePath: basePath, WWW: www, Store: store, Tunnel: tun, Facts: facts, Wrap: wrap, Version: version, Started: time.Now()})
	l, err := addonkit.Listen(port, "")
	if err != nil {
		return err
	}
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	c := store.Get()
	logf("%s: serving %s on %s; %d devices, UDP %d, network %s, the web server through %s", version, basePath, l.Addr(), len(c.Devices), c.Server.ListenPort, c.Server.Network, socket)
	if err := srv.Serve(l); err != nil && err != http.ErrServerClosed {
		return err
	}
	logf("stopping")
	os.Stdout.Sync()
	return nil
}
