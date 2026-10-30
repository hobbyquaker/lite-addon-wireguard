// fakesystem runs the fake openccu-lite and the web server's PROXY-socket stand-in for the page's
// development and the Playwright tests (scripts/dev-serve.sh): the system on -addr, the ingress
// stub on -socket; /dev/set?port_open=1&backup_unencrypted=1 drives the facts the page shows.
package main

import (
	"flag"
	"log"
	"net/http"
	"time"

	"github.com/hobbyquaker/lite-addon-wireguard/internal/fakesys"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:18080", "the fake system's address")
	socket := flag.String("socket", "", "the PROXY-protocol ingress stub's Unix socket (none without)")
	token := flag.String("token", "dev", "the token the fake accepts")
	port := flag.Int("port", 51820, "the UDP port the fake's firewall rule names when it is open")
	flag.Parse()
	s := fakesys.New(*token, "system:read")
	s.Port = *port
	if *socket != "" {
		stub, err := fakesys.ListenProxyStub(*socket)
		if err != nil {
			log.Fatal(err)
		}
		defer stub.Close()
		log.Printf("ingress stub on %s", *socket)
	}
	log.Printf("fake system on %s", *addr)
	srv := &http.Server{Addr: *addr, Handler: s.Handler(), ReadHeaderTimeout: 5 * time.Second}
	log.Fatal(srv.ListenAndServe())
}
