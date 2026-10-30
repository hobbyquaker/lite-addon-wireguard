#!/bin/sh
#
#   Runs the daemon against the fake system and the ingress stub, for the page's development and
#   the Playwright tests: the fake system on 127.0.0.1:18080 with the PROXY-socket stand-in, the
#   page on http://127.0.0.1:18298/addons/wireguard/ (no session check), the tunnel on UDP 51899. A
#   fresh configuration directory each run unless WG_CONF_DIR names one. The page is served from
#   ui/dist (npm run build first).
#
set -e
cd "$(dirname "$0")/.."
DIR=${WG_CONF_DIR:-$(mktemp -d)}
mkdir -p build "$DIR/addon"
go build -o build/fakesystem ./cmd/fakesystem
go build -o build/wireguard-dev ./cmd/wireguard
echo dev > "$DIR/token"
build/fakesystem -addr 127.0.0.1:18080 -socket "$DIR/proxy.sock" -port 51899 &
FAKE=$!
sleep 0.5
printf '{"server":{"enabled":true,"private_key":"","listen_port":51899,"network":"10.77.0.0/24","endpoint":"","keepalive":25},"devices":[]}\n' > "$DIR/wireguard.json"
build/wireguard-dev -system http://127.0.0.1:18080 -no-session-check -port 18298 -conf-dir "$DIR" -addon-dir "$DIR/addon" -www ui/dist -token-file "$DIR/token" -ingress-socket "$DIR/proxy.sock" &
DAEMON=$!
trap 'kill $DAEMON $FAKE 2>/dev/null' EXIT INT TERM
wait $DAEMON
