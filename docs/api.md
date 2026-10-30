# The page's API

The daemon serves the page and its API at `/addons/wireguard/` (lighttpd proxies it to `127.0.0.1:8298`). Every
request carries the system's session; only administrators are admitted (an API token of the scope `addon:wireguard`
or Full access passes the system's gate as well). Every write (`POST`, `PUT`, `DELETE`) needs the header
`X-CCU-Addon-Request`. Errors are `{"error": "<code>", "message": "…"}`: `invalid` (400 for bad JSON, 422 for a
refused value), `not-found` (404).

No secret is ever answered: the configuration view carries the system's **public** key and says whether a device has
a preshared key; the private key of a device made on the system is in the answer of its creation and nowhere else.

| Route | What |
| --- | --- |
| `GET api/v1/health` | `{ok, version, uptime_s, ready}`; with `?ready=1` 503 while the tunnel should run but does not |
| `GET api/v1/config` | `{mode: server\|client, server: {enabled, public_key, listen_port, network, address, endpoint, endpoint_for, keepalive}, client?: {…} (see the import), devices: [{id, name, public_key, address, enabled, has_psk, key_source: system\|imported, created}], defaults: {listen_port, network, keepalive}, version}`; `address` is the system's tunnel address, `endpoint_for` the endpoint with the port the devices dial (`""` without an endpoint) |
| `PUT api/v1/server` | `{enabled, listen_port (1024-65535), network (IPv4, /16-/29), endpoint ("" or name/address[:port]), keepalive (0-3600)}`; a changed network moves every device to the same host number. Answers the configuration. |
| `POST api/v1/server/regenerate-key` | a new private key for the system: every device configuration made so far stops working. Answers the configuration. |
| `PUT api/v1/mode` | `{mode: server\|client}` switches the mode (0.2.0): `server` - this system listens and the devices connect to it; `client` - this system connects to a WireGuard server elsewhere (a VPS, a router) and the devices come through it. The client mode needs an imported configuration. Answers the configuration. |
| `POST api/v1/client/import` | `{conf}`: the server's configuration file for this system (`[Interface] PrivateKey, Address; [Peer] PublicKey, PresharedKey?, Endpoint, AllowedIPs, PersistentKeepalive?`; one peer; DNS, MTU and scripts are ignored) - stored (the keys never answered) and the mode switched to `client`. `config.client` = `{public_key, address, peer_public_key, has_psk, endpoint, allowed_ips, keepalive, imported}`; `public_key` is this system's key in that tunnel, the one the server knows. 422 `invalid` with the line for a file that does not parse. |
| `DELETE api/v1/client` | forgets the imported configuration and returns to the server mode. Answers the configuration. |
| `POST api/v1/devices` | `{name, key_source: system\|imported, psk?, public_key?, preshared_key?}` → `201 {device, config, client?}`. `system` (the default) makes the key pair here: `client` = `{conf, file_name, qr, endpoint_missing}` - the configuration file the WireGuard apps import, its download name, the QR code as a PNG data URL - **handed out once, never kept**; `psk` (default true) adds a preshared key. `imported` takes the device's `public_key` (and an optional `preshared_key`), no `client`. The device gets the next free tunnel address. |
| `PUT api/v1/devices/{id}` | `{name, enabled}`; a disabled device stays with its key and address but is no peer of the tunnel. Answers the configuration. |
| `DELETE api/v1/devices/{id}` | forgets the device; its address is free again. Answers the configuration. |
| `GET api/v1/status` | `{running, error?, mode, listen_port, address, public_key, peers, connections, forwarded, socket_error?, since?, client?: {endpoint, last_handshake, rx_bytes, tx_bytes, connections} (the server peer in the client mode), mapped?: [{real, mapped, last_seen, connections}] (the client mode: each device's real tunnel address and the address from 10.77.1.0/24 the system sees it as, most recently seen first), devices: [{id, enabled, endpoint?, last_handshake, rx_bytes, tx_bytes, connections, connected}], now}` - the live state from wireguard-go: `last_handshake` in unix milliseconds (0 for none), `connected` = a handshake within the last three minutes, `connections` the web connections open through the tunnel for that device, `forwarded` the connections handed to the web server since the start, `socket_error` when the web server's ingress socket could not be reached |
| `GET api/v1/system` | what the system says, with the addon's token and cached for 15 s (`?refresh=1` reads anew): `{checked, token_ok, scopes, error?, port_open?, port_rule_for?, backup_unencrypted, hostname?, domain?, addresses, at}` - `port_open` from the firewall's rules (the addon's own rule for its port), `backup_unencrypted` from the system's warnings, `addresses` the system's own (hints for the endpoint) |

## What the daemon calls on the system

- `GET /api/auth/v1/state` with its token (the scopes), `GET /api/system/v1/firewall` (whether the UDP port is open),
  `GET /api/system/v1/warnings` (`backup-unencrypted`) and `GET /api/system/v1/network` (the system's name and
  addresses) - all `system:read`, all read-only, for the page's banners and hints. Nothing else; the addon makes no
  outgoing connection.
- The web server, through its ingress socket `/run/lighttpd-addons/wireguard/proxy.sock`: every TCP connection a
  device opens to the system's tunnel address on port 80 is forwarded there with a PROXY protocol v2 header that
  names the device's tunnel address, so the system sees the device as the client.
