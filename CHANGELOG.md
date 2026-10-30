# Changelog

## [0.1.0] - 2026-10-30

The first release, for openccu-lite 1.1.0-dev.6 and newer (the web ingress of the system).

- **WireGuard in userspace** (wireguard-go with a netstack): no kernel interface, no capability, no root. The tunnel
  ends inside the addon, which makes exactly one thing reachable through it: the system's web server - the user
  interface, the APIs and the addon pages. Not the LAN behind the system.
- **The web server sees the device:** the addon hands every web connection to the system's ingress socket with the
  device's tunnel address in front (PROXY protocol), so the login lockout, API token address ranges and the journal see
  `10.77.0.2` and not the loopback. Plain HTTP inside the tunnel; the tunnel encrypts.
- **Devices:** made on the system - the key pair and a preshared key are generated here, the configuration is shown
  once as a QR code for the WireGuard app and as a file to download, and the private key is never stored - or with
  the device's own key (paste its public key, optionally a preshared key). Each device has a name, a tunnel address,
  an on/off switch; the list shows the state (connected, idle, never, disabled), the last handshake, the traffic, the
  public endpoint the device came from, and the open connections.
- **Server:** on/off, the UDP port (51820), the tunnel network (10.77.0.0/24), the public endpoint the devices dial,
  the keepalive; the system's public key with a copy button; a new key behind a confirmation; a how-to for the router's
  port forward. The page says when the UDP port is closed on the firewall (the switch is on the Addons page), when no
  endpoint is set, and when the system's backups are unencrypted - the server's private key is in them.
- One declared UDP port, closed by default; no outgoing connections. German and English, light and dark.
