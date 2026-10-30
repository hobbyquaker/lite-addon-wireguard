# Changelog

## [0.2.0] - 2026-10-30

- **Client mode:** this system connects out to a WireGuard server elsewhere - a VPS, a router with a WireGuard server,
  OPNsense - and the devices come through that server; no open port and no port forward here, so it works behind
  DS-Lite and CGNAT too. The server's configuration file for this system is imported on the page (pasted; the private
  key in it is stored 0600 and never shown again); the page shows the connection's state (handshake, traffic), the
  server, this system's tunnel address and public key, and the networks whose devices may reach this system. The
  same ingress as the server mode: a device reaches this system's web server alone, with its own tunnel address as
  the client. A server name that does not resolve at boot is retried every minute. A VPS how-to on the page.
- **Addresses in the client mode:** the devices come with the server's addresses, which the system's ingress does
  not accept. Each device's address is mapped one to one and stably onto an address from `10.77.1.0/24`, the second
  block the manifest declares; the system - the login lockout, API token address ranges, the journal - sees the
  mapped address, the page shows both (*Devices seen*). The table is kept beside the configuration (in the backup);
  254 addresses, the device not seen for the longest time gives its address up when the block is full.

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
