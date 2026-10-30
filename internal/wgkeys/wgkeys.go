// Package wgkeys makes and renders WireGuard keys: Curve25519 key pairs and preshared keys from
// crypto/rand, their base64 (the configuration files and the apps) and hex (wireguard-go's UAPI)
// forms, the client configuration a device imports, and its QR code.
//
// A device's private key made here is handed out exactly once and never stored; only the public
// key stays on the system (the concept's rule).
package wgkeys

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	qrcode "github.com/skip2/go-qrcode"
	"golang.org/x/crypto/curve25519"
)

// KeySize is the size of every WireGuard key.
const KeySize = 32

// Key is a 32-byte key, private, public or preshared.
type Key [KeySize]byte

// NewPrivateKey makes a private key: 32 random bytes, clamped as Curve25519 wants them.
func NewPrivateKey() (Key, error) {
	var k Key
	if _, err := rand.Read(k[:]); err != nil {
		return Key{}, err
	}
	k[0] &= 248
	k[31] &= 127
	k[31] |= 64
	return k, nil
}

// NewPresharedKey makes a preshared key: 32 random bytes.
func NewPresharedKey() (Key, error) {
	var k Key
	if _, err := rand.Read(k[:]); err != nil {
		return Key{}, err
	}
	return k, nil
}

// Public is the public key of a private one.
func (k Key) Public() Key {
	var pub Key
	curve25519.ScalarBaseMult((*[32]byte)(&pub), (*[32]byte)(&k))
	return pub
}

// String is the base64 form, as configuration files and the apps write a key.
func (k Key) String() string { return base64.StdEncoding.EncodeToString(k[:]) }

// Hex is the form wireguard-go's UAPI takes.
func (k Key) Hex() string { return hex.EncodeToString(k[:]) }

// IsZero says whether the key is all zeros (unset).
func (k Key) IsZero() bool { return k == Key{} }

// ErrKey is a key that does not parse.
var ErrKey = errors.New("not a WireGuard key: 44 characters of base64 ending in =")

// Parse reads a base64 key. The one shape is accepted: 44 characters, the last an "=", decoding
// to 32 bytes.
func Parse(s string) (Key, error) {
	s = strings.TrimSpace(s)
	if len(s) != 44 || !strings.HasSuffix(s, "=") {
		return Key{}, ErrKey
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(b) != KeySize {
		return Key{}, ErrKey
	}
	var k Key
	copy(k[:], b)
	if k.IsZero() {
		return Key{}, ErrKey
	}
	return k, nil
}

// ClientConfig is what a device's configuration file says.
type ClientConfig struct {
	// PrivateKey is the device's own key (made on the system, handed out once).
	PrivateKey Key
	// Address is the device's tunnel address with its prefix, "10.77.0.2/32".
	Address string
	// ServerPublicKey is the system's public key.
	ServerPublicKey Key
	// PresharedKey is optional (zero: none).
	PresharedKey Key
	// Endpoint is what the device dials, "name-or-address:port".
	Endpoint string
	// AllowedIPs is what the device routes through the tunnel: the system's tunnel address alone
	// ("10.77.0.1/32"), so nothing else of the device's traffic takes this path.
	AllowedIPs string
	// Keepalive is PersistentKeepalive in seconds; 0 leaves the line out.
	Keepalive int
}

// Render is the configuration in the format the WireGuard apps import (a file or a QR code).
func (c ClientConfig) Render() string {
	var b strings.Builder
	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\n", c.PrivateKey)
	fmt.Fprintf(&b, "Address = %s\n", c.Address)
	b.WriteString("\n[Peer]\n")
	fmt.Fprintf(&b, "PublicKey = %s\n", c.ServerPublicKey)
	if !c.PresharedKey.IsZero() {
		fmt.Fprintf(&b, "PresharedKey = %s\n", c.PresharedKey)
	}
	if c.Endpoint != "" {
		fmt.Fprintf(&b, "Endpoint = %s\n", c.Endpoint)
	}
	fmt.Fprintf(&b, "AllowedIPs = %s\n", c.AllowedIPs)
	if c.Keepalive > 0 {
		fmt.Fprintf(&b, "PersistentKeepalive = %d\n", c.Keepalive)
	}
	return b.String()
}

// QRPNG is the configuration as the QR code the apps scan, a PNG of the given edge in pixels.
func QRPNG(conf string, size int) ([]byte, error) {
	png, err := qrcode.Encode(conf, qrcode.Medium, size)
	if err != nil {
		return nil, err
	}
	if !bytes.HasPrefix(png, []byte("\x89PNG")) {
		return nil, errors.New("qr: not a PNG")
	}
	return png, nil
}

// ImportedConfig is what a server's configuration file for this system says (the client mode): the
// system's own private key and tunnel address, and the one peer - the server - with its key, an
// optional preshared key, its endpoint, the addresses it routes to this system (AllowedIPs) and
// the keepalive.
type ImportedConfig struct {
	PrivateKey   Key
	Address      string
	PeerKey      Key
	PresharedKey Key
	Endpoint     string
	AllowedIPs   []string
	Keepalive    int
	// DNS is ignored on purpose (the system resolves nothing through the tunnel); kept for the page.
	DNS string
}

// ParseImported reads a WireGuard configuration file as wg-quick and the apps write it: one
// [Interface] with PrivateKey and Address, one [Peer] with PublicKey, Endpoint and AllowedIPs
// (PresharedKey and PersistentKeepalive optional). Anything else - a second peer, Table, PostUp,
// MTU - is refused or ignored as noted.
func ParseImported(text string) (ImportedConfig, error) {
	var c ImportedConfig
	section := ""
	peers := 0
	for n, raw := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(raw)
		if i := strings.IndexAny(line, "#;"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			if section == "peer" {
				peers++
				if peers > 1 {
					return c, fmt.Errorf("line %d: a second [Peer] - this system connects to one server", n+1)
				}
			} else if section != "interface" {
				return c, fmt.Errorf("line %d: unknown section [%s]", n+1, section)
			}
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return c, fmt.Errorf("line %d: not a key = value line", n+1)
		}
		k, v = strings.ToLower(strings.TrimSpace(k)), strings.TrimSpace(v)
		var err error
		switch section + "." + k {
		case "interface.privatekey":
			c.PrivateKey, err = Parse(v)
		case "interface.address":
			// the first IPv4 address; a second one (IPv6) is ignored
			for _, a := range strings.Split(v, ",") {
				a = strings.TrimSpace(a)
				if a != "" && !strings.Contains(a, ":") && c.Address == "" {
					c.Address = a
				}
			}
		case "interface.dns":
			c.DNS = v
		case "interface.listenport", "interface.mtu", "interface.table", "interface.preup", "interface.postup", "interface.predown", "interface.postdown", "interface.saveconfig", "interface.fwmark":
			// of no use here: the system listens on no port in the client mode and runs no scripts
		case "peer.publickey":
			c.PeerKey, err = Parse(v)
		case "peer.presharedkey":
			c.PresharedKey, err = Parse(v)
		case "peer.endpoint":
			c.Endpoint = v
		case "peer.allowedips":
			for _, a := range strings.Split(v, ",") {
				if a = strings.TrimSpace(a); a != "" {
					c.AllowedIPs = append(c.AllowedIPs, a)
				}
			}
		case "peer.persistentkeepalive":
			_, err = fmt.Sscanf(v, "%d", &c.Keepalive)
		default:
			return c, fmt.Errorf("line %d: unknown key %s in [%s]", n+1, k, section)
		}
		if err != nil {
			return c, fmt.Errorf("line %d: %s: %v", n+1, k, err)
		}
	}
	switch {
	case c.PrivateKey.IsZero():
		return c, errors.New("[Interface] PrivateKey is missing")
	case c.Address == "":
		return c, errors.New("[Interface] Address (IPv4) is missing")
	case peers == 0 || c.PeerKey.IsZero():
		return c, errors.New("[Peer] PublicKey is missing")
	case c.Endpoint == "":
		return c, errors.New("[Peer] Endpoint is missing: the server's name or address and port")
	case len(c.AllowedIPs) == 0:
		return c, errors.New("[Peer] AllowedIPs is missing: the server's tunnel network, whose devices may reach this system")
	}
	return c, nil
}
