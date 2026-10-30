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
