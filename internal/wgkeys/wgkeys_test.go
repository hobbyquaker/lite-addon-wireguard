package wgkeys

import (
	"bytes"
	"strings"
	"testing"

	"golang.org/x/crypto/curve25519"
)

func TestKeys(t *testing.T) {
	priv, err := NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	if priv[0]&7 != 0 || priv[31]&128 != 0 || priv[31]&64 == 0 {
		t.Fatal("not clamped")
	}
	pub := priv.Public()
	if pub.IsZero() || pub == priv {
		t.Fatal("public key")
	}
	s := priv.String()
	if len(s) != 44 || !strings.HasSuffix(s, "=") {
		t.Fatalf("base64 %q", s)
	}
	back, err := Parse(s)
	if err != nil || back != priv {
		t.Fatalf("round trip: %v", err)
	}
	if len(priv.Hex()) != 64 {
		t.Fatal("hex")
	}
	for _, bad := range []string{"", "x", s[:43], s + "=", strings.Repeat("A", 43) + "=", "!" + s[1:]} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
	// the public key is X25519 of the private key and the base point (what wg pubkey computes)
	want, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil || string(want) != string(pub[:]) {
		t.Fatalf("public key: %v", err)
	}
	psk, _ := NewPresharedKey()
	if psk.IsZero() {
		t.Fatal("psk")
	}
}

func TestClientConfig(t *testing.T) {
	priv, _ := Parse("WAmgVYXkbT2bCtdcDwolI88/iTy4GNaH42zKFkaWBHg=")
	srv, _ := Parse("qP3N6tb8nm2ssXDq6kAHtLEY6AWoltXL1Lv4Oc3bV0w=")
	c := ClientConfig{PrivateKey: priv, Address: "10.77.0.2/32", ServerPublicKey: srv, Endpoint: "ccu.example.org:51820", AllowedIPs: "10.77.0.1/32", Keepalive: 25}
	want := "[Interface]\nPrivateKey = WAmgVYXkbT2bCtdcDwolI88/iTy4GNaH42zKFkaWBHg=\nAddress = 10.77.0.2/32\n\n[Peer]\nPublicKey = qP3N6tb8nm2ssXDq6kAHtLEY6AWoltXL1Lv4Oc3bV0w=\nEndpoint = ccu.example.org:51820\nAllowedIPs = 10.77.0.1/32\nPersistentKeepalive = 25\n"
	if got := c.Render(); got != want {
		t.Fatalf("got\n%s\nwant\n%s", got, want)
	}
	c.PresharedKey = srv
	c.Endpoint = ""
	c.Keepalive = 0
	got := c.Render()
	if !strings.Contains(got, "PresharedKey = qP3N") || strings.Contains(got, "Endpoint") || strings.Contains(got, "Keepalive") {
		t.Fatalf("optional lines:\n%s", got)
	}
	png, err := QRPNG(want, 200)
	if err != nil || !bytes.HasPrefix(png, []byte("\x89PNG")) || len(png) < 500 {
		t.Fatalf("qr: %v %d", err, len(png))
	}
}

func TestParseImported(t *testing.T) {
	good := "[Interface]\nPrivateKey = WAmgVYXkbT2bCtdcDwolI88/iTy4GNaH42zKFkaWBHg=\nAddress = 10.8.0.5/32, fd42::5/128\nDNS = 10.8.0.1\nMTU = 1420\n\n# the server\n[Peer]\nPublicKey = bmPCoiV1OzK4UGZprBgXfZtdTtq0dfqPIVRQ9zi3SD8=\nPresharedKey = bmPCoiV1OzK4UGZprBgXfZtdTtq0dfqPIVRQ9zi3SD8=\nEndpoint = vps.example.org:51820\nAllowedIPs = 10.8.0.0/24, 192.168.50.0/24\nPersistentKeepalive = 25\n"
	c, err := ParseImported(good)
	if err != nil {
		t.Fatal(err)
	}
	if c.Address != "10.8.0.5/32" || c.Endpoint != "vps.example.org:51820" || len(c.AllowedIPs) != 2 || c.Keepalive != 25 || c.PresharedKey.IsZero() || c.DNS != "10.8.0.1" {
		t.Fatalf("%+v", c)
	}
	for _, bad := range []string{
		"", "[Peer]\nPublicKey = bmPCoiV1OzK4UGZprBgXfZtdTtq0dfqPIVRQ9zi3SD8=\n",
		strings.Replace(good, "Endpoint = vps.example.org:51820\n", "", 1),
		strings.Replace(good, "AllowedIPs = 10.8.0.0/24, 192.168.50.0/24\n", "", 1),
		good + "\n[Peer]\nPublicKey = WAmgVYXkbT2bCtdcDwolI88/iTy4GNaH42zKFkaWBHg=\n",
		strings.Replace(good, "PrivateKey = WAmgVYXkbT2bCtdcDwolI88/iTy4GNaH42zKFkaWBHg=", "PrivateKey = short", 1),
		good + "Bogus = 1\n",
		"[Other]\nx = 1\n",
	} {
		if _, err := ParseImported(bad); err == nil {
			t.Errorf("accepted:\n%s", bad)
		}
	}
}
