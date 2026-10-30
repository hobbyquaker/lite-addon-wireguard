// Package proxyproto writes and reads the HAProxy PROXY protocol v2 header: the one the addon
// puts in front of every connection it hands to the web server's Unix socket, so that lighttpd
// takes the device's tunnel address as the client's. The reader is for the tests' stub and for a
// development stand-in of the web server.
package proxyproto

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
)

var signature = []byte("\r\n\r\n\x00\r\nQUIT\n")

// Header is a PROXY v2 header for a proxied TCP connection.
func Header(src, dst netip.AddrPort) []byte {
	h := append([]byte{}, signature...)
	var addr []byte
	if src.Addr().Is4() && dst.Addr().Is4() {
		h = append(h, 0x21, 0x11) // PROXY, TCP over IPv4
		s, d := src.Addr().As4(), dst.Addr().As4()
		addr = append(addr, s[:]...)
		addr = append(addr, d[:]...)
	} else {
		h = append(h, 0x21, 0x21) // PROXY, TCP over IPv6
		s, d := src.Addr().As16(), dst.Addr().As16()
		addr = append(addr, s[:]...)
		addr = append(addr, d[:]...)
	}
	addr = binary.BigEndian.AppendUint16(addr, src.Port())
	addr = binary.BigEndian.AppendUint16(addr, dst.Port())
	h = binary.BigEndian.AppendUint16(h, uint16(len(addr)))
	return append(h, addr...)
}

// ErrNotProxy is a stream that does not start with the signature.
var ErrNotProxy = errors.New("no PROXY v2 header")

// Read reads one header from the start of a stream: the claimed source and destination. A LOCAL
// command answers zero addresses and ok.
func Read(r io.Reader) (src, dst netip.AddrPort, err error) {
	var fixed [16]byte
	if _, err := io.ReadFull(r, fixed[:]); err != nil {
		return src, dst, err
	}
	if string(fixed[:12]) != string(signature) || fixed[12]>>4 != 2 {
		return src, dst, ErrNotProxy
	}
	n := int(binary.BigEndian.Uint16(fixed[14:16]))
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return src, dst, err
	}
	if fixed[12]&0x0f == 0 { // LOCAL
		return src, dst, nil
	}
	switch fixed[13] {
	case 0x11:
		if n < 12 {
			return src, dst, fmt.Errorf("short IPv4 header: %d", n)
		}
		src = netip.AddrPortFrom(netip.AddrFrom4([4]byte(body[0:4])), binary.BigEndian.Uint16(body[8:10]))
		dst = netip.AddrPortFrom(netip.AddrFrom4([4]byte(body[4:8])), binary.BigEndian.Uint16(body[10:12]))
	case 0x21:
		if n < 36 {
			return src, dst, fmt.Errorf("short IPv6 header: %d", n)
		}
		src = netip.AddrPortFrom(netip.AddrFrom16([16]byte(body[0:16])), binary.BigEndian.Uint16(body[32:34]))
		dst = netip.AddrPortFrom(netip.AddrFrom16([16]byte(body[16:32])), binary.BigEndian.Uint16(body[34:36]))
	default:
		return src, dst, fmt.Errorf("unsupported family %#x", fixed[13])
	}
	return src, dst, nil
}

// AddrPortOf is a net.Addr as an AddrPort (zero for anything that is no TCP/UDP address).
func AddrPortOf(a net.Addr) netip.AddrPort {
	switch t := a.(type) {
	case *net.TCPAddr:
		return t.AddrPort()
	case *net.UDPAddr:
		return t.AddrPort()
	}
	ap, _ := netip.ParseAddrPort(a.String())
	return ap
}
