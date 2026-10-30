// Package addonpkg tests the package files the addon ships.
package addonpkg

import (
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/hobbyquaker/ccu-addon-kit/go/addonkit/fragment"
	"github.com/hobbyquaker/ccu-addon-kit/go/addonkit/manifest"
)

// The manifest as the system validates it at install, through the kit's strict load.
func TestManifest(t *testing.T) {
	m, err := manifest.Load("../../addon/openccu-lite.json")
	if err != nil {
		t.Fatal(err)
	}
	if m.ID != "wireguard" || m.Undeclared() || m.Runtime == nil || !m.Runtime.Daemon {
		t.Fatalf("manifest: %+v", m)
	}
	// no capability, no root, no group: WireGuard runs in userspace
	if m.Runtime.Root || len(m.Runtime.Capabilities) != 0 || len(m.Runtime.Groups) != 0 {
		t.Errorf("the addon needs no privilege: %+v", m.Runtime)
	}
	if len(m.Runtime.Ports) != 1 || m.Runtime.Ports[0] != 51820 || m.Runtime.PortInfo["51820"].Proto != "udp" {
		t.Errorf("the one declared port is UDP 51820: %+v %+v", m.Runtime.Ports, m.Runtime.PortInfo)
	}
	if len(m.Runtime.APIScopes) != 1 || m.Runtime.APIScopes[0] != "system:read" {
		t.Errorf("scopes %v", m.Runtime.APIScopes)
	}
	// the web ingress: the tunnel network, nothing else
	if m.Runtime.WebIngress == nil || len(m.Runtime.WebIngress.Ranges) != 1 || m.Runtime.WebIngress.Ranges[0] != "10.77.0.0/24" {
		t.Errorf("web_ingress %+v", m.Runtime.WebIngress)
	}
	if m.Description["de"] == "" || m.Description["en"] == "" || m.Runtime.Note["de"] == "" || m.Runtime.Note["en"] == "" {
		t.Error("the description and the note in both languages")
	}
	if !strings.Contains(m.Runtime.Note["en"], "51820") || !strings.Contains(m.Runtime.Note["en"], "10.77.0.0/24") {
		t.Error("the note names the port and the range")
	}
	if m.Requires.Lite != "1.1.0" {
		t.Errorf("requires.lite %q: the ingress needs 1.1.0-dev.6 or newer", m.Requires.Lite)
	}
}

// The manifest's version is the changelog's newest.
func TestVersionInChangelog(t *testing.T) {
	var m struct {
		Version string `json:"version"`
	}
	b, _ := os.ReadFile("../../addon/openccu-lite.json")
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	cl, err := os.ReadFile("../../CHANGELOG.md")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(cl), "## ["+m.Version+"]") {
		t.Errorf("CHANGELOG.md has no entry for %s", m.Version)
	}
}

// The manifest's images are tracked at the path the catalogue reads them from.
func TestImagesTracked(t *testing.T) {
	for _, p := range []string{"addon/wireguard/www/icon.svg", "addon/wireguard/www/icon-dark.svg", "addon/wireguard/etc/lighttpd.conf", "addon/wireguard/www/lighttpd-error-503.html"} {
		if out, err := exec.Command("git", "-C", "../..", "ls-files", "--error-unmatch", "--", p).CombinedOutput(); err != nil {
			t.Errorf("%s not tracked: %v %s", p, err, out)
		}
	}
}

// The proxy rule is what the kit's renderer writes (apart from the comment lines).
func TestFragment(t *testing.T) {
	want, err := fragment.Render(fragment.Fragment{ID: "wireguard", Port: 8298, ErrorfilePrefix: "/usr/local/addons/wireguard/www/lighttpd-error-"})
	if err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile("../../addon/wireguard/etc/lighttpd.conf")
	strip := func(s string) string {
		var out []string
		for _, l := range strings.Split(s, "\n") {
			if !strings.HasPrefix(l, "#") && strings.TrimSpace(l) != "" {
				out = append(out, l)
			}
		}
		return strings.Join(out, "\n")
	}
	if strip(string(got)) != strip(want) {
		t.Errorf("etc/lighttpd.conf:\n%s\nwant:\n%s", got, want)
	}
}

// The 503 page names the addon, in the tracked copy and the one the build copies.
func TestErrorPage(t *testing.T) {
	for _, p := range []string{"../../addon/static/lighttpd-error-503.html", "../../addon/wireguard/www/lighttpd-error-503.html"} {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(b), "<title>VPN (WireGuard)</title>") {
			t.Errorf("%s does not name the addon", p)
		}
	}
}

// The rc.d script and the update_script name no other addon and are sh scripts.
func TestScripts(t *testing.T) {
	for _, p := range []string{"../../addon/wireguard/rc.d", "../../addon/update_script"} {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		for _, other := range []string{"snmp", "forwarder", "nut", "UPS", "upsd"} {
			if strings.Contains(string(b), other) {
				t.Errorf("%s names another addon: %s", p, other)
			}
		}
		if !strings.HasPrefix(string(b), "#!/bin/sh\n") {
			t.Errorf("%s is not a sh script", p)
		}
	}
	rc, _ := os.ReadFile("../../addon/wireguard/rc.d")
	if !strings.Contains(string(rc), "ADDON=wireguard\n") || !strings.Contains(string(rc), `DAEMON_ARGS="-addon-dir $ADDON_DIR"`) {
		t.Error("rc.d: the addon name or the daemon's arguments")
	}
}
