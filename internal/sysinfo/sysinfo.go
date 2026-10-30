// Package sysinfo is what the addon asks the system about, with its own API token: whether the
// token is accepted and what it holds, whether the declared UDP port is open on the firewall, whether
// the system's backups go out unencrypted (the server key is in them), and the system's own
// addresses and name (hints for the public endpoint). Everything here is read-only and cached for a
// short while; the page shows it, the daemon never acts on it.
package sysinfo

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Facts is what the page shows about the system.
type Facts struct {
	// Checked is false until the system answered once.
	Checked bool `json:"checked"`
	// TokenOK: the system accepts the addon's token.
	TokenOK bool     `json:"token_ok"`
	Scopes  []string `json:"scopes"`
	Error   string   `json:"error,omitempty"`
	// PortOpen: the firewall holds an active rule of this addon for the UDP port (the switch on the
	// Addons page); nil when unknown.
	PortOpen *bool `json:"port_open,omitempty"`
	// PortRuleFor is the port the firewall rule names, when there is one.
	PortRuleFor int `json:"port_rule_for,omitempty"`
	// BackupUnencrypted: the system's warning backup-unencrypted is up.
	BackupUnencrypted bool `json:"backup_unencrypted"`
	// Hostname and Domain of the system.
	Hostname string `json:"hostname,omitempty"`
	Domain   string `json:"domain,omitempty"`
	// Addresses are the system's own addresses (IPv4 first), without the loopback.
	Addresses []string `json:"addresses"`
	// At is when the facts were read, unix milliseconds.
	At int64 `json:"at"`
}

// Client reads the facts.
type Client struct {
	// Base is the system's URL, http://127.0.0.1 by default.
	Base string
	// HTTP carries the addon's token (addonkit.AuthTransport).
	HTTP *http.Client
	// AddonID is this addon's id (the firewall rule's owner is addon:<id>).
	AddonID string
	// Port answers the configured UDP port (the firewall rule is looked up for it).
	Port func() int
	// TTL is how long facts are kept, 15 s by default.
	TTL time.Duration
	Log func(format string, args ...any)

	mu    sync.Mutex
	facts Facts
	at    time.Time
}

func (c *Client) base() string {
	if c.Base == "" {
		return "http://127.0.0.1"
	}
	return strings.TrimRight(c.Base, "/")
}

func (c *Client) get(ctx context.Context, path string, v any) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", c.base()+path, nil)
	if err != nil {
		return err
	}
	res, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	if res.StatusCode != 200 {
		return fmt.Errorf("%s: %d %s", path, res.StatusCode, strings.TrimSpace(string(body)))
	}
	return json.Unmarshal(body, v)
}

// Facts answers the cached facts, read anew when older than TTL or when force is set.
func (c *Client) Facts(ctx context.Context, force bool) Facts {
	c.mu.Lock()
	defer c.mu.Unlock()
	ttl := c.TTL
	if ttl == 0 {
		ttl = 15 * time.Second
	}
	if !force && c.facts.Checked && time.Since(c.at) < ttl {
		return c.facts
	}
	f := Facts{Checked: true, Scopes: []string{}, Addresses: []string{}, At: time.Now().UnixMilli()}
	var st struct {
		Authenticated bool     `json:"authenticated"`
		Scopes        []string `json:"scopes"`
	}
	if err := c.get(ctx, "/api/auth/v1/state", &st); err != nil {
		f.Error = err.Error()
		c.facts, c.at = f, time.Now()
		return f
	}
	f.TokenOK = st.Authenticated
	if st.Scopes != nil {
		f.Scopes = st.Scopes
	}
	if !f.TokenOK {
		f.Error = "the token is not accepted"
	}
	var fw struct {
		Config struct {
			Rules []struct {
				Port     int    `json:"port"`
				Proto    string `json:"proto"`
				Owner    string `json:"owner"`
				Disabled bool   `json:"disabled"`
			} `json:"rules"`
		} `json:"config"`
	}
	if err := c.get(ctx, "/api/system/v1/firewall", &fw); err == nil {
		open := false
		port := 0
		if c.Port != nil {
			port = c.Port()
		}
		for _, r := range fw.Config.Rules {
			if r.Owner == "addon:"+c.AddonID && r.Port == port && !r.Disabled {
				open = true
				f.PortRuleFor = r.Port
			}
		}
		f.PortOpen = &open
	} else if c.Log != nil {
		c.Log("system: firewall: %v", err)
	}
	var w struct {
		Warnings []struct {
			ID string `json:"id"`
		} `json:"warnings"`
	}
	if err := c.get(ctx, "/api/system/v1/warnings", &w); err == nil {
		for _, x := range w.Warnings {
			if x.ID == "backup-unencrypted" {
				f.BackupUnencrypted = true
			}
		}
	}
	var n struct {
		Network struct {
			Hostname   string `json:"hostname"`
			Domain     string `json:"domain"`
			Interfaces []struct {
				Name string `json:"name"`
				IPv4 []struct {
					Address string `json:"address"`
				} `json:"ipv4"`
				IPv6 []struct {
					Address string `json:"address"`
					Scope   string `json:"scope"`
				} `json:"ipv6"`
			} `json:"interfaces"`
		} `json:"network"`
	}
	if err := c.get(ctx, "/api/system/v1/network", &n); err == nil {
		f.Hostname, f.Domain = n.Network.Hostname, n.Network.Domain
		var v6 []string
		for _, i := range n.Network.Interfaces {
			for _, a := range i.IPv4 {
				f.Addresses = append(f.Addresses, a.Address)
			}
			for _, a := range i.IPv6 {
				if a.Scope == "global" || a.Scope == "" {
					v6 = append(v6, a.Address)
				}
			}
		}
		f.Addresses = append(f.Addresses, v6...)
	}
	c.facts, c.at = f, time.Now()
	return f
}

// Await waits until the system answers and the token is accepted (at boot the web server answers
// 503 until the system service is up; the token may not exist yet).
func (c *Client) Await(ctx context.Context) (Facts, error) {
	delay := time.Second
	for {
		f := c.Facts(ctx, true)
		if f.Error == "" {
			return f, nil
		}
		if c.Log != nil {
			c.Log("waiting for the system: %s", f.Error)
		}
		select {
		case <-ctx.Done():
			return f, ctx.Err()
		case <-time.After(delay):
		}
		if delay < 15*time.Second {
			delay *= 2
		}
	}
}
