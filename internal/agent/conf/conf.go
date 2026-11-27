// Package conf reads /etc/ctrlz/agent.conf, the file the install script writes
// as root (p4-nodes 7.2, 4.2): the hub's address and the four enrolled addresses.
//
// The format is lines of key=value; blank lines and lines starting with # are
// ignored. nodecfg.ReadBindIP reads dns_bind_ip from the same file with the same
// rules. The file is not tenant or network input, but it is parsed strictly: an
// unknown key, a repeated key or a value that does not parse is an error, so a
// typo is found at start and not by a node that quietly runs on defaults.
package conf

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
)

// DefaultHubPort is the node connection port of the hub (p4-nodes 5.1).
const DefaultHubPort = "9443"

// Agent is the content of agent.conf.
type Agent struct {
	// Hub is host or host:port of the hub; the host is what its TLS leaf must carry.
	Hub string
	// DNSBindIP, DNSAdvertisedIP, ProxyBindIP and ProxyAdvertisedIP are the four
	// enrolled addresses (4.2 step 3). Only the DNS ones are read by the agent in P4.
	DNSBindIP, DNSAdvertisedIP     netip.Addr
	ProxyBindIP, ProxyAdvertisedIP netip.Addr
	// FreeOutgoingInterface is the T-561 option: an address of the host in another
	// /24 that the free Unbound sends from. Optional.
	FreeOutgoingInterface netip.Addr
	// PanelAddrs optionally lists the panel's addresses for the nftables NTP rule
	// when Hub is a name. When empty and Hub is an address, that address is used.
	PanelAddrs []netip.Addr
}

// HubHost is the host part of Hub.
func (a Agent) HubHost() string {
	h, _, err := net.SplitHostPort(a.Hub)
	if err != nil {
		return strings.Trim(a.Hub, "[]")
	}
	return h
}

// HubAddr is Hub with the default port added.
func (a Agent) HubAddr() string {
	if _, _, err := net.SplitHostPort(a.Hub); err == nil {
		return a.Hub
	}
	return net.JoinHostPort(strings.Trim(a.Hub, "[]"), DefaultHubPort)
}

// Panel returns the addresses NTP may reach: PanelAddrs, or the hub host when it
// is an address.
func (a Agent) Panel() []netip.Addr {
	if len(a.PanelAddrs) > 0 {
		return a.PanelAddrs
	}
	if ip, err := netip.ParseAddr(a.HubHost()); err == nil {
		return []netip.Addr{ip}
	}
	return nil
}

// Read parses the file at path.
func Read(path string) (Agent, error) {
	f, err := os.Open(path)
	if err != nil {
		return Agent{}, err
	}
	defer f.Close()
	return Parse(f)
}

// Parse parses agent.conf from a reader.
func Parse(r io.Reader) (Agent, error) {
	var out Agent
	seen := map[string]bool{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 4096), 64<<10)
	line := 0
	for sc.Scan() {
		line++
		l := strings.TrimSpace(sc.Text())
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		k, v, ok := strings.Cut(l, "=")
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if !ok || k == "" {
			return Agent{}, fmt.Errorf("conf: line %d is not key=value", line)
		}
		if seen[k] {
			return Agent{}, fmt.Errorf("conf: %s is set twice", k)
		}
		seen[k] = true
		var err error
		addr := func(dst *netip.Addr) error {
			a, err := netip.ParseAddr(v)
			if err != nil || a.IsUnspecified() || a.IsMulticast() {
				return fmt.Errorf("conf: %s is not an address", k)
			}
			*dst = a.Unmap()
			return nil
		}
		switch k {
		case "hub":
			if v == "" || strings.ContainsAny(v, " \t/\\\"") {
				return Agent{}, errors.New("conf: hub is not a host")
			}
			out.Hub = v
		case "dns_bind_ip":
			err = addr(&out.DNSBindIP)
		case "dns_advertised_ip":
			err = addr(&out.DNSAdvertisedIP)
		case "proxy_bind_ip":
			err = addr(&out.ProxyBindIP)
		case "proxy_advertised_ip":
			err = addr(&out.ProxyAdvertisedIP)
		case "free_outgoing_interface":
			err = addr(&out.FreeOutgoingInterface)
		case "panel_addrs":
			for _, s := range strings.Split(v, ",") {
				a, perr := netip.ParseAddr(strings.TrimSpace(s))
				if perr != nil || a.IsUnspecified() || a.IsMulticast() {
					return Agent{}, errors.New("conf: panel_addrs is not a list of addresses")
				}
				out.PanelAddrs = append(out.PanelAddrs, a.Unmap())
			}
		default:
			return Agent{}, fmt.Errorf("conf: unknown key %q", k)
		}
		if err != nil {
			return Agent{}, err
		}
	}
	if err := sc.Err(); err != nil {
		return Agent{}, err
	}
	if out.Hub == "" {
		return Agent{}, errors.New("conf: hub is missing")
	}
	if !out.DNSBindIP.IsValid() {
		return Agent{}, errors.New("conf: dns_bind_ip is missing")
	}
	return out, nil
}
