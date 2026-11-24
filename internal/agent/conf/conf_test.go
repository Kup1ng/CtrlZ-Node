package conf

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Kup1ng/CtrlZ-Node/internal/store/nodecfg"
)

const good = `# written by install
hub=panel.example.net:9443
dns_bind_ip = 10.0.0.5
dns_advertised_ip=203.0.114.9

proxy_bind_ip=10.0.0.6
proxy_advertised_ip=203.0.114.10
free_outgoing_interface=198.51.101.7
`

func TestParse(t *testing.T) {
	a, err := Parse(strings.NewReader(good))
	if err != nil {
		t.Fatal(err)
	}
	if a.Hub != "panel.example.net:9443" || a.HubHost() != "panel.example.net" || a.HubAddr() != "panel.example.net:9443" {
		t.Errorf("hub %q %q %q", a.Hub, a.HubHost(), a.HubAddr())
	}
	if a.DNSBindIP != netip.MustParseAddr("10.0.0.5") || a.DNSAdvertisedIP != netip.MustParseAddr("203.0.114.9") || a.FreeOutgoingInterface != netip.MustParseAddr("198.51.101.7") {
		t.Errorf("%+v", a)
	}
	if len(a.Panel()) != 0 {
		t.Error("a host name gives no address for the NTP rule")
	}
}

func TestHubForms(t *testing.T) {
	for in, want := range map[string]string{"198.51.100.20": "198.51.100.20:9443", "198.51.100.20:1234": "198.51.100.20:1234", "[2001:db8::1]:9443": "[2001:db8::1]:9443", "2001:db8::1": "[2001:db8::1]:9443", "panel.example": "panel.example:9443"} {
		a, err := Parse(strings.NewReader("hub=" + in + "\ndns_bind_ip=10.0.0.5\n"))
		if err != nil || a.HubAddr() != want {
			t.Errorf("%q -> %q, %v", in, a.HubAddr(), err)
		}
	}
	a, _ := Parse(strings.NewReader("hub=198.51.100.20\ndns_bind_ip=10.0.0.5\n"))
	if p := a.Panel(); len(p) != 1 || p[0] != netip.MustParseAddr("198.51.100.20") {
		t.Errorf("panel %v", p)
	}
}

func TestStrict(t *testing.T) {
	for name, in := range map[string]string{
		"unknown key":    "hub=h\ndns_bind_ip=10.0.0.5\nfoo=1\n",
		"repeated key":   "hub=h\nhub=g\ndns_bind_ip=10.0.0.5\n",
		"no hub":         "dns_bind_ip=10.0.0.5\n",
		"no bind":        "hub=h\n",
		"bad address":    "hub=h\ndns_bind_ip=nope\n",
		"unspecified":    "hub=h\ndns_bind_ip=0.0.0.0\n",
		"multicast":      "hub=h\ndns_bind_ip=224.0.0.1\n",
		"not key=value":  "hub=h\ndns_bind_ip=10.0.0.5\njunk\n",
		"hub with space": "hub=a b\ndns_bind_ip=10.0.0.5\n",
		"bad panel list": "hub=h\ndns_bind_ip=10.0.0.5\npanel_addrs=1.1.1.1,zz\n",
	} {
		if _, err := Parse(strings.NewReader(in)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// nodecfg.ReadBindIP and this parser agree on the file, which is what the
// Plain-only fallback of 7.2 relies on.
func TestAgreesWithNodecfgReadBindIP(t *testing.T) {
	p := filepath.Join(t.TempDir(), "agent.conf")
	if err := os.WriteFile(p, []byte(good), 0o600); err != nil {
		t.Fatal(err)
	}
	ip, err := nodecfg.ReadBindIP(p)
	a, err2 := Read(p)
	if err != nil || err2 != nil || ip != a.DNSBindIP {
		t.Fatalf("%v %v %v %v", ip, a.DNSBindIP, err, err2)
	}
}
