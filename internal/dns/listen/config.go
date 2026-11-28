package listen

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net/netip"

	"github.com/Kup1ng/CtrlZ-Node/internal/dns/cookie"
	"github.com/Kup1ng/CtrlZ-Node/internal/dns/limits"
)

// Ports are the three port numbers of the node. DoH3 shares the DoH number on
// UDP, and DoQ the DoT number on UDP, as in production (443 and 853). They are
// parameters so a test binds high ports.
type Ports struct {
	DNS   uint16 // UDP and TCP, 53
	TLS   uint16 // DoT on TCP and DoQ on UDP, 853
	HTTPS uint16 // DoH on TCP and DoH3 on UDP, 443
}

// DefaultPorts are the production ports.
func DefaultPorts() Ports { return Ports{DNS: 53, TLS: 853, HTTPS: 443} }

func (p Ports) of(t Transport) uint16 {
	switch t {
	case UDP, TCP:
		return p.DNS
	case DoT, DoQ:
		return p.TLS
	default:
		return p.HTTPS
	}
}

// Config is everything a Server needs from its caller.
type Config struct {
	// Bind is the one address every listener binds, and nothing else listens
	// (D24). With no valid NodeConfig the caller passes the address the install
	// script wrote and Transports of UDP and TCP only (7.2).
	Bind netip.Addr

	Ports Ports

	// Transports selects the listeners to start; empty means all six.
	Transports []Transport

	// Handler is the query path.
	Handler Handler

	// Limits is the set of step-1 limits, built from limits.Default() by the
	// caller (or from a test registry). It is built outside this package so that
	// no limiter is constructed here (N5).
	Limits *limits.Set

	// Exempt is the name-form exemption of L13. Nil means none is exempt.
	Exempt *limits.Exemption

	// Settings are the listener settings; empty means limits.Listeners().
	Settings []limits.ListenerSettings

	// Cookies makes and checks server cookies for Plain DNS. Nil disables
	// cookies, which a node never does; tests may.
	Cookies *cookie.Jar

	// GetCertificate gives the certificate for a TLS or QUIC handshake, by SNI.
	// The agent hands the zone keys to the DNS process and the caller adapts
	// them into this (W5b). A handshake that must be refused (R7: SNI is a
	// HostResolver of an unknown rid) is refused by returning (nil, nil): with no
	// static certificate, crypto/tls then sends the unrecognized_name alert that
	// SC 3.3 asks for, on TCP and on QUIC. Returning an error sends internal_error
	// instead, which is not the rule (p4n-W6-r2-4).
	//
	// The provider must decide by hello.ServerName alone and must not panic. A
	// resumed session calls it a second time, with a ClientHelloInfo that has only
	// ServerName set (Conn, Context(), SignatureSchemes and SupportedVersions are
	// empty), to learn whether the name is still good; a provider that touches the
	// rest gets a panic there, which the listener recovers as "not good", and the
	// client then runs a full handshake (p4n-W6-r5-2, -5).
	GetCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error)

	// Verify serves GET /v on SNI *.verify.<zone> for DoH and DoH3. Nil means no
	// such host: the request goes to the DoH handler like any other.
	Verify VerifyHandler

	// Observer receives counts. Optional.
	Observer Observer

	// ForceRetry makes QUIC ask every source for a Retry, whatever the load. It
	// is for tests of the Retry path; production leaves it false and Retry
	// happens only over limits.RetryUnderLoad handshakes.
	ForceRetry bool
}

var (
	errNoHandler = errors.New("listen: no handler")
	errNoLimits  = errors.New("listen: no limits")
)

func (c *Config) transports() []Transport {
	if len(c.Transports) == 0 {
		return limits.All()
	}
	return c.Transports
}

func (c *Config) settings(t Transport) (limits.ListenerSettings, error) {
	ls := c.Settings
	if len(ls) == 0 {
		ls = limits.Listeners()
	}
	s, ok := limits.SettingsFor(ls, t)
	if !ok {
		return s, fmt.Errorf("listen: no settings for %s", t)
	}
	return s, nil
}

func (c *Config) validate() error {
	if c.Handler == nil {
		return errNoHandler
	}
	if c.Limits == nil {
		return errNoLimits
	}
	if !c.Bind.IsValid() || c.Bind.IsMulticast() || c.Bind.IsUnspecified() {
		// D24: the listeners bind NodeConfig.dns_bind_ip and nothing else. An
		// unspecified address would bind every interface, the management one
		// included (p4n-W6-r1-11).
		return errors.New("listen: no bind address")
	}
	for _, t := range c.transports() {
		if !t.Valid() {
			return errors.New("listen: bad transport")
		}
		if t != UDP && t != TCP && c.GetCertificate == nil {
			return fmt.Errorf("listen: %s needs a certificate provider", t)
		}
		if c.Ports.of(t) == 0 {
			return fmt.Errorf("listen: no port for %s", t)
		}
	}
	return nil
}
