package listen

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go/http3"
)

// Server is the set of listeners the caller asked for, all bound to the one
// address of Config.Bind. Nothing else listens.
type Server struct {
	cancel context.CancelFunc
	hs     *handshakes
	doh3   *doh3Server // for tests that look into the connections
	addrs  map[Transport]netip.AddrPort

	closers []func()
	wg      sync.WaitGroup
	once    sync.Once
}

// Start binds the listeners and starts serving. Every socket is bound before
// it returns, so an error means nothing is left running. The context ends the
// handlers' contexts; call Close to stop the sockets.
func Start(ctx context.Context, cfg Config) (*Server, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	s := &Server{cancel: cancel, addrs: map[Transport]netip.AddrPort{}}
	if err := s.start(ctx, &cfg); err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}

func (s *Server) start(ctx context.Context, cfg *Config) error {
	hs := &handshakes{forceRetry: cfg.ForceRetry}
	s.hs = hs
	var starters []func()
	for _, t := range cfg.transports() {
		c, err := newCore(ctx, cfg, t)
		if err != nil {
			return err
		}
		ap := netip.AddrPortFrom(cfg.Bind, cfg.Ports.of(t))
		switch t {
		case UDP:
			conn, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(ap))
			if err != nil {
				return fmt.Errorf("listen: %s: %w", t, err)
			}
			srv := newUDP(c, conn)
			s.add(t, conn.LocalAddr(), srv.close, srv.start, &starters)
		case TCP:
			ln, err := net.Listen("tcp", ap.String())
			if err != nil {
				return fmt.Errorf("listen: %s: %w", t, err)
			}
			srv := newStream(c, ln, nil)
			s.add(t, ln.Addr(), srv.close, srv.start, &starters)
		case DoT:
			ln, err := net.Listen("tcp", ap.String())
			if err != nil {
				return fmt.Errorf("listen: %s: %w", t, err)
			}
			srv := newStream(c, ln, cfg.tlsConfig(nil))
			s.add(t, ln.Addr(), srv.close, srv.start, &starters)
		case DoH:
			ln, err := net.Listen("tcp", ap.String())
			if err != nil {
				return fmt.Errorf("listen: %s: %w", t, err)
			}
			// h2 must be named or net/http does not enable HTTP/2.
			srv := newDoH(c, ln, cfg.tlsConfig([]string{"h2", "http/1.1"}), cfg.Verify)
			s.add(t, ln.Addr(), srv.close, srv.start, &starters)
		case DoQ, DoH3:
			conn, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(ap))
			if err != nil {
				return fmt.Errorf("listen: %s: %w", t, err)
			}
			if t == DoQ {
				b, err := newQUICBase(c, hs, conn, cfg.tlsConfig([]string{"doq"}), false)
				if err != nil {
					_ = conn.Close()
					return fmt.Errorf("listen: %s: %w", t, err)
				}
				srv := newDoQ(b)
				s.add(t, conn.LocalAddr(), srv.close, srv.start, &starters)
			} else {
				b, err := newQUICBase(c, hs, conn, http3.ConfigureTLSConfig(cfg.tlsConfig(nil)), true)
				if err != nil {
					_ = conn.Close()
					return fmt.Errorf("listen: %s: %w", t, err)
				}
				srv := newDoH3(b, cfg.Verify)
				s.doh3 = srv
				s.add(t, conn.LocalAddr(), srv.close, srv.start, &starters)
			}
		}
	}
	for _, f := range starters {
		f()
	}
	if cfg.Cookies != nil {
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			// The secret changes once a day; the one before it still verifies, so
			// a cookie is good for the hour of RFC 9018 whatever the hour of the
			// day it was made. The secret is never written anywhere (SC 8a.3).
			tk := time.NewTicker(24 * time.Hour)
			defer tk.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-tk.C:
					_ = cfg.Cookies.Rotate()
				}
			}
		}()
	}
	return nil
}

func (s *Server) add(t Transport, a net.Addr, closeFn, startFn func(), starters *[]func()) {
	if ap, ok := addrPort(a); ok {
		s.addrs[t] = ap
	}
	s.closers = append(s.closers, closeFn)
	*starters = append(*starters, startFn)
}

// Addr returns the bound address of a listener, for tests that bind port 0 or
// need the port they were given.
func (s *Server) Addr(t Transport) (netip.AddrPort, bool) {
	ap, ok := s.addrs[t]
	return ap, ok
}

// Close stops every listener and closes every accepted connection. It is
// safe to call twice.
func (s *Server) Close() {
	s.once.Do(func() {
		s.cancel()
		for _, f := range s.closers {
			f()
		}
		s.wg.Wait()
	})
}

// sniTag marks the entry of SessionState.Extra that holds the name a session
// was issued for.
const sniTag = "ctrlz-sni:"

// tlsConfig is the TLS configuration of one listener. Session tickets stay on,
// because resumption is what makes a DoT or DoH client cheap on a mobile link,
// but a ticket is tied to the name it was issued for. A resumption skips the
// certificate provider (crypto/tls only calls GetCertificate on a full
// handshake), so without the tie a ticket issued for a good name would carry
// any other name through the handshake, and the refusal of an unknown resolver
// ID with unrecognized_name (SC 3.3, R7) would hold only for a client that never
// held a ticket (p4n-W6-r3-2). A ticket for another name is not used: the
// handshake is a full one, and GetCertificate decides again.
func (c *Config) tlsConfig(alpn []string) *tls.Config {
	conf := &tls.Config{
		GetCertificate: c.GetCertificate,
		MinVersion:     tls.VersionTLS12,
		NextProtos:     alpn,
	}
	// The closures use conf itself for the encryption, so the ticket keys are
	// the one set this config owns, whatever copy quic-go makes of it.
	conf.WrapSession = func(cs tls.ConnectionState, ss *tls.SessionState) ([]byte, error) {
		ss.Extra = append(ss.Extra, []byte(sniTag+strings.ToLower(cs.ServerName)))
		return conf.EncryptTicket(cs, ss)
	}
	conf.UnwrapSession = func(identity []byte, cs tls.ConnectionState) (*tls.SessionState, error) {
		ss, err := conf.DecryptTicket(identity, cs)
		if err != nil || ss == nil {
			return nil, nil // not ours or not readable: a full handshake
		}
		want := sniTag + strings.ToLower(cs.ServerName)
		for _, e := range ss.Extra {
			if string(e) == want {
				// The name was good when the ticket was issued; ask the provider
				// again, because a resolver ID that was rotated or revoked since must
				// get the unrecognized_name refusal and not a resumption that skips
				// the provider for up to the ticket's 7 days (p4n-W6-r4-3). The
				// provider sees the server name only, which is all SC 3.3 uses.
				if !c.nameStillGood(cs.ServerName) {
					return nil, nil // a full handshake, where the provider refuses it
				}
				return ss, nil
			}
		}
		return nil, nil
	}
	return conf
}

// nameStillGood asks the certificate provider whether it still serves name. It
// is called from UnwrapSession, inside crypto/tls, with a ClientHelloInfo that has
// only ServerName, which is all SC 3.3 uses. crypto/tls runs no recover, and a
// panic here would end the DNS process for every tenant, so a provider that
// reads what this call does not carry is taken as "not good": the handshake is a
// full one, where the provider runs with the real hello (p4n-W6-r5-5).
func (c *Config) nameStillGood(name string) (ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	crt, err := c.GetCertificate(&tls.ClientHelloInfo{ServerName: name})
	return err == nil && crt != nil
}
