package dnsrole

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"time"

	"github.com/miekg/dns"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sock"
	"github.com/Kup1ng/CtrlZ-Node/internal/dns/cookie"
	"github.com/Kup1ng/CtrlZ-Node/internal/dns/limits"
	"github.com/Kup1ng/CtrlZ-Node/internal/dns/listen"
	"github.com/Kup1ng/CtrlZ-Node/internal/store"
	"github.com/Kup1ng/CtrlZ-Node/internal/store/image"
	"github.com/Kup1ng/CtrlZ-Node/internal/store/nodecfg"
)

// HandlerFactory builds the query path. It is the one seam between this package
// and the query path of SC 5.2: the factory gets the Env to read and the Sink to
// report to, and returns the Handler and the verify hook (nil for none).
type HandlerFactory func(env *Env, sink *Sink) (listen.Handler, listen.VerifyHandler, error)

// Config is what the role needs.
type Config struct {
	// Root is /var/lib/ctrlz (dns reads image/, blobs/ and config/ there and nothing else).
	Root string
	// AgentConf is /etc/ctrlz/agent.conf, for the Plain-only fallback's bind address.
	AgentConf string
	// SockPath is /run/ctrlz/agent.sock.
	SockPath string
	// Ports defaults to 53, 853 and 443.
	Ports listen.Ports
	// Build builds the query path; nil means RefuseHandler.
	Build HandlerFactory
	// Observer receives the listeners' counts, optional.
	Observer listen.Observer
	// Drain overrides the numbers of the drain rule; a test shortens them. Nil takes
	// the rule's own (SC 8a.6).
	Drain *DrainTimes
	// OnReady, when set, is called with the bound addresses once the listeners are up.
	OnReady func(*listen.Server)
}

// RefuseHandler answers every Plain, DoT and DoQ query REFUSED and every DoH
// request with 404. It is what the node runs until the query path is joined:
// nothing it says is wrong, because it says nothing.
func RefuseHandler(*Env, *Sink) (listen.Handler, listen.VerifyHandler, error) {
	return listen.HandlerFunc(func(_ context.Context, r *listen.Request) listen.Reply {
		if r.HTTP != nil {
			return listen.Reply{Status: http.StatusNotFound}
		}
		return listen.Reply{Msg: listen.Refused(r.Msg)}
	}), nil, nil
}

// Run is the dns role. It returns when ctx ends or a listener cannot start.
func Run(ctx context.Context, cfg Config) error {
	if cfg.Ports == (listen.Ports{}) {
		cfg.Ports = listen.DefaultPorts()
	}
	if cfg.Build == nil {
		cfg.Build = RefuseHandler
	}
	env := newEnv()
	env.ctx = ctx
	imagesDir := filepath.Join(cfg.Root, store.DirImage)

	serving, err := nodecfg.New(filepath.Join(cfg.Root, store.DirConfig), nil).LoadServing(cfg.AgentConf)
	if err != nil {
		return fmt.Errorf("dnsrole: no address to bind: %w", err)
	}
	lcfg := listen.Config{Ports: cfg.Ports, Observer: cfg.Observer}
	switch serving.Source {
	case nodecfg.PlainOnly:
		// No valid NodeConfig on disk: Plain UDP and TCP on the address the install
		// wrote, serving from image/ with no zone answers (7.2).
		lcfg.Bind = serving.PlainBind
		lcfg.Transports = []listen.Transport{listen.UDP, listen.TCP}
	default:
		ip, ok := addrOf(serving.Config.DnsBindIp)
		if !ok {
			return errors.New("dnsrole: the NodeConfig has no bind address")
		}
		lcfg.Bind = ip
		if b, err := marshalConfig(serving.Config); err == nil {
			env.setConfig(b) // proof_key zeroed: the real one comes from the agent
		}
	}
	if im, err := image.OpenCurrent(imagesDir); err == nil {
		env.image.Store(im)
	}

	exempt := limits.NewExemption()
	exempt.SetZones(env.Zones())
	set, err := limits.NewSet(limits.Default())
	if err != nil {
		return fmt.Errorf("dnsrole: limits: %w", err)
	}
	jar, err := cookie.New()
	if err != nil {
		return fmt.Errorf("dnsrole: cookies: %w", err)
	}
	go rotateCookies(ctx, jar)

	drain := newDrainCtl(env)
	if cfg.Drain != nil {
		drain.times = *cfg.Drain
	}
	var cl *sock.Client
	sink := newSink(func(m *sock.Msg) bool { return cl != nil && cl.Send(m) })
	handler, verify, err := cfg.Build(env, sink)
	if err != nil {
		return fmt.Errorf("dnsrole: query path: %w", err)
	}

	cl = sock.NewClient(cfg.SockPath, sock.ClientHandlers{
		Message: func(m *sock.Msg) {
			env.apply(m, imagesDir, func(n string) { cl.Send(ackMsg(n)) }, exempt)
			if m.Type == sock.TypeTable {
				drain.sync() // the drain rule follows drain_since (SC 8a.6)
			}
		},
		State: env.setLink,
	})
	go cl.Run(ctx)
	go sink.run(ctx)

	lcfg.Handler, lcfg.Verify = handler, verify
	lcfg.Limits, lcfg.Exempt, lcfg.Cookies = set, exempt, jar
	lcfg.GetCertificate = env.GetCertificate
	srv, err := listen.Start(ctx, lcfg)
	if err != nil {
		return fmt.Errorf("dnsrole: listeners: %w", err)
	}
	drain.attach(srv)
	if cfg.OnReady != nil {
		cfg.OnReady(srv)
	}
	<-ctx.Done()
	srv.Close()
	return nil
}

func ackMsg(name string) *sock.Msg {
	return &sock.Msg{Type: sock.TypeImageAck, ImageAck: &sock.ImageAck{Name: name}}
}

// apply folds one message of the agent into the Env.
func (e *Env) apply(m *sock.Msg, imagesDir string, ack func(string), exempt *limits.Exemption) {
	switch m.Type {
	case sock.TypeImage:
		if m.Image == nil {
			return
		}
		if im, err := openImage(imagesDir, m.Image.Name); err == nil {
			e.image.Store(im)
			n := m.Image.Name
			e.imgName.Store(&n)
			// The query path swaps to the image before dns confirms it: the agent ends
			// a revocation on the confirmation, so it has to mean "served from this".
			e.applied(m.Type)
			ack(n)
		}
		// An image that does not open leaves the last one serving.
	case sock.TypeTable:
		if m.Table != nil {
			e.setTable(m.Table)
		}
	case sock.TypeFacts:
		if m.Facts != nil {
			e.setFacts(*m.Facts)
		}
	case sock.TypeConfig:
		if m.Config != nil {
			e.setConfig(m.Config.NodeConfig)
			exempt.SetZones(e.Zones())
		}
	case sock.TypeZoneKey:
		if m.ZoneKey != nil {
			_ = e.setZoneKey(m.ZoneKey)
		}
	case sock.TypeRevocations:
		if m.Revocations != nil {
			items := append([]sock.RevItem(nil), m.Revocations.Items...)
			e.revs.Store(&items)
		}
	case sock.TypeAcme:
		if m.Acme != nil {
			e.setAcme(m.Acme)
		}
	case sock.TypeLocations, sock.TypeGrantIn, sock.TypeGrantSent:
		// The P4b messages carry no state the Env keeps: the query path's Grants take
		// them (querypath), through the hook.
		if f := e.onMsg.Load(); f != nil {
			(*f)(m)
		}
	}
	if m.Type != sock.TypeImage { // an image reports itself above, before its ack
		e.applied(m.Type)
	}
}

// openImage opens the image the agent named. The agent publishes after it has
// made the image current, so the link normally points at it; a link that has
// moved on again is followed by name.
func openImage(imagesDir, name string) (*image.Image, error) {
	if cur, err := image.CurrentName(imagesDir); err == nil && cur == name {
		if im, err := image.OpenCurrent(imagesDir); err == nil {
			return im, nil
		}
	}
	if name == "" || name != filepath.Base(name) {
		return nil, errors.New("dnsrole: not an image name")
	}
	return image.Open(filepath.Join(imagesDir, name))
}

func rotateCookies(ctx context.Context, j *cookie.Jar) {
	t := time.NewTicker(24 * time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_ = j.Rotate()
		}
	}
}

var _ = dns.TypeSOA
