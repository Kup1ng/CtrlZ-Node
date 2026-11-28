package proxy

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sock"
)

// link is one connection to dns over proxy.sock (5.1). dns is the server; the proxy
// connects, says hello, lists what it holds, and then asks for sources and verdicts.
// A link lives as long as its connection: when it ends every ask in flight fails,
// and the proxy dials a new one (with a new open list).
type link struct {
	c    net.Conn
	wmu  sync.Mutex
	done chan struct{}
	once sync.Once

	mu      sync.Mutex
	sources map[uint64]chan bool
	looks   map[uint64]chan *sock.LinkVerdict

	// onConfig, onEnd are the proxy's handlers of what dns pushes.
	onConfig func(*sock.ProxyConfig)
	onEnd    func(*sock.LinkEnd)
}

var (
	errLinkDown = errors.New("proxy: link down")
	errRefused  = errors.New("proxy: refused by dns")
)

func newLink(c net.Conn) *link {
	return &link{c: c, done: make(chan struct{}), sources: map[uint64]chan bool{}, looks: map[uint64]chan *sock.LinkVerdict{}}
}

// writeTimeout bounds one frame: dns reads quickly, and a dns that does not has
// stopped serving the link.
const writeTimeout = 5 * time.Second

func (l *link) send(m *sock.LinkMsg) error {
	l.wmu.Lock()
	defer l.wmu.Unlock()
	select {
	case <-l.done:
		return errLinkDown
	default:
	}
	_ = l.c.SetWriteDeadline(time.Now().Add(writeTimeout))
	if err := sock.LinkCodec.Write(l.c, m); err != nil {
		l.close()
		return err
	}
	return nil
}

func (l *link) close() {
	l.once.Do(func() {
		close(l.done)
		_ = l.c.Close()
	})
}

// read dispatches what dns sends until the link ends. A frame of a type that dns may
// not send ends the link (2.1: an unknown type or a failed check closes the
// connection). An answer for an id that is no longer waited on is dropped: the ask
// timed out or its connection went away, and dns cannot know that.
func (l *link) read() {
	defer l.close()
	for {
		m, err := sock.LinkCodec.Read(l.c)
		if err != nil {
			return
		}
		switch m.Type {
		case sock.TLinkConfig:
			l.onConfig(m.Config)
		case sock.TLinkEnd:
			l.onEnd(m.End)
		case sock.TLinkSourceKnown:
			l.mu.Lock()
			ch := l.sources[m.SourceKnown.ID]
			delete(l.sources, m.SourceKnown.ID)
			l.mu.Unlock()
			if ch != nil { // a late answer to an ask that timed out is not an error
				ch <- m.SourceKnown.Known
			}
		case sock.TLinkVerdict:
			l.mu.Lock()
			ch := l.looks[m.Verdict.ID]
			delete(l.looks, m.Verdict.ID)
			l.mu.Unlock()
			if ch != nil {
				ch <- m.Verdict
			}
		default:
			return
		}
	}
}

// askSource asks which pool connection id belongs to.
func (l *link) askSource(ctx context.Context, id uint64, src []byte) (bool, error) {
	ch := make(chan bool, 1)
	l.mu.Lock()
	l.sources[id] = ch
	l.mu.Unlock()
	if err := l.send(&sock.LinkMsg{Type: sock.TLinkSource, Source: &sock.LinkSource{ID: id, Source: src}}); err != nil {
		l.forget(id)
		return false, err
	}
	select {
	case k := <-ch:
		return k, nil
	case <-ctx.Done():
		l.forget(id)
		return false, ctx.Err()
	case <-l.done:
		return false, errLinkDown
	}
}

// lookup asks for the verdict of connection id.
func (l *link) lookup(ctx context.Context, id uint64, src, name []byte, port uint16) (*sock.LinkVerdict, error) {
	ch := make(chan *sock.LinkVerdict, 1)
	l.mu.Lock()
	l.looks[id] = ch
	l.mu.Unlock()
	m := &sock.LinkMsg{Type: sock.TLinkLookup, Lookup: &sock.LinkLookup{ID: id, Source: src, Name: name, Port: port}}
	if err := l.send(m); err != nil {
		l.forget(id)
		return nil, err
	}
	select {
	case v := <-ch:
		return v, nil
	case <-ctx.Done():
		l.forget(id)
		return nil, ctx.Err()
	case <-l.done:
		return nil, errLinkDown
	}
}

func (l *link) forget(id uint64) {
	l.mu.Lock()
	delete(l.sources, id)
	delete(l.looks, id)
	l.mu.Unlock()
}
