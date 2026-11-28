package sock

import (
	"context"
	"net"
	"sync"
	"time"
)

// ClientHandlers receive what the agent sends and the state of the link.
type ClientHandlers struct {
	// Message is called for every frame from the agent, on the reader goroutine.
	Message func(m *Msg)
	// State is called with true after the connection is made and with false when
	// it ends. dns takes the free path as off while the last call was false.
	State func(up bool)
}

// Client is dns's end. It reconnects on its own, so a restart of the agent costs
// dns only the time to reconnect, and dns keeps its last image meanwhile.
type Client struct {
	path string
	h    ClientHandlers

	mu  sync.Mutex
	out chan *Msg
	up  bool
}

// NewClient returns a Client for the socket at path.
func NewClient(path string, h ClientHandlers) *Client {
	return &Client{path: path, h: h}
}

// Up reports whether the link is up.
func (c *Client) Up() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.up
}

// Send queues a message for the agent. It never blocks and reports false when
// the link is down or the queue is full: counters and activity are best effort,
// and a message dns cannot send now is dropped rather than held in memory.
func (c *Client) Send(m *Msg) bool {
	// Checked before queueing: the writer goroutine would otherwise fail on a bad
	// P4b message and close the whole link, with the image acks and counters on it.
	if checkEnvelope(m) != nil {
		return false
	}
	c.mu.Lock()
	out := c.out
	c.mu.Unlock()
	if out == nil {
		return false
	}
	select {
	case out <- m:
		return true
	default:
		return false
	}
}

// Run connects and serves until ctx ends.
func (c *Client) Run(ctx context.Context) {
	backoff := 100 * time.Millisecond
	for ctx.Err() == nil {
		nc, err := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "unix", c.path)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			if backoff < 5*time.Second {
				backoff *= 2
			}
			continue
		}
		backoff = 100 * time.Millisecond
		c.session(ctx, nc)
	}
}

func (c *Client) session(ctx context.Context, nc net.Conn) {
	out := make(chan *Msg, sendQueue)
	done := make(chan struct{})
	var once sync.Once
	stop := func() { once.Do(func() { close(done); _ = nc.Close() }) }
	defer stop()
	go func() {
		select {
		case <-ctx.Done():
			stop()
		case <-done:
		}
	}()
	go func() {
		for {
			select {
			case m := <-out:
				_ = nc.SetWriteDeadline(time.Now().Add(writeTimeout))
				if err := Write(nc, m, MaxFrameFromDNS); err != nil {
					stop()
					return
				}
			case <-done:
				return
			}
		}
	}()
	c.mu.Lock()
	c.out, c.up = out, true
	c.mu.Unlock()
	if c.h.State != nil {
		c.h.State(true)
	}
	for {
		m, err := Read(nc, MaxFrameToDNS)
		if err != nil {
			break
		}
		if c.h.Message != nil {
			func() {
				defer func() { _ = recover() }()
				c.h.Message(m)
			}()
		}
	}
	stop()
	c.mu.Lock()
	c.out, c.up = nil, false
	c.mu.Unlock()
	if c.h.State != nil {
		c.h.State(false)
	}
}
