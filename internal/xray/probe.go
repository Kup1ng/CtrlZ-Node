package xray

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Prober is how the manager asks whether a config works and whether a slot answers.
type Prober interface {
	// Probe makes an HTTP GET through the SOCKS inbound at socks and reports whether
	// one of urls answered 204 within the time, and how long it took from the CONNECT to
	// the first byte of the response (6.4).
	Probe(ctx context.Context, socks string, urls []string) (time.Duration, bool)
	// Greet reports whether a SOCKS server at addr answers a greeting (the hang check
	// of 7.5 step 4). No exit is dialled for it.
	Greet(ctx context.Context, addr string) bool
}

// DefaultProbeURLs are the two of 6.4; the hub can change them (probe_urls).
var DefaultProbeURLs = []string{
	"http://www.gstatic.com/generate_204",
	"http://cp.cloudflare.com/generate_204",
}

// SocksProber is the real Prober.
type SocksProber struct {
	// Timeout is the time one URL gets (5 s).
	Timeout time.Duration
}

func (p SocksProber) timeout() time.Duration {
	if p.Timeout > 0 {
		return p.Timeout
	}
	return 5 * time.Second
}

// Greet implements Prober.
func (p SocksProber) Greet(ctx context.Context, addr string) bool {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	c, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	defer c.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	}
	_, err = c.Write([]byte{5, 1, 0})
	var r [2]byte
	if err != nil || readFull(c, r[:]) != nil {
		return false
	}
	return r[0] == 5 && r[1] == 0
}

func readFull(c net.Conn, b []byte) error {
	for n := 0; n < len(b); {
		k, err := c.Read(b[n:])
		n += k
		if err != nil && n < len(b) {
			return err
		}
	}
	return nil
}

// Probe implements Prober. The first URL is tried, and the second when it fails.
func (p SocksProber) Probe(ctx context.Context, socks string, urls []string) (time.Duration, bool) {
	for _, u := range urls {
		if d, ok := p.one(ctx, socks, u); ok {
			return d, true
		}
	}
	return 0, false
}

func (p SocksProber) one(ctx context.Context, socks, raw string) (time.Duration, bool) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" || u.Hostname() == "" || len(u.Hostname()) > 253 {
		return 0, false
	}
	port := 80
	if ps := u.Port(); ps != "" {
		if port, err = strconv.Atoi(ps); err != nil || port < 1 || port > 65535 {
			return 0, false
		}
	}
	ctx, cancel := context.WithTimeout(ctx, p.timeout())
	defer cancel()
	c, err := (&net.Dialer{}).DialContext(ctx, "tcp", socks)
	if err != nil {
		return 0, false
	}
	defer c.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	}
	br := bufio.NewReader(c)
	if _, err := c.Write([]byte{5, 1, 0}); err != nil {
		return 0, false
	}
	var g [2]byte
	if _, err := readN(br, g[:]); err != nil || g[0] != 5 || g[1] != 0 {
		return 0, false
	}
	// The name goes to Xray as a name (ATYP 3), so its lookup is Xray's own, through the
	// identified Unbound, and not the agent's.
	host := u.Hostname()
	req := append([]byte{5, 1, 0, 3, byte(len(host))}, host...)
	req = append(req, byte(port>>8), byte(port))
	start := time.Now()
	if _, err := c.Write(req); err != nil {
		return 0, false
	}
	var h [4]byte
	if _, err := readN(br, h[:]); err != nil || h[0] != 5 || h[1] != 0 {
		return 0, false
	}
	skip := 0
	switch h[3] {
	case 1:
		skip = 4 + 2
	case 4:
		skip = 16 + 2
	case 3:
		l, err := br.ReadByte()
		if err != nil {
			return 0, false
		}
		skip = int(l) + 2
	default:
		return 0, false
	}
	if _, err := br.Discard(skip); err != nil {
		return 0, false
	}
	path := u.RequestURI()
	if _, err := fmt.Fprintf(c, "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: ctrlz-probe\r\nConnection: close\r\n\r\n", path, u.Host); err != nil {
		return 0, false
	}
	if _, err := br.Peek(1); err != nil {
		return 0, false
	}
	lat := time.Since(start)
	line, err := br.ReadString('\n')
	if err != nil && line == "" {
		return 0, false
	}
	f := strings.Fields(line)
	return lat, len(f) >= 2 && f[1] == "204"
}

func readN(br *bufio.Reader, b []byte) (int, error) {
	n := 0
	for n < len(b) {
		k, err := br.Read(b[n:])
		n += k
		if err != nil {
			if n == len(b) {
				return n, nil
			}
			return n, err
		}
	}
	return n, nil
}

var errNoProbe = errors.New("xray: no probe")

// health is the state of one config's probes (6.4): it starts unhealthy, moves after
// three equal results in a row, and a first pass makes it healthy at once. Latency
// is smoothed and published only when it moves by more than 20% and 10 ms, which is
// the hysteresis that keeps Auto from flapping between two close exits.
type health struct {
	healthy   bool
	seenPass  bool
	against   int // results in a row that disagree with `healthy`
	smooth    float64
	published uint32
	pubSet    bool
}

const (
	healthFlip = 3
	latWeight  = 0.3
)

func (h *health) observe(ok bool, lat time.Duration) {
	if ok && !h.seenPass {
		h.seenPass = true
		h.healthy, h.against = true, 0
	} else if ok != h.healthy {
		if h.against++; h.against >= healthFlip {
			h.healthy, h.against = ok, 0
		}
	} else {
		h.against = 0
	}
	if !ok {
		return
	}
	ms := float64(lat) / float64(time.Millisecond)
	if h.smooth == 0 {
		h.smooth = ms
	} else {
		h.smooth = latWeight*ms + (1-latWeight)*h.smooth
	}
	cur := uint32(h.smooth + 0.5)
	if cur == 0 {
		cur = 1
	}
	diff := float64(cur) - float64(h.published)
	if diff < 0 {
		diff = -diff
	}
	if !h.pubSet || (diff > 10 && diff > 0.2*float64(h.published)) {
		h.published, h.pubSet = cur, true
	}
}

// reset makes the state that of a config just applied: unhealthy, first pass pending.
func (h *health) reset() { *h = health{} }
