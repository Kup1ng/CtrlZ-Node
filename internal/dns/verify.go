package dns

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	commonv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/common/v1"
	"github.com/Kup1ng/CtrlZ-Shared/identity"

	"github.com/Kup1ng/CtrlZ-Node/internal/lru"
)

// The verify names (SC 5.2 step 4a, p4-nodes.md 7.6). A page makes the visitor's
// resolver ask for <label>.verify.<zone>, then fetches GET /v from the same
// zone, and the node tells it whether the query arrived and over what, without
// ever saying which Endpoint it was, or what the label was, in the clear.

const (
	// verifyLRUSize and verifyTTL are D31: 65536 labels for 60 s.
	verifyLRUSize = 65536
	verifyTTL     = 60 * time.Second
	tagBytes      = 16
)

type verifyEntry struct {
	rid        string // empty when no identity resolved the label, or the identity is a claim
	client     string
	proto      commonv1.Protocol
	identified bool
	at         time.Time
}

// verifyPerRID is the most labels one Endpoint may hold in the identified table.
// An identified entry is what the verify page reads to say "this device uses
// Ctrl Z", so it must survive an unidentified flood (p4n-W7-r4-2); a tenant can
// make labels for its own resolver id as fast as it likes, and the quota keeps
// that to its own share of the table.
const verifyPerRID = 256

// ridLabels is one Endpoint's labels in the identified table, oldest first.
type ridLabels struct {
	labels []string
	last   time.Time
}

// verifyTable keeps two LRUs. ident holds labels noted by a query that has an
// identity and that step 4b let through; anon holds every other label. A query
// with no identity can write only anon, so a flood of random labels (free to
// make, from one host over TCP, or through open resolvers over UDP) can evict
// only other unidentified labels.
type verifyTable struct {
	mu     sync.Mutex
	anon   *lru.Cache[string, verifyEntry]
	ident  *lru.Cache[string, verifyEntry]
	rings  map[string]*ridLabels
	writes int
}

func newVerifyTable() *verifyTable {
	return &verifyTable{
		anon:  lru.New[string, verifyEntry](verifyLRUSize),
		ident: lru.New[string, verifyEntry](verifyLRUSize),
		rings: map[string]*ridLabels{},
	}
}

// note records a verify query. A query with no identity never replaces what an
// identified one recorded for the same label, so a spoofed UDP packet cannot
// turn an identified label into an unidentified one.
func (v *verifyTable) note(label string, e verifyEntry) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if !e.identified {
		if old, ok := v.ident.Peek(label); ok && e.at.Sub(old.at) < verifyTTL {
			old.at = e.at
			v.ident.Add(label, old, 1)
			// The label is live again, so its Endpoint's ring must say so, or
			// prune and the quota drop a label that get still serves (p4n-W7-r5-5).
			v.refresh(old.rid, label, e.at)
			return
		}
		v.anon.Add(label, e, 1)
		return
	}
	if old, ok := v.ident.Peek(label); ok && old.rid == e.rid && v.rings[e.rid] != nil {
		v.ident.Add(label, e, 1)
		v.refresh(e.rid, label, e.at)
		return
	}
	r := v.rings[e.rid]
	if r == nil {
		r = &ridLabels{}
		v.rings[e.rid] = r
	}
	// A label the global LRU evicted may still be in the ring: take it out first,
	// so the ring never holds one label twice and the quota never drops the fresh
	// entry in place of the stale one.
	r.remove(label)
	if len(r.labels) >= verifyPerRID {
		v.drop(e.rid, r.labels[0])
		r.labels = append(r.labels[:0], r.labels[1:]...)
	}
	r.labels = append(r.labels, label)
	r.last = e.at
	v.ident.Add(label, e, 1)
	v.writes++
	if v.writes%1024 == 0 {
		v.prune(e.at)
	}
}

// remove takes label out of the ring. The ring is at most verifyPerRID long.
func (r *ridLabels) remove(label string) {
	for i, l := range r.labels {
		if l == label {
			r.labels = append(r.labels[:i], r.labels[i+1:]...)
			return
		}
	}
}

// refresh marks a label of rid as seen at now: it moves to the young end of the
// ring (the quota drops the oldest) and the ring's last time moves up (prune
// forgets only an Endpoint that has been quiet for a whole TTL).
func (v *verifyTable) refresh(rid, label string, now time.Time) {
	r := v.rings[rid]
	if r == nil {
		return
	}
	r.remove(label)
	r.labels = append(r.labels, label)
	r.last = now
}

// drop removes a label from ident when rid still owns it.
func (v *verifyTable) drop(rid, label string) {
	if o, ok := v.ident.Peek(label); ok && o.rid == rid {
		v.ident.Remove(label)
	}
}

// prune forgets the Endpoints that have not noted a label for a whole TTL, so
// the ring map does not grow with every resolver id ever seen.
func (v *verifyTable) prune(now time.Time) {
	for rid, r := range v.rings {
		if now.Sub(r.last) < verifyTTL {
			continue
		}
		for _, l := range r.labels {
			v.drop(rid, l)
		}
		delete(v.rings, rid)
	}
}

func (v *verifyTable) get(label string, now time.Time) (verifyEntry, bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if e, ok := v.ident.Get(label); ok {
		if now.Sub(e.at) < verifyTTL {
			return e, true
		}
		v.ident.Remove(label)
	}
	e, ok := v.anon.Get(label)
	if !ok {
		return verifyEntry{}, false
	}
	if now.Sub(e.at) >= verifyTTL {
		v.anon.Remove(label)
		return verifyEntry{}, false
	}
	return e, true
}

// verifyBody is the JSON of GET /v. It has no field that says which Endpoint,
// which label, which protocol, or whether the label was identified: anyone can
// fetch /v for a label a page made a visitor resolve, so a clear field would mark
// the visitor as a Ctrl Z user and name the transport, and two reads of one label
// share no value to link visits by.
type verifyBody struct {
	Seen      bool   `json:"seen"`
	N         string `json:"n"`
	RIDTag    string `json:"rid_tag"`
	ClientTag string `json:"client_tag"`
	ProtoTag  string `json:"proto_tag"`
}

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand does not fail on a working system; a failure must not
		// become a predictable tag.
		panic("dns: no randomness")
	}
	return hex.EncodeToString(b)
}

func tag(label string, n []byte, msg []byte) string {
	key := append([]byte(label), n...)
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return hex.EncodeToString(m.Sum(nil)[:tagBytes])
}

// body builds the response for a label. n is drawn here, per response.
func (v *verifyTable) body(label string, now time.Time) verifyBody {
	n := make([]byte, 16)
	if _, err := rand.Read(n); err != nil {
		panic("dns: no randomness")
	}
	e, seen := v.get(label, now)
	b := verifyBody{Seen: seen, N: hex.EncodeToString(n)}
	if seen && e.identified && e.rid != "" {
		b.RIDTag = tag(label, n, []byte(e.rid))
		b.ClientTag = tag(label, n, append(append([]byte(e.rid), 0x00), e.client...))
		b.ProtoTag = tag(label, n, append(append([]byte(e.rid), 0x01), byte(e.proto)))
		return b
	}
	b.RIDTag, b.ClientTag, b.ProtoTag = randHex(tagBytes), randHex(tagBytes), randHex(tagBytes)
	return b
}

// verifyHandler is the listen.VerifyHandler: GET /v on an SNI of *.verify.<zone>.
// The CORS answer exists only here: DoH and DoH3 answer OPTIONS with 405 and send
// no Access-Control-Allow-Origin anywhere else (the listener sees to that).
type verifyHandler struct {
	h *Handler
}

// VerifyHost reports whether sni is a verify host of one of the node's zones.
func (v verifyHandler) VerifyHost(sni string) bool {
	set := v.h.set.Load()
	if set == nil {
		return false
	}
	return identity.ParseHost(sni, set.zones).Kind == identity.HostVerify
}

func (v verifyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	set := v.h.set.Load()
	hdr := w.Header()
	hdr.Set("Cache-Control", "no-store")
	hdr.Set("X-Content-Type-Options", "nosniff")
	if set == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	// CORS for the panel's origins only. A response for another origin carries no
	// Access-Control-Allow-Origin, so the browser refuses to hand it to the page.
	origin := r.Header.Get("Origin")
	allowed := origin != "" && set.origins[origin]
	hdr.Add("Vary", "Origin")
	if allowed {
		hdr.Set("Access-Control-Allow-Origin", origin)
	}
	switch r.Method {
	case http.MethodOptions:
		if !allowed {
			hdr.Set("Allow", "GET")
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		hdr.Set("Access-Control-Allow-Methods", "GET")
		hdr.Set("Access-Control-Max-Age", "600")
		w.WriteHeader(http.StatusNoContent)
		return
	case http.MethodGet:
	default:
		hdr.Set("Allow", "GET, OPTIONS")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	sni := ""
	if r.TLS != nil {
		sni = r.TLS.ServerName
	}
	host := identity.ParseHost(sni, set.zones)
	if host.Kind != identity.HostVerify {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	// A browser reuses one HTTP/2 or HTTP/3 connection for every name the
	// certificate covers, and every <label>.verify.<zone> resolves to this node.
	// The label that counts is the one in the request's authority, as R7 says for
	// DoH identity: when it is not the SNI's label, this connection was opened
	// for another name, and 421 makes the browser retry on a connection of its
	// own (RFC 9110 15.5.20; p4n-W7-r2-5).
	if auth := authorityHost(r.Host); auth != "" {
		if ah := identity.ParseHost(auth, set.zones); ah.Kind != identity.HostVerify || ah.Label != host.Label {
			w.WriteHeader(http.StatusMisdirectedRequest)
			return
		}
	}
	b := v.h.verify.body(host.Label, v.h.now())
	hdr.Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(b)
}

// authorityHost is the host part of a request's authority, lower-cased, with no
// port and no trailing dot. Empty when there is none.
func authorityHost(a string) string {
	if a == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(a); err == nil {
		a = h
	}
	return strings.TrimSuffix(strings.ToLower(a), ".")
}
