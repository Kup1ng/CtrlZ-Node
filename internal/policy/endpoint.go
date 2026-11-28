package policy

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sync"
	"weak"

	"github.com/Kup1ng/CtrlZ-Shared/blob"
	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"
	"github.com/Kup1ng/CtrlZ-Shared/identity"
	sharedpolicy "github.com/Kup1ng/CtrlZ-Shared/policy"
	"github.com/Kup1ng/CtrlZ-Shared/schedule"

	"github.com/Kup1ng/CtrlZ-Node/internal/lru"
)

// ErrBlobMissing means a profile the Endpoint's binding names is not on disk or
// does not match its hash. The Endpoint is then served degraded (SC 9.7 item 7):
// the query path answers by PostDefault and never guesses a policy.
var ErrBlobMissing = errors.New("policy: profile blob missing or damaged")

// ErrBlobUnreadable means reading a profile blob failed for a reason that is not
// about the blob (descriptor limit, memory, I/O error). The Endpoint is served
// degraded for this query only; the state is not remembered, so the next query
// tries the file again.
var ErrBlobUnreadable = errors.New("policy: profile blob unreadable")

// ProfileLoader returns the opened profile for a hash.
type ProfileLoader interface {
	Profile(hash [32]byte) (*blob.Profile, error)
}

// Profiles opens profile blobs and keeps the most recently used ones. A blob is
// content-addressed, so an opened one is right for any image that names its
// hash, and the cache is shared by every image of the process. It holds no path
// function: where a file lives is the image's business, and a newer image has
// other files, so each Serving binds its own image's lookup through Bind. (A
// loader fixed to the first image degraded every Endpoint whose profile changed
// after start.)
//
// Two things bound memory. The LRU keeps budget opened blobs warm. A blob that
// compiled Endpoints still hold is also found again by hash through a weak
// pointer, so an eviction never makes a second resident copy of a blob that is
// in use: resident copies are one per distinct live hash, not one per compile.
type Profiles struct {
	mu   sync.Mutex
	l    *lru.Cache[[32]byte, *blob.Profile]
	live map[[32]byte]weak.Pointer[blob.Profile]
	// loading holds the load in flight of each hash.
	loading map[[32]byte]*profLoad
	// read is os.ReadFile; a test swaps it to count and stall reads.
	read func(string) ([]byte, error)
	// sweepAt is the size of live that triggers the next removal of dead entries.
	sweepAt int
}

// NewProfiles makes a loader cache. budget is how many profiles stay warm.
func NewProfiles(budget int) *Profiles {
	return &Profiles{
		l:       lru.New[[32]byte, *blob.Profile](int64(budget)),
		live:    map[[32]byte]weak.Pointer[blob.Profile]{},
		loading: map[[32]byte]*profLoad{},
		read:    os.ReadFile,
		sweepAt: 2*budget + 64,
	}
}

type boundProfiles struct {
	p    *Profiles
	path func(hash [32]byte) (string, bool)
}

// Bind returns the ProfileLoader of one image: files come from path (the image's
// own ProfilePath), opened blobs come from the shared cache.
func (p *Profiles) Bind(path func(hash [32]byte) (string, bool)) ProfileLoader {
	return boundProfiles{p: p, path: path}
}

// Profile implements ProfileLoader. The file is read whole and opened with
// blob.Open, which checks its structure, and its content hash must be the one
// asked for: a rotted file is a missing one.
//
// One load runs per hash at a time. A blob can be 64 MiB and hashing it takes
// hundreds of milliseconds, so without this every concurrent first query of an
// Endpoint (a restart under load, or a new image after a tenant edits a large
// profile) read and opened its own copy, and the peak was queries times blob
// size (p4n-W7-r2-4). Waiters take the leader's result.
func (b boundProfiles) Profile(h [32]byte) (*blob.Profile, error) {
	p := b.p
	for {
		p.mu.Lock()
		pr := p.getLocked(h)
		p.mu.Unlock()
		if pr != nil {
			return pr, nil
		}
		file, ok := b.path(h)
		if !ok {
			return nil, ErrBlobMissing
		}
		p.mu.Lock()
		// Another query may have finished loading while the path was looked up.
		if pr := p.getLocked(h); pr != nil {
			p.mu.Unlock()
			return pr, nil
		}
		if c, busy := p.loading[h]; busy {
			p.mu.Unlock()
			<-c.done
			if c.err == nil {
				return c.pr, nil
			}
			if c.file == file {
				return nil, c.err
			}
			// The leader read another image's file for this hash, which may be
			// the one that is damaged or absent: try this image's own.
			continue
		}
		c := &profLoad{file: file, done: make(chan struct{})}
		p.loading[h] = c
		p.mu.Unlock()
		return p.lead(h, c)
	}
}

// profLoad is one load in flight: its waiters read pr and err after done closes.
type profLoad struct {
	file string
	done chan struct{}
	pr   *blob.Profile
	err  error
}

// lead runs the load for c and publishes the result. The deferred block also
// runs on a panic, so a waiter is never left hanging.
func (p *Profiles) lead(h [32]byte, c *profLoad) (*blob.Profile, error) {
	c.err = ErrBlobMissing
	defer func() {
		p.mu.Lock()
		if p.loading[h] == c {
			delete(p.loading, h)
		}
		p.mu.Unlock()
		close(c.done)
	}()
	pr, err := readProfile(p.read, c.file, h)
	if err != nil {
		c.err = err
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	// A copy may have been adopted meanwhile (an older leader of another image's
	// path); use it so the resident copy stays one.
	if cur := p.liveLocked(h); cur != nil {
		pr = cur
	} else {
		p.live[h] = weak.Make(pr)
		if len(p.live) > p.sweepAt {
			p.sweepLocked()
		}
	}
	p.l.Add(h, pr, 1)
	c.pr, c.err = pr, nil
	return pr, nil
}

// readProfile reads and checks one blob file. A file that is absent, or whose
// structure or hash is wrong, is ErrBlobMissing. Any other read failure
// (descriptor limit, memory, I/O error) is ErrBlobUnreadable: it says nothing
// about the blob, so the caller must not remember it (p4n-W7-r2-6).
func readProfile(read func(string) ([]byte, error), file string, h [32]byte) (*blob.Profile, error) {
	raw, err := read(file)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, ErrBlobMissing
		}
		return nil, ErrBlobUnreadable
	}
	pr, err := blob.Open(raw)
	if err != nil || pr.Hash() != h {
		return nil, ErrBlobMissing
	}
	return pr, nil
}

// getLocked finds an opened blob: warm in the LRU, or still held by a compiled
// Endpoint.
func (p *Profiles) getLocked(h [32]byte) *blob.Profile {
	if pr, ok := p.l.Get(h); ok {
		return pr
	}
	if pr := p.liveLocked(h); pr != nil {
		p.l.Add(h, pr, 1) // in use by a compiled Endpoint: warm again
		return pr
	}
	return nil
}

func (p *Profiles) liveLocked(h [32]byte) *blob.Profile {
	if w, ok := p.live[h]; ok {
		if pr := w.Value(); pr != nil {
			return pr
		}
		delete(p.live, h)
	}
	return nil
}

// sweepLocked drops the entries whose blob has been collected and sets the next
// threshold, so the sweep is amortized over inserts.
func (p *Profiles) sweepLocked() {
	for h, w := range p.live {
		if w.Value() == nil {
			delete(p.live, h)
		}
	}
	p.sweepAt = 2*len(p.live) + 64
}

// CompileEndpoint converts an EndpointRecord into the evaluator's view. The
// merge of the two profiles is computed by policy.NewStack, once, so a query
// only reads it. A Redirect to a location needs the pair's location bitmap
// (CompileEndpointPair); with none it falls back to Bypass with location_unavailable.
func CompileEndpoint(rec *policyv1.EndpointRecord, profiles ProfileLoader) (*sharedpolicy.EndpointView, error) {
	return CompileEndpointPair(rec, profiles, nil)
}

// CompileEndpointPair is CompileEndpoint with the location bitmap of the Endpoint's
// pair (p4b-proxy 6.2, 4.4): bit wire_id is set when both nodes of the pair have the
// location, and every stack of the Endpoint reads it.
func CompileEndpointPair(rec *policyv1.EndpointRecord, profiles ProfileLoader, pairLocs []uint64) (*sharedpolicy.EndpointView, error) {
	if len(rec.GetEndpointId()) != 16 {
		return nil, errors.New("policy: endpoint id")
	}
	ev := &sharedpolicy.EndpointView{Clients: map[[16]byte]*sharedpolicy.Stack{}}
	copy(ev.ID[:], rec.EndpointId)
	var err error
	if ev.Base, err = stackOf(rec.GetBase(), profiles, pairLocs); err != nil {
		return nil, err
	}
	for _, c := range rec.GetClients() {
		if len(c.GetClientHash()) != 16 || c.GetStack() == nil {
			continue
		}
		s, err := stackOf(c.Stack, profiles, pairLocs)
		if err != nil {
			return nil, err
		}
		ev.Clients[[16]byte(c.ClientHash)] = s
	}
	if sr := rec.GetSchedule(); sr != nil {
		trs := make([]schedule.Transition, 0, len(sr.Transitions))
		for _, t := range sr.Transitions {
			trs = append(trs, schedule.Transition{At: t.At, Offset: t.Offset})
		}
		sc, err := schedule.New(sr.BaseOffset, trs, sr.Grid, len(sr.Windows))
		if err != nil {
			return nil, fmt.Errorf("policy: schedule: %w", err)
		}
		ev.Sched = sc
		for _, w := range sr.Windows {
			s, err := stackOf(w.GetStack(), profiles, pairLocs)
			if err != nil {
				return nil, err
			}
			ev.Windows = append(ev.Windows, s)
			var id [16]byte
			copy(id[:], w.GetWindowId())
			ev.WindowIDs = append(ev.WindowIDs, id)
		}
	}
	return ev, nil
}

func stackOf(sr *policyv1.StackRecord, profiles ProfileLoader, pairLocs []uint64) (*sharedpolicy.Stack, error) {
	var p [2]*blob.Profile
	for i, h := range [][]byte{sr.GetProfile1Hash(), sr.GetProfile2Hash()} {
		if len(h) == 0 {
			continue
		}
		if len(h) != 32 {
			return nil, errors.New("policy: profile hash")
		}
		pr, err := profiles.Profile([32]byte(h))
		if err != nil {
			return nil, err
		}
		p[i] = pr
	}
	return sharedpolicy.NewStack(p[0], p[1], pairLocs), nil
}

// ClientHash is the hash of a client label, as the Endpoint's clients are keyed.
func ClientHash(label string) [16]byte {
	if label == "" {
		return [16]byte{}
	}
	return identity.ClientHash(label)
}

// Purge forgets every opened profile, so the next query reads the files again.
func (p *Profiles) Purge() {
	p.mu.Lock()
	p.l.Clear()
	p.live = map[[32]byte]weak.Pointer[blob.Profile]{}
	p.mu.Unlock()
}
