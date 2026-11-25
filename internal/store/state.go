package store

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sort"

	"google.golang.org/protobuf/proto"

	"github.com/Kup1ng/CtrlZ-Shared/blob"
	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"
	"github.com/Kup1ng/CtrlZ-Shared/quarantine"
	"github.com/Kup1ng/CtrlZ-Shared/reason"
	"github.com/Kup1ng/CtrlZ-Shared/wire"

	"github.com/Kup1ng/CtrlZ-Node/internal/store/fsx"
)

// Applied is everything a node keeps between entries: the shared quarantine
// State, the free DNS value in force (SC 5.2a (a): "part of State", written with
// applied_seq) and the membership PairTable of the last applied entry that
// carried one.
//
// The membership is kept because an entry without a PairTable changes nothing
// (wire.ValidatePairTable: a nil table is valid), so the table in use after a
// restart must come from the last entry that had one, which need not be the
// entry at applied_seq.
type Applied struct {
	Q       *quarantine.State
	FreeDNS *policyv1.FreeDns   // nil: no value in force, free DNS counts as off
	Member  *policyv1.PairTable // nil: no applied entry has carried a table
}

// NewApplied is the state of a node that has applied nothing.
func NewApplied() *Applied { return &Applied{Q: quarantine.NewState()} }

// Clone copies the state far enough to roll an Apply back: it copies the State
// struct, so the old maps stay as they were. That is sound because
// quarantine.Apply and Retry build new maps and assign them at the end (their
// swap, 9.7 item 4) and never edit a map they were given; the Apply tests of
// this repository check that this still holds.
func (a *Applied) Clone() *Applied {
	q := *a.Q
	return &Applied{Q: &q, FreeDNS: a.FreeDNS, Member: a.Member}
}

const (
	stateFile  = "state.bin"
	stateMagic = "CZST"
	stateVer   = 1
)

// ---- encoding: a flat, bounds-checked format of our own. The body is sealed
// (magic + SHA-256), so a flipped bit is found at load, and the whole file is
// replaced atomically, so a reader never sees half of it.

type enc struct{ b []byte }

func (e *enc) u8(v uint8)     { e.b = append(e.b, v) }
func (e *enc) u32(v uint32)   { e.b = binary.LittleEndian.AppendUint32(e.b, v) }
func (e *enc) u64(v uint64)   { e.b = binary.LittleEndian.AppendUint64(e.b, v) }
func (e *enc) raw(p []byte)   { e.b = append(e.b, p...) }
func (e *enc) bytes(p []byte) { e.u32(uint32(len(p))); e.raw(p) }
func (e *enc) msg(m proto.Message) error {
	p, err := proto.MarshalOptions{Deterministic: true}.Marshal(m)
	if err != nil {
		return err
	}
	e.bytes(p)
	return nil
}

type dec struct {
	b   []byte
	err error
}

var errShort = errors.New("state: truncated")

func (d *dec) take(n int) []byte {
	if d.err != nil {
		return nil
	}
	if n < 0 || n > len(d.b) {
		d.err = errShort
		return nil
	}
	p := d.b[:n]
	d.b = d.b[n:]
	return p
}
func (d *dec) u8() uint8 {
	if p := d.take(1); p != nil {
		return p[0]
	}
	return 0
}
func (d *dec) u32() uint32 {
	if p := d.take(4); p != nil {
		return binary.LittleEndian.Uint32(p)
	}
	return 0
}
func (d *dec) u64() uint64 {
	if p := d.take(8); p != nil {
		return binary.LittleEndian.Uint64(p)
	}
	return 0
}
func (d *dec) bytes() []byte { return d.take(int(d.u32())) }

// count reads a record count and refuses one that the rest of the file could not
// hold, so a damaged count never sizes an allocation.
func (d *dec) count(minRecord int) int {
	n := int(d.u32())
	if d.err == nil && (n < 0 || n*minRecord > len(d.b)) {
		d.err = errShort
		return 0
	}
	return n
}
func (d *dec) hash32() (h [32]byte) {
	copy(h[:], d.take(32))
	return
}
func (d *dec) msg(m proto.Message) {
	if p := d.bytes(); d.err == nil {
		if err := proto.Unmarshal(p, m); err != nil {
			d.err = fmt.Errorf("state: record: %w", err)
		}
	}
}

func sortedKeys32[V any](m map[[32]byte]V) [][32]byte {
	ks := make([][32]byte, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Slice(ks, func(i, j int) bool { return bytes.Compare(ks[i][:], ks[j][:]) < 0 })
	return ks
}

func sortedKeys16[V any](m map[[16]byte]V) [][16]byte {
	ks := make([][16]byte, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Slice(ks, func(i, j int) bool { return bytes.Compare(ks[i][:], ks[j][:]) < 0 })
	return ks
}

// EncodeApplied is deterministic: the same state gives the same bytes, so the
// SHA-256 of them identifies a state (the image records it, see image.Meta.Tag).
func EncodeApplied(a *Applied) ([]byte, error) {
	q := a.Q
	e := &enc{}
	e.u32(stateVer)
	e.u64(q.AppliedSeq)
	e.raw(q.Head[:])
	e.raw(q.WantedCursor[:])
	if a.FreeDNS != nil {
		e.u8(1)
		if err := e.msg(a.FreeDNS); err != nil {
			return nil, err
		}
	} else {
		e.u8(0)
	}
	if a.Member != nil {
		e.u8(1)
		if err := e.msg(a.Member); err != nil {
			return nil, err
		}
	} else {
		e.u8(0)
	}
	// Profiles and block pages are saved as hashes only: their bytes are in
	// blobs/, and Load reads them back and opens them again.
	e.u32(uint32(len(q.Profiles)))
	for _, h := range sortedKeys32(q.Profiles) {
		e.raw(h[:])
	}
	pages := make(map[[32]byte]struct{}, len(q.BlockPages))
	for h, ok := range q.BlockPages {
		if ok {
			pages[h] = struct{}{}
		}
	}
	e.u32(uint32(len(pages)))
	for _, h := range sortedKeys32(pages) {
		e.raw(h[:])
	}
	e.u32(uint32(len(q.Quarantined)))
	for _, h := range sortedKeys32(q.Quarantined) {
		e.raw(h[:])
		e.bytes([]byte(q.Quarantined[h]))
	}
	e.u32(uint32(len(q.Wanted)))
	for _, h := range sortedKeys32(q.Wanted) {
		if err := e.msg(q.Wanted[h]); err != nil {
			return nil, err
		}
	}
	e.u32(uint32(len(q.Endpoints)))
	for _, k := range sortedKeys16(q.Endpoints) {
		if err := e.msg(q.Endpoints[k]); err != nil {
			return nil, err
		}
	}
	e.u32(uint32(len(q.Claims)))
	for _, k := range sortedKeys16(q.Claims) {
		if err := e.msg(q.Claims[k]); err != nil {
			return nil, err
		}
	}
	var deg [][16]byte
	for k, ok := range q.Degraded {
		if ok {
			deg = append(deg, k)
		}
	}
	sort.Slice(deg, func(i, j int) bool { return bytes.Compare(deg[i][:], deg[j][:]) < 0 })
	e.u32(uint32(len(deg)))
	for _, k := range deg {
		e.raw(k[:])
	}
	e.u32(uint32(len(q.Pending)))
	for _, k := range sortedKeys16(q.Pending) {
		p := q.Pending[k]
		if err := e.msg(p.Record); err != nil {
			return nil, err
		}
		e.u32(uint32(len(p.Wants)))
		for _, h := range sortedKeys32(p.Wants) {
			if err := e.msg(p.Wants[h]); err != nil {
				return nil, err
			}
		}
	}
	return fsx.Seal(stateMagic, e.b), nil
}

// profileHashes and pageHashes are what decodeApplied could not restore by
// itself: the blobs are read from blobs/ by the caller.
type blobHashes struct {
	profiles [][32]byte
	pages    [][32]byte
}

func decodeApplied(file []byte) (*Applied, blobHashes, error) {
	var bh blobHashes
	body, err := fsx.Unseal(stateMagic, file)
	if err != nil {
		return nil, bh, err
	}
	d := &dec{b: body}
	if v := d.u32(); d.err == nil && v != stateVer {
		return nil, bh, fmt.Errorf("state: version %d, want %d", v, stateVer)
	}
	a := NewApplied()
	q := a.Q
	q.AppliedSeq = d.u64()
	q.Head = d.hash32()
	q.WantedCursor = d.hash32()
	if d.u8() == 1 {
		a.FreeDNS = &policyv1.FreeDns{}
		d.msg(a.FreeDNS)
	}
	if d.u8() == 1 {
		a.Member = &policyv1.PairTable{}
		d.msg(a.Member)
	}
	for i, n := 0, d.count(32); i < n && d.err == nil; i++ {
		bh.profiles = append(bh.profiles, d.hash32())
	}
	for i, n := 0, d.count(32); i < n && d.err == nil; i++ {
		bh.pages = append(bh.pages, d.hash32())
	}
	for i, n := 0, d.count(36); i < n && d.err == nil; i++ {
		h := d.hash32()
		q.Quarantined[h] = reason.Code(d.bytes())
	}
	for i, n := 0, d.count(4); i < n && d.err == nil; i++ {
		ref := &policyv1.BlobRef{}
		d.msg(ref)
		if d.err == nil && len(ref.Hash) == 32 {
			q.Wanted[[32]byte(ref.Hash)] = ref
		} else if d.err == nil {
			d.err = errors.New("state: wanted ref without a hash")
		}
	}
	for i, n := 0, d.count(4); i < n && d.err == nil; i++ {
		ep := &policyv1.EndpointRecord{}
		d.msg(ep)
		if d.err == nil && len(ep.EndpointId) == 16 {
			q.Endpoints[[16]byte(ep.EndpointId)] = ep
		} else if d.err == nil {
			d.err = errors.New("state: endpoint without an id")
		}
	}
	for i, n := 0, d.count(4); i < n && d.err == nil; i++ {
		c := &policyv1.ClaimRecord{}
		d.msg(c)
		if d.err == nil && len(c.ClaimId) == 16 {
			q.Claims[[16]byte(c.ClaimId)] = c
		} else if d.err == nil {
			d.err = errors.New("state: claim without an id")
		}
	}
	for i, n := 0, d.count(16); i < n && d.err == nil; i++ {
		var k [16]byte
		copy(k[:], d.take(16))
		q.Degraded[k] = true
	}
	for i, n := 0, d.count(8); i < n && d.err == nil; i++ {
		rec := &policyv1.EndpointRecord{}
		d.msg(rec)
		p := &quarantine.Pending{Record: rec, Wants: map[[32]byte]*policyv1.BlobRef{}}
		for j, m := 0, d.count(4); j < m && d.err == nil; j++ {
			ref := &policyv1.BlobRef{}
			d.msg(ref)
			if d.err == nil && len(ref.Hash) == 32 {
				p.Wants[[32]byte(ref.Hash)] = ref
			}
		}
		if d.err == nil && len(rec.EndpointId) == 16 {
			q.Pending[[16]byte(rec.EndpointId)] = p
		} else if d.err == nil {
			d.err = errors.New("state: pending endpoint without an id")
		}
	}
	if d.err == nil && len(d.b) != 0 {
		d.err = errors.New("state: trailing bytes")
	}
	if d.err != nil {
		return nil, bh, d.err
	}
	return a, bh, nil
}

// SaveApplied writes the state atomically. It is the commit point of an Apply:
// until this returns, a restart sees the state before the entry.
func (r *Root) SaveApplied(a *Applied) error {
	b, err := EncodeApplied(a)
	if err != nil {
		return fmt.Errorf("store: encode state: %w", err)
	}
	return r.WriteApplied(b)
}

// WriteApplied writes bytes that EncodeApplied made. Split from SaveApplied so
// the apply code can name the image after the state it is about to commit.
func (r *Root) WriteApplied(b []byte) error {
	return r.W.WriteFile(r.Path(DirState, stateFile), b, ModePrivate)
}

// LoadReport says what Load had to do beyond reading the file.
type LoadReport struct {
	// Fresh is true when there was no usable state: a new node, or a damaged
	// file that was set aside (Corrupt).
	Fresh bool
	// Corrupt is the reason a state file was set aside, or nil. The node starts
	// from nothing and gets a snapshot from the hub; image/ keeps serving what
	// it holds until the new state builds its own.
	Corrupt error
	// Lost lists blobs that the state names but blobs/ could not supply intact.
	// Each went back on the wanted list, and the Endpoints that bind it are
	// degraded and pending until Retry fetches it (9.7 items 2 and 7).
	Lost [][32]byte
}

// LoadApplied reads the state and opens the blobs it names. It returns an error
// only for a failure it cannot turn into a state (the directory cannot be
// read); a file that is missing or fails its check gives a fresh state and says
// so in the report, because a node that refused to start on a damaged file would
// be a node that stops answering.
func (r *Root) LoadApplied() (*Applied, LoadReport, error) {
	var rep LoadReport
	path := r.Path(DirState, stateFile)
	file, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		rep.Fresh = true
		return NewApplied(), rep, nil
	}
	if err != nil {
		return nil, rep, fmt.Errorf("store: read state: %w", err)
	}
	a, bh, derr := decodeApplied(file)
	if derr != nil {
		// Keep the bytes for a person to look at, out of the way of the next write.
		_ = os.Rename(path, r.Path(DirQuarantine, stateFile+".corrupt"))
		rep.Fresh, rep.Corrupt = true, derr
		return NewApplied(), rep, nil
	}
	q := a.Q
	for _, h := range bh.profiles {
		p, err := r.openProfile(h)
		if err != nil {
			rep.Lost = append(rep.Lost, h)
			q.Wanted[h] = &policyv1.BlobRef{Hash: h[:], Kind: policyv1.BlobKind_BLOB_KIND_PROFILE}
			continue
		}
		q.Profiles[h] = p
	}
	for _, h := range bh.pages {
		if err := r.checkBlockPage(h); err != nil {
			rep.Lost = append(rep.Lost, h)
			q.Wanted[h] = &policyv1.BlobRef{Hash: h[:], Kind: policyv1.BlobKind_BLOB_KIND_BLOCK_PAGE}
			continue
		}
		q.BlockPages[h] = true
	}
	if len(rep.Lost) > 0 {
		repairLost(q)
	}
	return a, rep, nil
}

func (r *Root) openProfile(h [32]byte) (*blob.Profile, error) {
	b, err := r.ReadBlob(h)
	if err != nil {
		return nil, err
	}
	return blob.Open(b)
}

func (r *Root) checkBlockPage(h [32]byte) error {
	b, err := r.ReadBlob(h)
	if err != nil {
		return err
	}
	if len(b) > wire.MaxBlockPageBlob {
		return errors.New("store: block page over the cap")
	}
	page := &policyv1.BlockPage{}
	if err := proto.Unmarshal(b, page); err != nil {
		return err
	}
	return wire.ValidateBlockPage(page)
}

// repairLost makes the state say what is true after blobs went missing: an
// Endpoint that binds a profile the node no longer has is degraded and waits for
// it, as if the Apply that bound it had not found the blob (9.7 items 2 and 7).
// Retry then fetches the blob and promote switches the Endpoint back.
func repairLost(q *quarantine.State) {
	usable := func(h []byte) bool {
		if len(h) != 32 {
			return true // not a hash: ValidateEndpoint refused such a record, so there is nothing to wait for
		}
		_, ok := q.Profiles[[32]byte(h)]
		return ok
	}
	for id, ep := range q.Endpoints {
		wants := map[[32]byte]*policyv1.BlobRef{}
		quarantined := false
		for _, hb := range bindingHashes(ep) {
			if usable(hb) {
				continue
			}
			h := [32]byte(hb)
			if _, bad := q.Quarantined[h]; bad {
				quarantined = true
				continue
			}
			ref := q.Wanted[h]
			if ref == nil {
				ref = &policyv1.BlobRef{Hash: hb, Kind: policyv1.BlobKind_BLOB_KIND_PROFILE}
				q.Wanted[h] = ref
			}
			wants[h] = ref
		}
		if len(wants) == 0 && !quarantined {
			continue
		}
		q.Degraded[id] = true
		// An Endpoint that already waits for a newer record keeps waiting for that
		// one: replacing it with the record it has now would, once the lost blob is
		// back, switch the Endpoint to the policy the panel had already moved it off.
		// The lost hash is on the wanted list either way (Load put it there), and
		// apply.reconcileDegraded lifts the degraded mark when it returns.
		if _, waiting := q.Pending[id]; len(wants) > 0 && !waiting {
			q.Pending[id] = &quarantine.Pending{Record: ep, Wants: wants}
		}
	}
}

// bindingHashes lists every profile hash an Endpoint record names, as
// quarantine does for its own use (it does not export it).
func bindingHashes(ep *policyv1.EndpointRecord) [][]byte {
	var out [][]byte
	add := func(s *policyv1.StackRecord) {
		if s == nil {
			return
		}
		out = append(out, s.Profile1Hash)
		if len(s.Profile2Hash) != 0 {
			out = append(out, s.Profile2Hash)
		}
	}
	add(ep.Base)
	if ep.Schedule != nil {
		for _, w := range ep.Schedule.Windows {
			add(w.Stack)
		}
	}
	for _, c := range ep.Clients {
		add(c.Stack)
	}
	return out
}

// StateHash is the SHA-256 of the saved state file, for tests and for the
// agent's integrity log line (it holds no secret).
func (r *Root) StateHash() ([32]byte, error) {
	b, err := os.ReadFile(r.Path(DirState, stateFile))
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(b), nil
}

// PeekMember is the PairTable of the applied state, or nil when there is none or the
// file does not decode. It opens no blob and changes nothing on disk, not even a
// damaged file, which only LoadApplied sets aside and reports: the start of an agent
// that has no identity yet reads the node addresses from it (the do-not-query list)
// and must leave the repair, and the alert about it, to the agent that follows.
func (r *Root) PeekMember() *policyv1.PairTable {
	file, err := os.ReadFile(r.Path(DirState, stateFile))
	if err != nil {
		return nil
	}
	a, _, err := decodeApplied(file)
	if err != nil {
		return nil
	}
	return a.Member
}
