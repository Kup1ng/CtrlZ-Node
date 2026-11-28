// Package image is the serving image: what the dns process reads to answer
// queries, built by the agent after each Apply (spec p4-nodes 7.2, SC 9.7 item 4).
//
// # Why a directory per image, swapped by a symlink
//
// A reader must never see half of an image. Each image is built under a
// temporary name inside image/, every file synced, then renamed to its final
// name (the directory is complete from that instant), and only then does the
// symlink image/current get renamed to point at it. Both renames are atomic, so
// a reader that resolves image/current sees the old image or the new one. The
// previous image stays on disk for one more generation, so a reader that is
// half way through opening the old one is not pulled from under.
//
// # Directory name
//
// image/<seq> with seq zero-padded to 20 digits. A rebuild of the same seq (a
// Retry that promoted an Endpoint, or a repair at start) adds ".<n>", so the
// name always changes when the content does.
//
// # Files
//
// Every file is sealed (fsx.Seal: magic, SHA-256 of the body, body)
// and Open checks every seal, so a flipped bit makes Open fail instead of
// serving a wrong Endpoint.
//
//	meta       magic CZIM, JSON: format, seq, entry hash, generation, free DNS value,
//	           the counts of every file and whether a zone table is present
//	endpoints  magic CZEP, u32 count, then count records
//	           record: u32 length, u8 flags (bit 0 degraded), EndpointRecord protobuf
//	           sorted by endpoint_id
//	claims     magic CZCL, u32 count, then count records
//	           record: u32 length, ClaimRecord protobuf, sorted by claim_id
//	blobs      magic CZBL, u32 count, then count records of 33 bytes: u8 kind
//	           (1 profile, 2 block page) and the SHA-256; the blobs that were on disk
//	           in blobs/ when the image was built, sorted by hash
//	zone       magic CZZT, the PairTable of the entry, protobuf; absent when no
//	           applied entry has carried one
//
// The format is the contract between the agent that writes it and dns that reads
// it. W7 serves from the Go API below and never parses the files itself.
//
// # Read or map
//
// Open reads each file into memory and builds maps. It does not mmap. The
// reasons: a mapped file that is truncated under the process raises SIGBUS,
// which no recover can catch, and the rule of this node is that bad input never
// stops it (T-074); portability to the Windows development machines; and the
// image holds records only (the large part, the profile blobs, stays in blobs/
// and is opened by path on demand), so a full image of 100,000 Endpoints is
// tens of megabytes and opens in tens of milliseconds. The cost is one copy of
// those records in dns's heap, which the 7.6 resource budget carries.
package image

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"google.golang.org/protobuf/proto"

	commonv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/common/v1"
	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"
	"github.com/Kup1ng/CtrlZ-Shared/identity"
	"github.com/Kup1ng/CtrlZ-Shared/wire"
	"github.com/Kup1ng/CtrlZ-Shared/zone"

	"github.com/Kup1ng/CtrlZ-Node/internal/store/fsx"
)

// Names inside the images directory and inside an image.
const (
	CurrentLink = "current"

	fileMeta      = "meta"
	fileEndpoints = "endpoints"
	fileClaims    = "claims"
	fileBlobs     = "blobs"
	fileZone      = "zone"

	magicMeta      = "CZIM"
	magicEndpoints = "CZEP"
	magicClaims    = "CZCL"
	magicBlobs     = "CZBL"
	magicZone      = "CZZT"

	// FormatVersion is bumped for an incompatible change of the files.
	FormatVersion = 1

	// maxRecord bounds one record. It is what the wire allows, not a smaller figure
	// of our own: an Endpoint record the validator accepts (10,000 clients) is over
	// 1 MiB, and a reader that refuses what Build wrote would cost the node its whole
	// image. A damaged length cannot size an allocation anyway: a record is a slice
	// of the file already in memory, and hdr+l is checked against its length.
	maxRecord = wire.MaxEntrySize
)

// Blob kinds in the blobs file.
const (
	KindProfile   uint8 = 1
	KindBlockPage uint8 = 2
)

// Meta is the content of the meta file.
type Meta struct {
	Format    int    `json:"format"`
	Seq       uint64 `json:"seq"`
	Gen       uint32 `json:"gen"` // 0 for the first image of a seq
	EntryHash string `json:"entry_hash"`
	Endpoints int    `json:"endpoints"`
	Claims    int    `json:"claims"`
	Blobs     int    `json:"blobs"`
	HasZone   bool   `json:"has_zone"`
	// Tag is set by the builder to name the state the image was built from (the
	// apply code puts the SHA-256 of the state file there), so a restart can tell
	// an image that matches the state from one a cut left behind.
	Tag string `json:"tag"`
	// Free DNS value in force (SC 5.2a (a)); Free is false when none is.
	Free        bool   `json:"free"`
	FreeEnabled bool   `json:"free_enabled"`
	FreeQPS     uint32 `json:"free_qps"`
	FreeVersion uint64 `json:"free_version"`
}

// Input is what an image is built from: the applied state, as plain maps so this
// package does not depend on the apply code.
type Input struct {
	Seq        uint64
	Head       [32]byte
	Endpoints  map[[16]byte]*policyv1.EndpointRecord
	Claims     map[[16]byte]*policyv1.ClaimRecord
	Degraded   map[[16]byte]bool
	Profiles   map[[32]byte]bool // profile blobs present in blobs/
	BlockPages map[[32]byte]bool
	Member     *policyv1.PairTable // the entry's table, flags as the log carried them
	FreeDNS    *policyv1.FreeDns
	Tag        string
}

// DirName is the directory name of an image.
func DirName(seq uint64, gen uint32) string {
	if gen == 0 {
		return fmt.Sprintf("%020d", seq)
	}
	return fmt.Sprintf("%020d.%d", seq, gen)
}

// ParseDirName is the inverse of DirName.
func ParseDirName(name string) (seq uint64, gen uint32, ok bool) {
	base, g, hasGen := strings.Cut(name, ".")
	if len(base) != 20 {
		return 0, 0, false
	}
	for _, c := range base {
		if c < '0' || c > '9' {
			return 0, 0, false
		}
	}
	fmt.Sscanf(base, "%d", &seq)
	if hasGen {
		var n uint32
		if _, err := fmt.Sscanf(g, "%d", &n); err != nil || fmt.Sprint(n) != g || n == 0 {
			return 0, 0, false
		}
		gen = n
	}
	return seq, gen, true
}

// Build writes a complete image under imagesDir and returns its directory name.
// It does not touch the current link: the caller swaps it in with SetCurrent
// once everything else of the Apply has succeeded.
//
// A failure at any point leaves no directory under a final name: the temporary
// one is removed (or, after a crash, found by fsx.CleanTemps at the next start).
func Build(w *fsx.Writer, imagesDir string, in Input) (name string, err error) {
	gen := nextGen(imagesDir, in.Seq)
	name = DirName(in.Seq, gen)
	final := filepath.Join(imagesDir, name)
	tmp := fsx.TempDir(final)
	if err := os.Mkdir(tmp, 0o750); err != nil {
		return "", err
	}
	// Mkdir applies the umask, and dns must be able to traverse the directory, so
	// the mode is set; the setgid bit of image/ goes with it, as chmod would drop it.
	if err := os.Chmod(tmp, 0o750|fsx.KeepSetgid(imagesDir)); err != nil {
		os.RemoveAll(tmp)
		return "", err
	}
	// A hook failure stands for a crash and keeps the temporary directory, as a
	// crash would; any other failure cleans up.
	defer func() {
		if err != nil && !errors.Is(err, fsx.ErrInjected) {
			os.RemoveAll(tmp)
		}
	}()
	write := func(file string, data []byte) error {
		return w.WriteFile(filepath.Join(tmp, file), data, 0o640)
	}

	// Endpoints.
	ids := sortedIDs(in.Endpoints)
	var b []byte
	b = binary.LittleEndian.AppendUint32(b, uint32(len(ids)))
	for _, id := range ids {
		rec, err := marshal(in.Endpoints[id])
		if err != nil {
			return "", err
		}
		var flags byte
		if in.Degraded[id] {
			flags |= 1
		}
		b = binary.LittleEndian.AppendUint32(b, uint32(len(rec)))
		b = append(b, flags)
		b = append(b, rec...)
	}
	if err := write(fileEndpoints, fsx.Seal(magicEndpoints, b)); err != nil {
		return "", err
	}

	// Claims.
	cids := sortedIDs(in.Claims)
	b = binary.LittleEndian.AppendUint32(nil, uint32(len(cids)))
	for _, id := range cids {
		rec, err := marshal(in.Claims[id])
		if err != nil {
			return "", err
		}
		b = binary.LittleEndian.AppendUint32(b, uint32(len(rec)))
		b = append(b, rec...)
	}
	if err := write(fileClaims, fsx.Seal(magicClaims, b)); err != nil {
		return "", err
	}

	// Blobs present.
	type kh struct {
		kind uint8
		h    [32]byte
	}
	var bl []kh
	for h := range in.Profiles {
		bl = append(bl, kh{KindProfile, h})
	}
	for h := range in.BlockPages {
		bl = append(bl, kh{KindBlockPage, h})
	}
	sort.Slice(bl, func(i, j int) bool { return bytes.Compare(bl[i].h[:], bl[j].h[:]) < 0 })
	b = binary.LittleEndian.AppendUint32(nil, uint32(len(bl)))
	for _, x := range bl {
		b = append(b, x.kind)
		b = append(b, x.h[:]...)
	}
	if err := write(fileBlobs, fsx.Seal(magicBlobs, b)); err != nil {
		return "", err
	}

	// Zone table of the entry, built here under recover first: an image whose
	// table does not build is never published (SC 9.7 item 4).
	if in.Member != nil {
		if _, err := BuildZone(in.Member); err != nil {
			return "", fmt.Errorf("image: zone table: %w", err)
		}
		zb, err := marshal(in.Member)
		if err != nil {
			return "", err
		}
		if err := write(fileZone, fsx.Seal(magicZone, zb)); err != nil {
			return "", err
		}
	}

	m := Meta{
		Format: FormatVersion, Seq: in.Seq, Gen: gen, EntryHash: hex.EncodeToString(in.Head[:]),
		Endpoints: len(ids), Claims: len(cids), Blobs: len(bl), HasZone: in.Member != nil, Tag: in.Tag,
	}
	if in.FreeDNS != nil {
		m.Free, m.FreeEnabled, m.FreeQPS, m.FreeVersion = true, in.FreeDNS.Enabled, in.FreeDNS.Qps, in.FreeDNS.Version
	}
	mj, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	// meta goes last: an image directory without it is incomplete by definition.
	if err := write(fileMeta, fsx.Seal(magicMeta, mj)); err != nil {
		return "", err
	}
	if err := fsx.SyncDir(tmp); err != nil {
		return "", err
	}
	if err := w.RenameDir(tmp, final); err != nil {
		return "", err
	}
	return name, nil
}

// BuildZone makes the zone table of an entry's PairTable, under recover, with no
// withdrawal flags: the log never carries any (SC 8a.7). The agent's table writer
// builds the table in use from the same membership plus the flags of a push.
func BuildZone(pt *policyv1.PairTable) (t *zone.Table, err error) {
	defer func() {
		if r := recover(); r != nil {
			t, err = nil, errors.New("zone build panicked")
		}
	}()
	in := wire.ZoneInput(pt)
	// The log carries no flags (SC 8a.7); a table that did would still not
	// withdraw anything here, because only a push may.
	for i := range in.Nodes {
		in.Nodes[i].Withdrawn = false
	}
	return zone.Build(in)
}

// SetCurrent makes name the current image, atomically. The link target is
// relative, so the whole root can move.
func SetCurrent(w *fsx.Writer, imagesDir, name string) error {
	return w.ReplaceSymlink(filepath.Join(imagesDir, CurrentLink), name)
}

// CurrentName returns the directory name image/current points at.
func CurrentName(imagesDir string) (string, error) {
	t, err := os.Readlink(filepath.Join(imagesDir, CurrentLink))
	if err != nil {
		return "", err
	}
	return filepath.Base(t), nil
}

// Images lists the image directories in imagesDir, oldest first.
func Images(imagesDir string) ([]string, error) {
	ents, err := os.ReadDir(imagesDir)
	if err != nil {
		return nil, err
	}
	type it struct {
		name string
		seq  uint64
		gen  uint32
	}
	var l []it
	for _, e := range ents {
		if s, g, ok := ParseDirName(e.Name()); ok && e.IsDir() {
			l = append(l, it{e.Name(), s, g})
		}
	}
	sort.Slice(l, func(i, j int) bool {
		if l[i].seq != l[j].seq {
			return l[i].seq < l[j].seq
		}
		return l[i].gen < l[j].gen
	})
	out := make([]string, len(l))
	for i := range l {
		out[i] = l[i].name
	}
	return out, nil
}

// Prune removes every image directory except the ones named in keep.
func Prune(imagesDir string, keep ...string) error {
	names, err := Images(imagesDir)
	if err != nil {
		return err
	}
	k := map[string]bool{}
	for _, n := range keep {
		k[n] = true
	}
	for _, n := range names {
		if !k[n] {
			if err := os.RemoveAll(filepath.Join(imagesDir, n)); err != nil {
				return err
			}
		}
	}
	return nil
}

// nextGen is 0 when no image of seq exists and one more than the highest
// generation otherwise, so a rebuild never reuses a name a reader may hold.
func nextGen(imagesDir string, seq uint64) uint32 {
	names, _ := Images(imagesDir)
	var next uint32
	found := false
	for _, n := range names {
		if s, g, ok := ParseDirName(n); ok && s == seq {
			found = true
			if g+1 > next {
				next = g + 1
			}
		}
	}
	if !found {
		return 0
	}
	return next
}

func marshal(m proto.Message) ([]byte, error) {
	return proto.MarshalOptions{Deterministic: true}.Marshal(m)
}

func sortedIDs[V any](m map[[16]byte]V) [][16]byte {
	ids := make([][16]byte, 0, len(m))
	for k := range m {
		ids = append(ids, k)
	}
	sort.Slice(ids, func(i, j int) bool { return bytes.Compare(ids[i][:], ids[j][:]) < 0 })
	return ids
}

// ---- read side ----

// Endpoint is one Endpoint of an image.
type Endpoint struct {
	Record *policyv1.EndpointRecord
	// Degraded is the Endpoint with no usable binding: served as soft_disabled
	// with decision_ref=degraded until a valid binding arrives (SC 9.7 item 7).
	Degraded bool
}

// Claim is one claim record in a form the query path's trie takes directly.
type Claim struct {
	ID         [16]byte
	EndpointID [16]byte
	Prefix     netip.Prefix
}

// Image is an opened, read-only image. Nothing in it changes after Open, so any
// number of goroutines may read it. The records it returns must not be edited.
type Image struct {
	meta     Meta
	dir      string // the real directory, links resolved
	root     string // the store root, two levels up
	byRID    map[[16]byte]*Endpoint
	byID     map[[16]byte]*Endpoint
	claims   []Claim
	profiles map[[32]byte]bool
	pages    map[[32]byte]bool
	member   *policyv1.PairTable
	zone     *zone.Table
}

// Open reads and checks the image in dir, which may be the current link. It
// follows the link once and reads every file from the real directory, so the
// files it reads all belong to one image.
func Open(dir string) (*Image, error) {
	real, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return nil, err
	}
	read := func(file, magic string) ([]byte, error) {
		raw, err := os.ReadFile(filepath.Join(real, file))
		if err != nil {
			return nil, err
		}
		body, err := fsx.Unseal(magic, raw)
		if err != nil {
			return nil, fmt.Errorf("image: %s: %w", file, err)
		}
		return body, nil
	}
	mb, err := read(fileMeta, magicMeta)
	if err != nil {
		return nil, err
	}
	im := &Image{dir: real, root: filepath.Dir(filepath.Dir(real)),
		byRID: map[[16]byte]*Endpoint{}, byID: map[[16]byte]*Endpoint{}, profiles: map[[32]byte]bool{}, pages: map[[32]byte]bool{}}
	if err := json.Unmarshal(mb, &im.meta); err != nil {
		return nil, fmt.Errorf("image: meta: %w", err)
	}
	if im.meta.Format != FormatVersion {
		return nil, fmt.Errorf("image: format %d, want %d", im.meta.Format, FormatVersion)
	}

	eb, err := read(fileEndpoints, magicEndpoints)
	if err != nil {
		return nil, err
	}
	d := &frames{b: eb}
	n := d.count()
	ambiguous := map[[16]byte]struct{}{}
	for i := 0; i < n && d.err == nil; i++ {
		rec := d.frame(true)
		if d.err != nil {
			break
		}
		ep := &policyv1.EndpointRecord{}
		if err := proto.Unmarshal(rec.body, ep); err != nil || len(ep.EndpointId) != 16 || len(ep.RidHash) != 16 {
			return nil, errors.New("image: endpoint record")
		}
		e := &Endpoint{Record: ep, Degraded: rec.flags&1 != 0}
		im.byID[[16]byte(ep.EndpointId)] = e
		rh := [16]byte(ep.RidHash)
		if _, dup := ambiguous[rh]; dup {
			continue
		}
		if _, dup := im.byRID[rh]; dup {
			// Two Endpoints with one rid_hash are two tenants' resolver ids that
			// cannot be told apart. Letting the later one win would filter one
			// tenant's devices with another's policy and make the first one's
			// hard_disable unreachable, so the lookup refuses both: a miss is what
			// an unknown resolver id gets.
			delete(im.byRID, rh)
			ambiguous[rh] = struct{}{}
			continue
		}
		im.byRID[rh] = e
	}
	if err := d.done(n, im.meta.Endpoints); err != nil {
		return nil, fmt.Errorf("image: endpoints: %w", err)
	}

	cb, err := read(fileClaims, magicClaims)
	if err != nil {
		return nil, err
	}
	d = &frames{b: cb}
	n = d.count()
	for i := 0; i < n && d.err == nil; i++ {
		rec := d.frame(false)
		if d.err != nil {
			break
		}
		c := &policyv1.ClaimRecord{}
		if err := proto.Unmarshal(rec.body, c); err != nil || len(c.ClaimId) != 16 || len(c.EndpointId) != 16 {
			return nil, errors.New("image: claim record")
		}
		p, err := prefixOf(c.Prefix)
		if err != nil {
			return nil, err
		}
		im.claims = append(im.claims, Claim{ID: [16]byte(c.ClaimId), EndpointID: [16]byte(c.EndpointId), Prefix: p})
	}
	if err := d.done(n, im.meta.Claims); err != nil {
		return nil, fmt.Errorf("image: claims: %w", err)
	}

	bb, err := read(fileBlobs, magicBlobs)
	if err != nil {
		return nil, err
	}
	if len(bb) < 4 || int(binary.LittleEndian.Uint32(bb)) != im.meta.Blobs || len(bb) != 4+33*im.meta.Blobs {
		return nil, errors.New("image: blobs list")
	}
	for i := 0; i < im.meta.Blobs; i++ {
		o := 4 + 33*i
		h := [32]byte(bb[o+1 : o+33])
		switch bb[o] {
		case KindProfile:
			im.profiles[h] = true
		case KindBlockPage:
			im.pages[h] = true
		default:
			return nil, errors.New("image: blob kind")
		}
	}

	if im.meta.HasZone {
		zb, err := read(fileZone, magicZone)
		if err != nil {
			return nil, err
		}
		pt := &policyv1.PairTable{}
		if err := proto.Unmarshal(zb, pt); err != nil {
			return nil, errors.New("image: zone table")
		}
		t, err := BuildZone(pt)
		if err != nil {
			return nil, fmt.Errorf("image: zone table: %w", err)
		}
		im.member, im.zone = pt, t
	}
	return im, nil
}

// OpenCurrent opens image/current under root. A swap and a prune can move the
// link between resolving it and reading the last file; the old image is kept one
// generation, so one more attempt reads the new one.
func OpenCurrent(imagesDir string) (*Image, error) {
	var err error
	for i := 0; i < 3; i++ {
		var im *Image
		im, err = Open(filepath.Join(imagesDir, CurrentLink))
		if err == nil || !errors.Is(err, fs.ErrNotExist) {
			return im, err
		}
	}
	return nil, err
}

type frame struct {
	flags byte
	body  []byte
}

type frames struct {
	b   []byte
	err error
	n   int
}

func (f *frames) count() int {
	if len(f.b) < 4 {
		f.err = errors.New("short")
		return 0
	}
	n := int(binary.LittleEndian.Uint32(f.b))
	f.b = f.b[4:]
	if n < 0 || n*4 > len(f.b) {
		f.err = errors.New("count")
		return 0
	}
	return n
}

func (f *frames) frame(flag bool) frame {
	if f.err != nil {
		return frame{}
	}
	hdr := 4
	if flag {
		hdr = 5
	}
	if len(f.b) < hdr {
		f.err = errors.New("short")
		return frame{}
	}
	l := int(binary.LittleEndian.Uint32(f.b))
	if l < 0 || l > maxRecord || hdr+l > len(f.b) {
		f.err = errors.New("record length")
		return frame{}
	}
	var out frame
	if flag {
		out.flags = f.b[4]
	}
	out.body = f.b[hdr : hdr+l]
	f.b = f.b[hdr+l:]
	f.n++
	return out
}

func (f *frames) done(n, want int) error {
	if f.err != nil {
		return f.err
	}
	if len(f.b) != 0 || n != want || f.n != n {
		return errors.New("count differs from meta")
	}
	return nil
}

func prefixOf(p *commonv1.Prefix) (netip.Prefix, error) {
	a, ok := netip.AddrFromSlice(p.GetAddr())
	if !ok {
		return netip.Prefix{}, errors.New("image: claim prefix address")
	}
	pf, err := a.Prefix(int(p.GetBits()))
	if err != nil || pf.Addr() != a {
		return netip.Prefix{}, errors.New("image: claim prefix")
	}
	return pf, nil
}

// Meta returns the image's header.
func (im *Image) Meta() Meta { return im.meta }

// Dir is the image's real directory.
func (im *Image) Dir() string { return im.dir }

// Seq is the applied_seq the image was built for.
func (im *Image) Seq() uint64 { return im.meta.Seq }

// ByRIDHash looks an Endpoint up by the hash of its resolver id, which is the key
// the node stores because no plain resolver id is kept (R16).
func (im *Image) ByRIDHash(h [16]byte) (*Endpoint, bool) {
	e, ok := im.byRID[h]
	return e, ok
}

// ByResolverID looks an Endpoint up by the resolver id a client presented. It
// does no format check: the caller has parsed the id from the name already, and
// an unknown id, a malformed one and a rotated one all give the same miss.
func (im *Image) ByResolverID(rid string) (*Endpoint, bool) {
	return im.ByRIDHash(identity.RIDHash(rid))
}

// RIDCollisions returns the endpoint ids of every Endpoint that shares its
// rid_hash with another, sorted. The image refuses to look such an Endpoint up by
// resolver id (see Open); the apply code reports them so the hub can be told.
func RIDCollisions(eps map[[16]byte]*policyv1.EndpointRecord) [][16]byte {
	by := make(map[[16]byte][][16]byte, len(eps))
	for id, ep := range eps {
		if ep == nil || len(ep.RidHash) != 16 {
			continue
		}
		rh := [16]byte(ep.RidHash)
		by[rh] = append(by[rh], id)
	}
	var out [][16]byte
	for _, ids := range by {
		if len(ids) > 1 {
			out = append(out, ids...)
		}
	}
	sort.Slice(out, func(i, j int) bool { return bytes.Compare(out[i][:], out[j][:]) < 0 })
	return out
}

// ByEndpointID looks an Endpoint up by its id, which is what a claim names.
func (im *Image) ByEndpointID(id [16]byte) (*Endpoint, bool) {
	e, ok := im.byID[id]
	return e, ok
}

// Blobs lists the hashes of every profile and block page the image was built with
// on disk. The apply code keeps these files when it sweeps blobs/, so an image that
// is still served never loses a file under it.
func (im *Image) Blobs() [][32]byte {
	out := make([][32]byte, 0, len(im.profiles)+len(im.pages))
	for h := range im.profiles {
		out = append(out, h)
	}
	for h := range im.pages {
		out = append(out, h)
	}
	return out
}

// EndpointCount is the number of Endpoints.
func (im *Image) EndpointCount() int { return len(im.byID) }

// Claims returns every claim, in claim id order, for the query path to build its
// longest-prefix trie from (T-011). The slice is the image's own; do not edit it.
func (im *Image) Claims() []Claim { return im.claims }

// ProfilePath is the file of a profile blob, when the image was built with it on
// disk. A binding whose profile is missing returns false, and the query path
// serves that Endpoint as degraded.
func (im *Image) ProfilePath(h [32]byte) (string, bool) {
	if !im.profiles[h] {
		return "", false
	}
	return filepath.Join(im.root, "blobs", hex.EncodeToString(h[:])), true
}

// BlockPagePath is the file of a block page blob, with the same rule.
func (im *Image) BlockPagePath(h [32]byte) (string, bool) {
	if !im.pages[h] {
		return "", false
	}
	return filepath.Join(im.root, "blobs", hex.EncodeToString(h[:])), true
}

// PairTable is the membership table of the entry the image was built for, or nil
// when no applied entry has carried one. Do not edit it.
func (im *Image) PairTable() *policyv1.PairTable { return im.member }

// Zone is the zone table of that entry with no withdrawal flags, or nil. A dns
// process that has no table from the agent answers from this one with no flags;
// the table in use, with the flags of the push, comes over the agent socket.
func (im *Image) Zone() *zone.Table { return im.zone }

// FreeDNS is the free DNS value in force, and false when none is (free DNS then
// counts as off, SC 5.2a (a)).
func (im *Image) FreeDNS() (enabled bool, qps uint32, version uint64, ok bool) {
	return im.meta.FreeEnabled, im.meta.FreeQPS, im.meta.FreeVersion, im.meta.Free
}

// Digest is a SHA-256 over the files of an image directory, for tests that
// compare two images.
func Digest(dir string) ([32]byte, error) {
	h := sha256.New()
	for _, f := range []string{fileMeta, fileEndpoints, fileClaims, fileBlobs, fileZone} {
		b, err := os.ReadFile(filepath.Join(dir, f))
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return [32]byte{}, err
		}
		h.Write([]byte(f))
		h.Write(b)
	}
	var out [32]byte
	h.Sum(out[:0])
	return out, nil
}
