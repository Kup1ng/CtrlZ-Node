package store

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// HashHex is the file name of a blob: the lower-case hex of its SHA-256.
func HashHex(h [32]byte) string { return hex.EncodeToString(h[:]) }

// ParseHashHex is the inverse of HashHex, for listing a directory.
func ParseHashHex(s string) ([32]byte, bool) {
	var h [32]byte
	if len(s) != 64 {
		return h, false
	}
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		return h, false
	}
	copy(h[:], b)
	return h, true
}

// BlobPath is where a blob is, or would be, in blobs/.
func (r *Root) BlobPath(h [32]byte) string { return r.Path(DirBlobs, HashHex(h)) }

// QuarantinePath is where a set-aside blob is, or would be.
func (r *Root) QuarantinePath(h [32]byte) string { return r.Path(DirQuarantine, HashHex(h)) }

func (r *Root) incomingPath(h [32]byte) string { return filepath.Join(r.IncomingDir(), HashHex(h)) }

// ReadBlob reads a blob and checks it against its name, so a file that rotted
// on disk is never handed on as the blob it claims to be.
func (r *Root) ReadBlob(h [32]byte) ([]byte, error) {
	b, err := os.ReadFile(r.BlobPath(h))
	if err != nil {
		return nil, err
	}
	if sha256.Sum256(b) != h {
		return nil, fmt.Errorf("store: blob %s does not hash to its name", HashHex(h)[:12])
	}
	return b, nil
}

// HasBlob reports whether a blob file exists. It does not read it.
func (r *Root) HasBlob(h [32]byte) bool {
	_, err := os.Stat(r.BlobPath(h))
	return err == nil
}

// BlobIntact reports whether the blob file exists and hashes to its name. A
// file that exists is not enough to keep fresh bytes out: a rotted one must be
// replaced, not trusted.
func (r *Root) BlobIntact(h [32]byte) bool {
	_, err := r.ReadBlob(h)
	return err == nil
}

// StageBlob writes bytes that were fetched and hash to their name into
// quarantine/incoming/. Nothing reads that directory but the Apply that staged
// the file, which then promotes or drops it once it knows what the bytes are.
// Staging, rather than holding the bytes in memory, keeps one Apply's memory
// bounded by one blob however many a hostile hub makes it fetch.
func (r *Root) StageBlob(h [32]byte, data []byte) error {
	return r.W.WriteFile(r.incomingPath(h), data, ModePrivate)
}

// PromoteBlob moves a staged blob into blobs/ (group-readable: dns maps what
// the image names). It is a rename within one filesystem, so it is atomic and
// cheap.
func (r *Root) PromoteBlob(h [32]byte) error {
	src := r.incomingPath(h)
	if err := os.Chmod(src, ModeShared); err != nil {
		return err
	}
	return r.W.RenameFile(src, r.BlobPath(h))
}

// SetAsideStaged moves a staged blob whose bytes hash right but do not open into
// quarantine/ (SC 9.7 item 3). The file stays agent-only.
func (r *Root) SetAsideStaged(h [32]byte) error {
	return r.W.RenameFile(r.incomingPath(h), r.QuarantinePath(h))
}

// DropStaged deletes a staged blob. A missing file is not an error.
func (r *Root) DropStaged(h [32]byte) {
	_ = os.Remove(r.incomingPath(h))
}

// PutBlob writes a blob whose bytes are in memory, as Load does when it repairs
// the directory from a snapshot. It refuses bytes that do not hash to h.
func (r *Root) PutBlob(h [32]byte, data []byte) error {
	if sha256.Sum256(data) != h {
		return errors.New("store: blob bytes do not hash to the name")
	}
	if r.HasBlob(h) {
		return nil
	}
	return r.W.WriteFile(r.BlobPath(h), data, ModeShared)
}

// DeleteBlob removes a blob file. A missing file is not an error.
func (r *Root) DeleteBlob(h [32]byte) error {
	err := os.Remove(r.BlobPath(h))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// ListBlobs returns the hashes of the files in blobs/. A name that is not a
// hash is skipped, and left alone: it is not ours to delete.
func (r *Root) ListBlobs() ([][32]byte, error) {
	ents, err := os.ReadDir(r.Path(DirBlobs))
	if err != nil {
		return nil, err
	}
	var out [][32]byte
	for _, e := range ents {
		if h, ok := ParseHashHex(e.Name()); ok && !e.IsDir() {
			out = append(out, h)
		}
	}
	return out, nil
}

// --- the stored log ---

// logName is zero-padded so a directory listing is in seq order.
func logName(seq uint64) string { return fmt.Sprintf("%020d.entry", seq) }

// AppendEntry stores an entry's exact bytes (the bytes the chain hashed, never a
// re-marshalled form). Writing it again with the same seq replaces it, which
// happens when an Apply was cut short and the hub resends.
func (r *Root) AppendEntry(seq uint64, stored []byte) error {
	return r.W.WriteFile(r.Path(DirLog, logName(seq)), stored, ModePrivate)
}

// ReadEntry returns a stored entry.
func (r *Root) ReadEntry(seq uint64) ([]byte, error) {
	return os.ReadFile(r.Path(DirLog, logName(seq)))
}

// LogSeqs lists the stored entries' seqs in order.
func (r *Root) LogSeqs() ([]uint64, error) {
	ents, err := os.ReadDir(r.Path(DirLog))
	if err != nil {
		return nil, err
	}
	var out []uint64
	for _, e := range ents {
		n, ok := strings.CutSuffix(e.Name(), ".entry")
		if !ok {
			continue
		}
		if seq, err := strconv.ParseUint(n, 10, 64); err == nil {
			out = append(out, seq)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}

// PruneLog deletes the stored entries below seq and returns how many. The log
// is only kept from the latest snapshot on (7.2), and a node that applies a
// snapshot drops what is behind it.
func (r *Root) PruneLog(below uint64) (int, error) {
	seqs, err := r.LogSeqs()
	if err != nil {
		return 0, err
	}
	n := 0
	for _, s := range seqs {
		if s >= below {
			break
		}
		if err := os.Remove(r.Path(DirLog, logName(s))); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return n, err
		}
		n++
	}
	return n, nil
}

// MaxQuarantineBytes bounds the evidence kept in quarantine/. The verdict itself
// lives in the state; the bytes only let an admin look at what the hub sent, so
// when the directory is over this size the oldest files go first.
const MaxQuarantineBytes int64 = 512 << 20

// DeleteQuarantined removes a set-aside blob. A missing file is not an error.
func (r *Root) DeleteQuarantined(h [32]byte) error {
	err := os.Remove(r.QuarantinePath(h))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// TrimQuarantine deletes the set-aside files that keep does not list, then the
// oldest of the rest while the directory holds more than limit bytes. Names that are
// not a hash (state.bin.corrupt, incoming/) are left alone. It returns how many
// files it deleted.
func (r *Root) TrimQuarantine(keep func([32]byte) bool, limit int64) int {
	ents, err := os.ReadDir(r.Path(DirQuarantine))
	if err != nil {
		return 0
	}
	type file struct {
		h    [32]byte
		size int64
		mod  time.Time
	}
	var kept []file
	var total int64
	n := 0
	for _, e := range ents {
		h, ok := ParseHashHex(e.Name())
		if !ok || e.IsDir() {
			continue
		}
		if !keep(h) {
			if r.DeleteQuarantined(h) == nil {
				n++
			}
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		kept = append(kept, file{h, info.Size(), info.ModTime()})
		total += info.Size()
	}
	sort.Slice(kept, func(i, j int) bool { return kept[i].mod.Before(kept[j].mod) })
	for _, f := range kept {
		if total <= limit {
			break
		}
		if r.DeleteQuarantined(f.h) == nil {
			total -= f.size
			n++
		}
	}
	return n
}
