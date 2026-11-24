package apply_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"
	signv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/sign/v1"

	"github.com/Kup1ng/CtrlZ-Node/internal/store"
	"github.com/Kup1ng/CtrlZ-Node/internal/store/apply"
	"github.com/Kup1ng/CtrlZ-Node/internal/store/blobfetch"
	"github.com/Kup1ng/CtrlZ-Node/internal/store/fsx"
	"github.com/Kup1ng/CtrlZ-Node/internal/store/image"
	"github.com/Kup1ng/CtrlZ-Node/internal/store/push"
	"github.com/Kup1ng/CtrlZ-Node/internal/store/storetest"
)

const clock = int64(1_000_000)

// env is a node's directory with a fake hub, and the objects a running agent
// would hold. reopen() makes new ones over the same directory, which is a restart.
type env struct {
	t       *testing.T
	dir     string
	hub     *storetest.Hub
	keys    *storetest.Keys
	chain   storetest.Chain
	timeout time.Duration
	noSnap  bool                                            // no snapshot source: a gap is an error
	headFn  func(context.Context) (uint64, [32]byte, error) // apply.Config.Head
	budget  time.Duration                                   // apply.Config.FailedFetchBudget, 0 for the default
	// hook, when set, sees every atomic write of the store.
	hook   func(path string, s fsx.Step) error
	rawFet quarantineFetcher // replaces the blobfetch fetcher when set

	root   *store.Root
	tables apply.Tables
	// fakeTables, when set, wraps the real table writer for a test.
	fakeTables func(*push.Writer) apply.Tables
	push       *push.Writer
	a          *apply.Applier
	rep        apply.OpenReport
}

type quarantineFetcher interface {
	Fetch(hash [32]byte, kind policyv1.BlobKind, size uint64) ([]byte, bool)
}

func newEnv(t *testing.T) *env {
	t.Helper()
	e := &env{t: t, dir: t.TempDir(), hub: storetest.NewHub(), keys: storetest.NewKeys(t), timeout: 5 * time.Second}
	e.reopen()
	return e
}

func (e *env) reopen() {
	e.t.Helper()
	w := &fsx.Writer{Hook: func(p string, s fsx.Step) error {
		if e.hook != nil {
			return e.hook(p, s)
		}
		return nil
	}}
	root, err := store.Open(e.dir, w)
	if err != nil {
		e.t.Fatal(err)
	}
	e.root = root
	e.push = push.New(push.Config{Dir: root.Path(store.DirPush), W: w, Root: func() (*signv1.Root, error) { return e.keys.Root, nil }})
	e.tables = e.push
	if e.fakeTables != nil {
		e.tables = e.fakeTables(e.push)
	}
	var f quarantineFetcher = blobfetch.New(e.hub, blobfetch.WithTimeout(e.timeout))
	if e.rawFet != nil {
		f = e.rawFet
	}
	var snaps apply.SnapshotSource = e.hub
	if e.noSnap {
		snaps = nil
	}
	a, rep, err := apply.Open(apply.Config{Root: root, Fetcher: f, Tables: e.tables, Snapshots: snaps, FailedFetchBudget: e.budget, Head: e.headFn, Now: func() int64 { return clock }})
	if err != nil {
		e.t.Fatal(err)
	}
	e.a, e.rep = a, rep
}

// blob puts a blob on the hub and returns its bytes.
func (e *env) blob(token string) []byte {
	e.t.Helper()
	d := storetest.Blob(e.t, token)
	e.hub.Add(d)
	return d
}

// apply stores the entry the chain makes and applies it, advancing the chain only
// when the node advanced.
func (e *env) apply(ent *policyv1.ConfigEntry) apply.Result {
	e.t.Helper()
	b := e.chain.Marshal(e.t, ent)
	res := e.a.ApplyEntry(context.Background(), b)
	if res.Report.Advanced {
		e.chain.Advance(b)
	}
	return res
}

func (e *env) mustApply(ent *policyv1.ConfigEntry) apply.Result {
	e.t.Helper()
	res := e.apply(ent)
	if !res.Report.Advanced || res.Err != nil || res.ImageErr != nil {
		e.t.Fatalf("entry not applied: %+v", res)
	}
	return res
}

func (e *env) imagesDir() string { return e.root.Path(store.DirImage) }

// current opens the image the dns process would.
func (e *env) current() *image.Image {
	e.t.Helper()
	im, err := image.OpenCurrent(e.imagesDir())
	if err != nil {
		e.t.Fatalf("image/current does not open: %v", err)
	}
	return im
}

func (e *env) hasFile(rel ...string) bool {
	_, err := os.Stat(filepath.Join(append([]string{e.dir}, rel...)...))
	return err == nil
}

func putEntry(blobs [][]byte, eps ...*policyv1.EndpointRecord) *policyv1.ConfigEntry {
	ent := &policyv1.ConfigEntry{PutEndpoints: eps}
	for _, b := range blobs {
		ent.PutBlobs = append(ent.PutBlobs, storetest.Ref(b))
	}
	return ent
}

func key16(b byte) [16]byte { return [16]byte(bytes.Repeat([]byte{b}, 16)) }
