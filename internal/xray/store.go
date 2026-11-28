package xray

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
)

// The files of the manager (7.5). Everything under dir is the agent's alone (mode
// 0700 directory, 0600 files): the fragments hold the credentials of the exits.
//
//	wanted.json      the configs the hub wants, with their fragments
//	state.json       the active slot, the running set, drains, the trial and the marks
//	good/<id>.json   the last good fragment of a config

// maxStateFile bounds what is read back: 64 configs of 32 KiB, twice, with room.
const maxStateFile = 8 << 20

// retiredRec is an older generation that still carries connections until Until.
type retiredRec struct {
	Rec   runRec `json:"rec"`
	Until int64  `json:"until"` // unix nanoseconds
}

// drainRec is the slot that an upgrade or rebuild left behind (7.7 step 5).
type drainRec struct {
	Slot    string   `json:"slot"`
	Version string   `json:"version"`
	Running []runRec `json:"running"`
	Until   int64    `json:"until"`
}

// trialRec is the write-ahead record of a live add (7.5 step 2): config, hash, boot
// and the PID of the process it was added to, so a restart of the agent can tell a
// trial that the slot survived from one that ended it.
type trialRec struct {
	Rec  runRec `json:"rec"`
	Boot string `json:"boot"`
	PID  int    `json:"pid"`
}

// persisted is state.json.
type persisted struct {
	Slot    string            `json:"slot"`    // active slot, "a" when lost (7.7 step 6)
	Version string            `json:"version"` // its release
	Running []runRec          `json:"running"`
	Retired []retiredRec      `json:"retired,omitempty"`
	Drain   *drainRec         `json:"drain,omitempty"`
	Trial   *trialRec         `json:"trial,omitempty"`
	Crashed map[string]string `json:"crashed,omitempty"` // config id -> hash of the fragment that ended the process
	Gens    map[string]int    `json:"gens,omitempty"`    // last generation of each config
	// BaseSig is the signature of the base (the blocked ranges) that the active slot's
	// process was started with: the slots outlive the agent, so a change of the node
	// addresses while the agent was down is found by comparing it at the next start.
	BaseSig string `json:"base_sig,omitempty"`
	// CandidateRun is the run id of the last xray.candidate this agent acted on.
	CandidateRun string `json:"candidate_run,omitempty"`
}

// wantedFile is wanted.json.
type wantedFile struct {
	Configs []wantedRec `json:"configs"`
}

type wantedRec struct {
	ID       string   `json:"id"`
	Location uint32   `json:"loc"`
	Tag      string   `json:"tag"`
	Priority uint32   `json:"prio"`
	Fragment []byte   `json:"frag"`
	Accepted []string `json:"accepted,omitempty"`
}

// goodRec is good/<id>.json.
type goodRec struct {
	Hash     string `json:"hash"`
	Frag     []byte `json:"frag"`
	Location uint32 `json:"loc"`
	Priority uint32 `json:"prio"`
	Stateful bool   `json:"stateful,omitempty"`
	// Accepted is the list the fragment was accepted with: a restored good fragment is judged
	// by it and not by the list of the newer fragment that ended the process (B5 r3-2).
	Accepted []string `json:"accepted,omitempty"`
}

// writeFile writes atomically: a temporary file in the directory, then a rename, so
// a crash leaves the old file or the new one and never half of either.
func writeFile(path string, data []byte, mode fs.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	name := f.Name()
	ok := false
	defer func() {
		if !ok {
			_ = f.Close()
			_ = os.Remove(name)
		}
	}()
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Chmod(mode); err != nil && !errors.Is(err, errors.ErrUnsupported) {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	ok = true
	return nil
}

func readJSON(path string, v any) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() > maxStateFile {
		return errors.New("xray: a state file is not a regular file of a sane size")
	}
	return json.NewDecoder(f).Decode(v)
}

func (m *Manager) statePath(name string) string { return filepath.Join(m.opt.StateDir, name) }
func (m *Manager) goodPath(id string) string {
	return filepath.Join(m.opt.StateDir, "good", id+".json")
}

func (m *Manager) saveState() error {
	b, err := json.Marshal(&m.st)
	if err != nil {
		return err
	}
	return writeFile(m.statePath("state.json"), b, 0o600)
}

func (m *Manager) loadState() {
	var p persisted
	if err := readJSON(m.statePath("state.json"), &p); err == nil {
		m.st = p
	}
	// With the state lost, slot a and the lowest allowed version (7.7 step 6): the
	// version is filled by the first start, which reads the allow file.
	if m.st.Slot != "a" && m.st.Slot != "b" {
		m.st.Slot = "a"
	}
	if m.st.Crashed == nil {
		m.st.Crashed = map[string]string{}
	}
	if m.st.Gens == nil {
		m.st.Gens = map[string]int{}
	}
}

func (m *Manager) saveWanted(cs []*cfgRec) {
	f := wantedFile{}
	for _, c := range cs {
		f.Configs = append(f.Configs, wantedRec{ID: c.hex, Location: c.Location, Tag: c.Tag,
			Priority: c.Priority, Fragment: c.Fragment, Accepted: c.Accepted})
	}
	if b, err := json.Marshal(f); err == nil {
		_ = writeFile(m.statePath("wanted.json"), b, 0o600)
	}
}

func (m *Manager) readGood(id string) (goodRec, bool) {
	var g goodRec
	if readJSON(m.goodPath(id), &g) != nil || len(g.Frag) == 0 {
		return goodRec{}, false
	}
	return g, true
}

func (m *Manager) writeGood(r runRec) {
	b, _ := json.Marshal(goodRec{Hash: r.Hash, Frag: r.Frag, Location: r.Location, Priority: r.Priority, Stateful: r.Stateful, Accepted: r.Accepted})
	_ = writeFile(m.goodPath(r.ID), b, 0o600)
}

func (m *Manager) deleteGood(id string) { _ = os.Remove(m.goodPath(id)) }
