package sock

import (
	"errors"
	"regexp"
)

// /run/ctrlz-xrayctl/ctl.sock (p4b-proxy 2.1, 7.5): the agent, or root, asks the
// unit ctrlz-xrayctl to run the Xray binary for one fixed operation. It takes the
// operations below and never a path, because the process that runs a binary on
// what an admin pasted must not be a way to run anything else.

// Operations of a `run` frame.
const (
	OpTest     = "test"
	OpAddOut   = "ado"
	OpAddIn    = "adi"
	OpAddRules = "adrules"
	OpRmOut    = "rmo"
	OpRmIn     = "rmi"
	OpRmRules  = "rmrules"
)

// Caps of the control socket.
const (
	MaxCtlTags   = 16
	MaxCtlStdin  = 256 << 10
	MaxCtlError  = 4 << 10
	maxTagLength = 64
)

// CtlMsg is one frame of ctl.sock. Exactly the field of its Type is set: `run`
// from the client, `result` back.
type CtlMsg struct {
	Type string `json:"t"`

	Run    *CtlRun    `json:"run,omitempty"`
	Result *CtlResult `json:"result,omitempty"`
}

// Types of CtlMsg.
const (
	CtlTypeRun    = "run"
	CtlTypeResult = "result"
)

// CtlRun asks for one operation. Version is a release tag the allow file holds.
// Slot is "a" or "b" for every operation but test. Tags are only in the forms of
// 7.4: the tag is never a file name (finding 4: `rmi` and `rmo` read an argument
// that names a file in the working directory), so a form that cannot be one is
// what this check is for. Stdin is the JSON of the operation.
type CtlRun struct {
	ID      uint64   `json:"id"`
	Version string   `json:"version"`
	Op      string   `json:"op"`
	Slot    string   `json:"slot,omitempty"`
	Tags    []string `json:"tags,omitempty"`
	Stdin   []byte   `json:"stdin,omitempty"`
}

// CtlResult is the answer: the exit status of the child and an error text that the
// agent treats as untrusted (7.5).
type CtlResult struct {
	ID    uint64 `json:"id"`
	Exit  int32  `json:"exit"`
	Error string `json:"error,omitempty"`
}

// CtlCodec is the codec of ctl.sock.
var CtlCodec = Codec[CtlMsg]{Check: (*CtlMsg).check}

var (
	versionRE = regexp.MustCompile(`^v[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$`)
	// 7.4: inbound `in:<id>.<g>`, rule `L<id>.<g>`, outbound `L<id>.<g>.<n>`, id as
	// 32 hex digits. Nothing else is a tag, and none of them can start with a
	// scheme or contain a slash, a dot-dot or a space.
	inTagRE   = regexp.MustCompile(`^in:[0-9a-f]{32}\.[0-9]{1,9}$`)
	ruleTagRE = regexp.MustCompile(`^L[0-9a-f]{32}\.[0-9]{1,9}$`)
	outTagRE  = regexp.MustCompile(`^L[0-9a-f]{32}\.[0-9]{1,9}\.[0-9]{1,3}$`)
)

func (m *CtlMsg) check() error {
	return one(m.Type,
		field{CtlTypeRun, m.Run != nil, func() error { return m.Run.check() }},
		field{CtlTypeResult, m.Result != nil, func() error { return lenMax("error", len(m.Result.Error), MaxCtlError) }},
	)
}

func (r *CtlRun) check() error {
	if !versionRE.MatchString(r.Version) {
		return errors.New("sock: ctl version is not a release tag")
	}
	hasStdin := false
	var tagRE *regexp.Regexp
	switch r.Op {
	case OpTest, OpAddOut, OpAddIn, OpAddRules:
		hasStdin = true
	case OpRmOut:
		tagRE = outTagRE
	case OpRmIn:
		tagRE = inTagRE
	case OpRmRules:
		tagRE = ruleTagRE
	default:
		return errors.New("sock: unknown ctl operation")
	}
	if r.Op == OpTest {
		if r.Slot != "" {
			return errors.New("sock: test takes no slot")
		}
	} else if r.Slot != "a" && r.Slot != "b" {
		return errors.New("sock: ctl slot is not a or b")
	}
	if len(r.Tags) > MaxCtlTags {
		return errors.New("sock: too many ctl tags")
	}
	if hasStdin {
		// The configuration travels on stdin and the tags inside it, so a tag
		// argument would be a second way to say the same thing.
		if len(r.Tags) != 0 || len(r.Stdin) == 0 {
			return errors.New("sock: this operation takes stdin and no tags")
		}
	} else if len(r.Tags) == 0 || len(r.Stdin) != 0 {
		return errors.New("sock: this operation takes tags and no stdin")
	}
	if len(r.Stdin) > MaxCtlStdin {
		return errors.New("sock: ctl stdin over its cap")
	}
	for _, t := range r.Tags {
		if len(t) > maxTagLength || !tagRE.MatchString(t) {
			return errors.New("sock: a ctl tag is not in the form of its operation")
		}
	}
	return nil
}
