package sock

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// The codec of the P4b sockets (p4b-proxy 2.1): a 4-byte length, a JSON body, bytes
// as base64. proxy.sock, serve.sock, the block agent socket and ctl.sock all use it,
// each with its own message type. agent.sock keeps the older Read and Write above
// because its frames are larger (a table, a zone key), so its caps differ.
//
// Why one generic codec and not a copy per socket: the rules that keep a hostile or
// broken peer from costing memory (length checked before anything is allocated, an
// unknown field or type ends the connection, a frame is validated before it is used)
// must be the same on every socket, and a copy that drifts is where they get lost.
const (
	// MaxFrame is the cap of every P4b socket's frame.
	MaxFrame = 1 << 20
	// MaxPartBytes and MaxPartItems cap one part of a list; MaxListBytes caps the
	// whole list (2.1). A part is cut by whichever limit comes first.
	MaxPartBytes = 512 << 10
	MaxPartItems = 5000
	MaxListBytes = 64 << 20
)

// ErrFrame is a frame over its cap, empty, or with a length that cannot be right.
var ErrFrame = errors.New("sock: frame size")

// Codec reads and writes the frames of one socket. M is the socket's envelope;
// Check is its validator: it must reject an unknown type, a type whose field is
// not the one set, and every field out of its bound. A nil Check is refused at
// use, so a socket cannot be added without one.
type Codec[M any] struct {
	// Check validates a message after it was decoded and before it was encoded.
	Check func(*M) error
	// IsList says that a message is one part of a list, whose frame is held to
	// MaxPartBytes and not to MaxFrame.
	IsList func(*M) bool
}

// Write validates m and sends it as one frame. The validation is on the sending
// side too: a bug that builds a message the peer will refuse shows up as an error
// here, in the process that made it, and not as a connection that closes.
func (c Codec[M]) Write(w io.Writer, m *M) error {
	_, err := c.WriteSized(w, m)
	return err
}

// WriteSized is Write that also returns the encoded size of the body, which the
// sender of a list counts against MaxListBytes.
func (c Codec[M]) WriteSized(w io.Writer, m *M) (int, error) {
	if c.Check == nil {
		return 0, errors.New("sock: a codec needs a Check")
	}
	if err := c.Check(m); err != nil {
		return 0, err
	}
	b, err := json.Marshal(m)
	if err != nil {
		return 0, fmt.Errorf("sock: marshal: %w", err)
	}
	max := MaxFrame
	if c.IsList != nil && c.IsList(m) {
		max = MaxPartBytes
	}
	if len(b) > max {
		return 0, ErrFrame
	}
	var h [4]byte
	binary.BigEndian.PutUint32(h[:], uint32(len(b)))
	// One Write call: two writers of the same connection never interleave a header
	// with another frame's body as long as the caller serialises its calls.
	if _, err := w.Write(append(h[:], b...)); err != nil {
		return 0, err
	}
	return len(b), nil
}

// Read reads one frame and validates it. The length is judged before the body is
// allocated. Exactly the frame's bytes are consumed, so a socket whose frame is
// followed by raw bytes (serve.sock) can read the rest from the same connection.
func (c Codec[M]) Read(r io.Reader) (*M, error) {
	m, _, err := c.ReadSized(r)
	return m, err
}

// ReadSized is Read that also returns the size of the body.
func (c Codec[M]) ReadSized(r io.Reader) (*M, int, error) {
	if c.Check == nil {
		return nil, 0, errors.New("sock: a codec needs a Check")
	}
	var h [4]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return nil, 0, err
	}
	n := binary.BigEndian.Uint32(h[:])
	if n == 0 || int64(n) > MaxFrame {
		return nil, 0, ErrFrame
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, 0, err
	}
	m := new(M)
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(m); err != nil {
		return nil, 0, decodeErr(err)
	}
	if err := noTrailing(dec); err != nil {
		return nil, 0, err
	}
	if c.IsList != nil && c.IsList(m) && int(n) > MaxPartBytes {
		return nil, 0, ErrFrame
	}
	if err := c.Check(m); err != nil {
		return nil, 0, err
	}
	return m, int(n), nil
}

// decodeErr turns an encoding/json error into a fixed text. The library quotes the
// key of an unknown field and the literal of a wrong number, both chosen by the
// peer and as long as the frame, and a reader that logs its read error would then
// write the peer's text into the journal on every reconnect (an error names the
// field and never a value: 5.2 step 7).
func decodeErr(err error) error {
	kind := "field or value"
	var syn *json.SyntaxError
	var typ *json.UnmarshalTypeError
	switch {
	case errors.As(err, &syn):
		kind = "syntax"
	case errors.As(err, &typ):
		kind = "type"
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		kind = "short body"
	}
	return errors.New("sock: decode failed: " + kind)
}

// noTrailing refuses any byte after the first value but white space. Decoder.More
// is not that check: it answers false before a closing bracket, so `}` or `]` after
// the message would pass. A second Token call must report the end of the input.
func noTrailing(dec *json.Decoder) error {
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("sock: bytes after the message")
	}
	return nil
}

// SplitList cuts items into the parts of a list: at most MaxPartItems each and at
// most MaxPartBytes of encoded items together with the room a part's envelope
// needs. There is always at least one part, so an empty list still says "last".
// It refuses a list over MaxListBytes, and an item that alone cannot fit a part.
func SplitList[T any](items []T) ([][]T, error) {
	// envelope is what a part's frame holds besides its items: the type, the
	// brackets, `last`, and a run id. Generous on purpose: a part that is a few
	// bytes under the cap is no reason to risk the frame check on the peer.
	const envelope = 256
	var parts [][]T
	var cur []T
	curBytes, total := envelope, 0
	for _, it := range items {
		b, err := json.Marshal(it)
		if err != nil {
			return nil, fmt.Errorf("sock: marshal item: %w", err)
		}
		sz := len(b) + 1 // the comma
		if sz+envelope > MaxPartBytes {
			return nil, ErrFrame
		}
		total += sz
		if total > MaxListBytes {
			return nil, errors.New("sock: list over its cap")
		}
		if len(cur) == MaxPartItems || curBytes+sz > MaxPartBytes {
			parts = append(parts, cur)
			cur, curBytes = nil, envelope
		}
		cur = append(cur, it)
		curBytes += sz
	}
	return append(parts, cur), nil
}

// ListAssembler joins the parts of one list on the receiving side. It is the
// receiver's half of the 64 MiB cap: a sender that never says `last` fills no more
// than that. The zero value is ready.
type ListAssembler[T any] struct {
	items []T
	bytes int64
}

// Add takes one part (its decoded items, the size of its frame body from
// ReadSized, and `last`). It returns the whole list once the last part arrived.
// After an error or a completed list the assembler is empty again: a connection
// that sent a bad part is closed by its owner anyway.
func (a *ListAssembler[T]) Add(part []T, encoded int, last bool) ([]T, bool, error) {
	if len(part) > MaxPartItems || encoded > MaxPartBytes {
		a.reset()
		return nil, false, ErrFrame
	}
	a.bytes += int64(encoded)
	if a.bytes > MaxListBytes {
		a.reset()
		return nil, false, errors.New("sock: list over its cap")
	}
	a.items = append(a.items, part...)
	if !last {
		return nil, false, nil
	}
	out := a.items
	a.reset()
	return out, true, nil
}

// Reset drops a half-received list (the connection ended).
func (a *ListAssembler[T]) Reset() { a.reset() }

func (a *ListAssembler[T]) reset() { a.items, a.bytes = nil, 0 }
