package xrayschema

import "strings"

// kind is the JSON shape a table node accepts.
type kind uint8

const (
	kObj     kind = iota + 1 // object with the keys of fields
	kArr                     // array of elem
	kStr                     // string
	kNum                     // number
	kBool                    // true or false
	kStrList                 // a string, or an array of strings (Xray's StringList)
	kRange                   // a number or a string such as "1-2" (Xray's Int32Range, PortList)
	kAny                     // a string, a number or a boolean
	kRaw                     // any JSON value; still scanned for forbidden keys and values
	kStrMap                  // an object whose keys are free (HTTP headers); its values are strings or string lists
	kEnum                    // a string that must be one of enum
)

// node is one place of a release table. The tables are built by functions and
// never kept in a package-level variable: the module has no mutable package state,
// and a table is read-only once Check has it.
type node struct {
	k kind
	// fields maps the canonical spelling of each allowed key to its node.
	fields map[string]*node
	// alias maps an old spelling to the canonical (new) one. A member under either
	// is stored under the new one; both with different values is a rejection.
	alias map[string]string
	// reject lists keys (lower case) that are refused in this object on top of the
	// global list, each with a reason that is about this object alone.
	reject map[string]string
	elem   *node
	max    int // longest array, 0 for the default
	// enum maps the lower-case spelling of a value to its canonical form. The loader
	// of the release folds these values with strings.ToLower before it compares, and so
	// does Check. soft says that an unknown value is a warning that accept_unknown can
	// pass; a hard enum refuses it for good.
	enum map[string]string
	soft bool
	// lazy defers the node to the first use, so a table can contain itself
	// (downloadSettings holds stream settings). Depth is bounded by MaxDepth.
	lazy func() *node
	// A variant picks the node of one member by the value of another: selKey is the
	// member that holds the selector (an enum), selOn the member that depends on it.
	selKey, selOn string
	sel           map[string]*node
	// strict makes an unknown key a rejection and not a warning (the top level).
	strict bool
	// dialer marks the string that names another outbound by its tag.
	dialer bool
	// forceTrue lists boolean keys that the normal form always sets to true.
	forceTrue []string
}

func (n *node) resolve() *node {
	for n.lazy != nil {
		n = n.lazy()
	}
	return n
}

type fd struct {
	key string
	n   *node
}

func f(key string, n *node) fd { return fd{key, n} }

func obj(fs ...fd) *node {
	n := &node{k: kObj, fields: make(map[string]*node, len(fs))}
	for _, x := range fs {
		n.fields[x.key] = x.n
	}
	return n
}

// aliased records that old is the former spelling of key.
func (n *node) aliased(key, old string) *node {
	if n.alias == nil {
		n.alias = map[string]string{}
	}
	n.alias[old] = key
	return n
}

func (n *node) refusing(key, why string) *node {
	if n.reject == nil {
		n.reject = map[string]string{}
	}
	n.reject[strings.ToLower(key)] = why
	return n
}

func (n *node) forcing(keys ...string) *node {
	n.forceTrue = append(n.forceTrue, keys...)
	return n
}

func arr(elem *node) *node { return &node{k: kArr, elem: elem} }

func str() *node                { return &node{k: kStr} }
func num() *node                { return &node{k: kNum} }
func boolean() *node            { return &node{k: kBool} }
func strList() *node            { return &node{k: kStrList} }
func rng() *node                { return &node{k: kRange} }
func anyScalar() *node          { return &node{k: kAny} }
func raw() *node                { return &node{k: kRaw} }
func strMap() *node             { return &node{k: kStrMap} }
func lazy(f func() *node) *node { return &node{lazy: f} }

func dialerTag() *node { return &node{k: kStr, dialer: true} }

// enumOf builds a hard enum. Each argument is "spelling=canonical" or just the
// canonical spelling.
func enumOf(soft bool, vals ...string) *node {
	n := &node{k: kEnum, soft: soft, enum: make(map[string]string, len(vals))}
	for _, v := range vals {
		spell, canon, found := strings.Cut(v, "=")
		if !found {
			canon = spell
		}
		n.enum[strings.ToLower(spell)] = canon
	}
	return n
}

// withVariant makes the member selOn depend on the enum member selKey.
func (n *node) withVariant(selKey, selOn string, by map[string]*node) *node {
	n.selKey, n.selOn, n.sel = selKey, selOn, by
	return n
}
