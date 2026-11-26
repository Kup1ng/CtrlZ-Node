// Package dns is the DNS role: sockets bound to DNS_IP for UDP/TCP 53, DoT, DoH
// and DoQ, and the query pipeline of the shared contract (section 5.2).
//
// The pipeline order is fixed by the contract and the golden vectors, and the
// steps that are shared code (system names, identity, SelectStack, Pre, Post)
// are called, not copied. This package owns only the glue: sockets, rate
// limits, the cache and the router.
package dns

import (
	"github.com/Kup1ng/CtrlZ-Node/internal/config"
)

// Step names the stages of the node query path, in order (contract 5.2). The
// list exists so logs and tests can refer to a stage by name; it is the
// pipeline's table of contents, not an implementation of it.
type Step string

const (
	StepSocket    Step = "socket_and_rate_limit"
	StepSysNames  Step = "system_names"
	StepOwnZone   Step = "own_zone"
	StepIdentity  Step = "identity"
	StepVerify    Step = "verify_names"
	StepAdmin     Step = "authorized_ips_and_admin_state"
	StepStack     Step = "select_stack"
	StepPre       Step = "pre"
	StepGrant     Step = "grant_when_done"
	StepResolve   Step = "cache_and_router"
	StepPost      Step = "post"
	StepAnswerLog Step = "answer_and_log"
)

// Run starts the DNS role. Stub.
func Run(cfg config.Config) error { return config.ErrNotImplemented }
