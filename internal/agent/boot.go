package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"time"

	"google.golang.org/grpc"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/alert"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/conf"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/hubconn"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sock"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sysx"
	"github.com/Kup1ng/CtrlZ-Node/internal/enroll"
	"github.com/Kup1ng/CtrlZ-Node/internal/labroot"
)

const osReleasePath = "/etc/os-release"

// bootEnv is where Main gets its inputs. Main fills the production paths; a test
// fills the same struct with its own and the hooks, and so runs the real start-up
// sequence (the lab-root check, enrolment, the identity, the Control stream) and not
// a copy of it.
type bootEnv struct {
	Version  string
	Root     string // /var/lib/ctrlz
	ConfPath string
	SockPath string

	// The hooks below are nil in production.
	OSReleasePath string
	Out           io.Writer                                        // the console of enrolment, os.Stdout
	Hostname      func() (string, error)                           // os.Hostname
	LookupUID     func(name string) (uint32, error)                // the uid of ctrlz-dns
	TuneEnroll    func(*enroll.Config)                             // timings and the dialer of the enrolment
	Tune          func(*Config)                                    // the real Config before New
	Sleep         func(ctx context.Context, d time.Duration) error // the waits of the enrolment back-off
}

func isLabRoot(err error) bool { return errors.Is(err, labroot.ErrLabRoot) }

// boot is the agent's start: agent.conf, the root of trust, the node's identity
// (enrolled first when keys/ holds none), then New and Run.
func boot(ctx context.Context, env bootEnv) error {
	ac, err := conf.Read(env.ConfPath)
	if err != nil {
		return fmt.Errorf("agent: %s: %w", env.ConfPath, err)
	}
	keys := filepath.Join(env.Root, "keys")

	// The root comes first. A release build that finds the lab test root stops here,
	// before it has made a key or spent the enrolment token on a hub whose bundles
	// anyone could have signed.
	trust := &rootCache{path: filepath.Join(keys, hubconn.RootFile)}
	if err := trust.load(); err != nil {
		return fmt.Errorf("agent: %s: %w", filepath.Join(keys, hubconn.RootFile), err)
	}

	id, err := ensureIdentity(ctx, env, ac, keys)
	if err != nil {
		return err
	}

	lookup := env.LookupUID
	if lookup == nil {
		lookup = func(name string) (uint32, error) {
			u, err := user.Lookup(name)
			if err != nil {
				return 0, err
			}
			n, err := strconv.ParseUint(u.Uid, 10, 32)
			return uint32(n), err
		}
	}
	uid, err := lookup(DNSUser)
	if err != nil {
		return fmt.Errorf("agent: the user %s: %w", DNSUser, err)
	}

	cfg := Config{
		Root: env.Root, Conf: ac, ConfPath: env.ConfPath,
		SockPath: env.SockPath, SockGroup: SockGroup, PeerCheck: sock.UIDCheck(uid),
		Version:   env.Version,
		Identity:  id,
		Dial:      func(r hubconn.Role) (*grpc.ClientConn, error) { return id.Dial(ac.HubAddr(), r) },
		TrustRoot: trust.get,
		Runner:    sysx.ExecRunner{},
		Files:     sysx.OSFiles{},
		// An alert is a line in the journal, at most one a minute for a code. It holds
		// no name, address or key (package alert).
		Alert: &alert.Log{W: os.Stderr},
	}
	if env.Tune != nil {
		env.Tune(&cfg)
	}
	a, err := New(cfg)
	if err != nil {
		return err
	}
	// Run opens Control: 4.2 step 7, after the certificate is stored and not before.
	return a.Run(ctx)
}

// ensureIdentity returns the node's identity. A node with no certificate or no key
// in keys/ is a fresh install: it enrols (4.2 steps 3, 6 and 7) and, once the hub
// has approved, loads what the enrolment wrote. Anything else that is wrong with the
// files (a broken certificate, a missing CA) is not a reason to enrol again, and
// LoadIdentity reports it as it always has.
func ensureIdentity(ctx context.Context, env bootEnv, ac conf.Agent, keys string) (*hubconn.Identity, error) {
	have, err := haveIdentity(keys)
	if err != nil {
		return nil, err
	}
	if !have {
		if err := enrolNode(ctx, env, ac, keys); err != nil {
			return nil, err
		}
	}
	return hubconn.LoadIdentity(keys, ac.HubHost())
}

func haveIdentity(keys string) (bool, error) {
	for _, name := range []string{hubconn.NodeCertFile, hubconn.NodeKeyFile} {
		if _, err := os.Stat(filepath.Join(keys, name)); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return false, nil
			}
			return false, fmt.Errorf("agent: %s: %w", name, err)
		}
	}
	return true, nil
}

func enrolNode(ctx context.Context, env bootEnv, ac conf.Agent, keys string) error {
	pinTxt, err := os.ReadFile(filepath.Join(keys, hubconn.HubPinFile))
	if err != nil {
		return fmt.Errorf("agent: enrolment: %s: %w", hubconn.HubPinFile, err)
	}
	pin, err := hubconn.ParsePin(string(pinTxt))
	if err != nil {
		return fmt.Errorf("agent: enrolment: %w", err)
	}
	caPEM, err := os.ReadFile(filepath.Join(keys, hubconn.NodeCAFile))
	if err != nil {
		return fmt.Errorf("agent: enrolment: %s: %w", hubconn.NodeCAFile, err)
	}
	hostname := os.Hostname
	if env.Hostname != nil {
		hostname = env.Hostname
	}
	host, err := hostname()
	if err != nil {
		return fmt.Errorf("agent: enrolment: host name: %w", err)
	}
	osPath := env.OSReleasePath
	if osPath == "" {
		osPath = osReleasePath
	}
	osRel, _ := os.ReadFile(osPath) // an unreadable file reads as "unknown", which the hub accepts
	out := env.Out
	if out == nil {
		out = os.Stdout // the journal of ctrlz-agent: the admin compares what it shows with the panel
	}
	sleep := env.Sleep
	if sleep == nil {
		sleep = ctxSleep
	}
	ec := enroll.Config{
		KeysDir: keys, Hub: ac.HubAddr(), HubHost: ac.HubHost(), Pin: pin, NodeCAPEM: caPEM,
		DNSBind: ac.DNSBindIP, DNSAdvertised: ac.DNSAdvertisedIP,
		ProxyBind: ac.ProxyBindIP, ProxyAdvertised: ac.ProxyAdvertisedIP,
		Hostname: host, OSRelease: enroll.OSRelease(osRel), NodeVersion: env.Version,
		Out: out,
	}
	if env.TuneEnroll != nil {
		env.TuneEnroll(&ec)
	}
	// A transient failure (the hub is down, busy or answers nonsense) is retried here with
	// a back-off, as Control is: leaving it to systemd's 2 s restart would call Enroll
	// thirty times a minute, which is the hub's whole limit for the source's /24 (5.7) and
	// would keep that limit full for every other node of the prefix. The token is kept by
	// enroll on these answers and the pending record resumes a half-made enrolment.
	var err2 error
	for attempt := 0; ; attempt++ {
		_, err2 = enroll.Run(ctx, ec)
		if err2 == nil {
			return nil
		}
		if ctx.Err() != nil || !(errors.Is(err2, enroll.ErrHubUnreachable) || errors.Is(err2, enroll.ErrBadHub)) {
			break
		}
		d := enrolBackoff(attempt)
		fmt.Fprintf(out, "ctrlz-enroll: %v; trying again in %s\n", err2, d)
		if err := sleep(ctx, d); err != nil {
			return err2
		}
	}
	// A dead enrolment (no token, rejected, expired, a bad certificate) ends the process,
	// and systemd starts it again two seconds later with the same outcome. Hold a minute
	// first, so the journal carries one line a minute and not thirty, and the admin has
	// the time to run the install command again (which stops this unit and wakes it).
	if ctx.Err() == nil {
		_ = sleep(ctx, deadEnrolmentHold)
	}
	return err2
}

// enrolBackoff is the wait before the n-th retry: 1 s, doubling, at most 30 s.
func enrolBackoff(n int) time.Duration {
	d := time.Second << min(n, 5)
	return min(d, 30*time.Second)
}

// deadEnrolmentHold is how long boot waits before it gives up on an enrolment that
// cannot succeed on its own.
const deadEnrolmentHold = time.Minute

// ctxSleep waits d or until ctx ends.
func ctxSleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
