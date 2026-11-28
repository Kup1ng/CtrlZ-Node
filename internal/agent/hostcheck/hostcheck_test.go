package hostcheck

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/Kup1ng/CtrlZ-Node/internal/agent/alert"
	"github.com/Kup1ng/CtrlZ-Node/internal/agent/sysx/fake"
)

const limitsOK = "Limit Soft Limit Hard Limit Units\nMax cpu time unlimited unlimited seconds\nMax core file size 0 0 bytes\n"
const dropIn = "[Coredump]\nStorage=none\nProcessSizeMax=0\n"

func goodFiles() *fake.Files {
	return fake.NewFiles(map[string]string{
		SelfLimitsPath:  limitsOK,
		CorePatternPath: "|/lib/systemd/systemd-coredump %P %u %g %s %t %c %h\n",
		CoredumpDropIn:  dropIn,
	})
}

func TestCoreDumps(t *testing.T) {
	if fs := CoreDumps(goodFiles()); len(fs) != 0 {
		t.Fatalf("findings on a good host: %v", fs)
	}
	for name, mut := range map[string]func(*fake.Files){
		"apport pipe":   func(f *fake.Files) { f.Set(CorePatternPath, "|/usr/share/apport/apport -p%p -s%s\n") },
		"empty pattern": func(f *fake.Files) { f.Set(CorePatternPath, "\n") },
		"core limit": func(f *fake.Files) {
			f.Set(SelfLimitsPath, strings.Replace(limitsOK, "0 0 bytes", "unlimited unlimited bytes", 1))
		},
		"no drop-in":          func(f *fake.Files) { delete(f.M, CoredumpDropIn) },
		"drop-in keeps cores": func(f *fake.Files) { f.Set(CoredumpDropIn, "[Coredump]\nStorage=external\nProcessSizeMax=0\n") },
		"limits unreadable":   func(f *fake.Files) { delete(f.M, SelfLimitsPath) },
	} {
		f := goodFiles()
		mut(f)
		fs := CoreDumps(f)
		if len(fs) != 1 || fs[0].Code != alert.CorePattern {
			t.Errorf("%s: %v", name, fs)
		}
	}
	// a plain file pattern is covered by the limit
	f := goodFiles()
	f.Set(CorePatternPath, "core\n")
	if fs := CoreDumps(f); len(fs) != 0 {
		t.Errorf("plain pattern refused: %v", fs)
	}
}

func TestHostResolver(t *testing.T) {
	nodes := []netip.Addr{netip.MustParseAddr("203.0.114.9"), netip.MustParseAddr("203.0.115.9")}
	f := fake.NewFiles(map[string]string{ResolvConf: "# x\nnameserver 127.0.0.53\noptions edns0\n"})
	if fs := HostResolver(f, nodes); len(fs) != 0 {
		t.Fatalf("clean host: %v", fs)
	}
	f.Set(ResolvedConf, "nameserver 9.9.9.9\nnameserver 203.0.115.9\n")
	fs := HostResolver(f, nodes)
	if len(fs) != 1 || fs[0].Code != alert.HostResolver {
		t.Fatalf("findings: %v", fs)
	}
	if strings.Contains(fs[0].Detail, "203.0") {
		t.Error("the finding names the address")
	}
	f.Set(ResolvConf, "nameserver ::ffff:203.0.114.9\n")
	if fs := HostResolver(f, nodes); len(fs) != 1 {
		t.Errorf("mapped form not caught: %v", fs)
	}
	f.Set(ResolvConf, "nameserver 203.0.114.9\n")
	f.Set(ResolvedConf, "")
	if fs := HostResolver(f, nil); len(fs) != 0 {
		t.Error("no node addresses, no finding")
	}
}

func TestEnsureConntrack(t *testing.T) {
	ctx := context.Background()
	f := fake.NewFiles(map[string]string{ConntrackMax: "65536\n"})
	r := &fake.Runner{Reply: func(c fake.Call) ([]byte, error) {
		f.Set(ConntrackMax, "524288\n")
		return nil, nil
	}}
	if fs := EnsureConntrack(ctx, f, r, DefaultConntrackMax); len(fs) != 0 {
		t.Fatalf("raised value still alerted: %v", fs)
	}
	if got := r.Lines(); len(got) != 1 || got[0] != "sysctl -w net.netfilter.nf_conntrack_max=524288" {
		t.Errorf("calls %v", got)
	}
	// already enough: no command
	r2 := &fake.Runner{}
	if fs := EnsureConntrack(ctx, f, r2, 1000); len(fs) != 0 || len(r2.Calls()) != 0 {
		t.Error("work for nothing")
	}
	// cannot raise: alert
	f.Set(ConntrackMax, "65536\n")
	r3 := &fake.Runner{Reply: func(fake.Call) ([]byte, error) { return nil, errors.New("denied") }}
	if fs := EnsureConntrack(ctx, f, r3, DefaultConntrackMax); len(fs) != 1 || fs[0].Code != alert.ConntrackLow {
		t.Errorf("findings %v", fs)
	}
	// raised by the command but the kernel clamps it: alert
	r4 := &fake.Runner{}
	if fs := EnsureConntrack(ctx, f, r4, DefaultConntrackMax); len(fs) != 1 {
		t.Errorf("a value still low must alert: %v", fs)
	}
	// no module
	if fs := EnsureConntrack(ctx, fake.NewFiles(nil), r4, 1); len(fs) != 1 {
		t.Error("missing file")
	}
	mem := &alert.Memory{}
	Alerts(mem, CoreDumps(fake.NewFiles(nil)))
	if mem.Count(alert.CorePattern) != 3 {
		t.Errorf("alerts = %d", mem.Count(alert.CorePattern))
	}
}

// T-017: the agent alerts when SYN cookies are off or cannot be read. Removing the
// v != "1" && v != "2" test in Syncookies makes the "off" case return nothing; removing
// the read-error branch makes the "unreadable" case return nothing.
func TestSyncookies(t *testing.T) {
	for _, on := range []string{"1\n", "2\n"} {
		if fs := Syncookies(fake.NewFiles(map[string]string{SyncookiesPath: on})); len(fs) != 0 {
			t.Errorf("value %q refused: %v", on, fs)
		}
	}
	for name, content := range map[string]string{"off": "0\n", "empty": "\n", "junk": "yes\n"} {
		fs := Syncookies(fake.NewFiles(map[string]string{SyncookiesPath: content}))
		if len(fs) != 1 || fs[0].Code != alert.SyncookiesOff {
			t.Errorf("%s: %v", name, fs)
		}
	}
	fs := Syncookies(fake.NewFiles(nil))
	if len(fs) != 1 || fs[0].Code != alert.SyncookiesOff {
		t.Errorf("unreadable: %v", fs)
	}
	mem := &alert.Memory{}
	Alerts(mem, fs)
	if mem.Count(alert.SyncookiesOff) != 1 {
		t.Error("the finding was not raised as an alert")
	}
}

func TestProxyKernel(t *testing.T) {
	m := map[string]string{}
	for _, k := range ProxySysctl {
		// /proc/sys values of three numbers are separated by tabs.
		m["/proc/sys/"+strings.ReplaceAll(k[0], ".", "/")] = strings.ReplaceAll(k[1], " ", "\t") + "\n"
	}
	f := fake.NewFiles(m)
	if fs := ProxyKernel(f); len(fs) != 0 {
		t.Fatalf("findings on the installed values: %v", fs)
	}
	f.Set("/proc/sys/net/ipv4/tcp_mem", "1\t2\t3\n")
	fs := ProxyKernel(f)
	if len(fs) != 1 || fs[0].Code != alert.SysctlOff || !strings.Contains(fs[0].Detail, "tcp_mem") {
		t.Fatalf("findings %v", fs)
	}
	// A missing module has no file for the timeouts: that is a finding too.
	if fs := ProxyKernel(fake.NewFiles(nil)); len(fs) != len(ProxySysctl) {
		t.Fatalf("findings %d", len(fs))
	}
}
