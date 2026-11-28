package xrayrun

import "testing"

// The slot's run directory is one directory a slot, /run/ctrlz-xray-<slot>, as
// p4b-proxy 3.3 and the tmpfiles line of the packaging name it. A change of either
// side alone leaves the unit unable to create the socket.
func TestDefaultLayoutRunDirectories(t *testing.T) {
	l := DefaultLayout()
	for slot, want := range map[string]string{
		"a": "/run/ctrlz-xray-a/api.sock",
		"b": "/run/ctrlz-xray-b/api.sock",
	} {
		if got := l.APISock(slot); got != want {
			t.Errorf("APISock(%s) = %s, want %s", slot, got, want)
		}
		if got := l.APILock(slot); got != want+".lock" {
			t.Errorf("APILock(%s) = %s, want %s.lock", slot, got, want)
		}
	}
	if got := l.APIDir("b"); got != "/run/ctrlz-xray-b" {
		t.Errorf("APIDir(b) = %s", got)
	}
}
