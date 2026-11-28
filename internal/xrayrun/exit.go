package xrayrun

// The status that ctrlz-xrayctl answers when the child gave none of its own. A status above
// 0 is the binary's own and is a verdict on what it was given; every status below 0 says
// that nothing was judged, and which of the ways it went wrong, because the manager acts
// differently on each (B5 r1-2, r1-5):
//
//   - CtlNotJudged: the call never reached the binary (a release the allow file does not
//     name, a bad request, a cancelled call).
//   - CtlTimeout: the child ran past its limit and was killed. One is no verdict, but the
//     same input three times in a row is the fragment's doing, not the node's.
//   - CtlNoRun: the binary could not be executed at all (missing, wrong architecture).
//     It is a fact about the release, so an upgrade to it is blocked instead of retried.
//   - CtlSignal: the child was killed by a signal (the unit's memory limit, an OOM kill).
//     Counted like a timeout.
const (
	CtlNotJudged int32 = -1
	CtlTimeout   int32 = -2
	CtlNoRun     int32 = -3
	CtlSignal    int32 = -4
)
