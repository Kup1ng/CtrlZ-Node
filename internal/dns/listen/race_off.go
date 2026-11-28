//go:build !race

package listen

// The two raceEnabled files are not _test.go files on purpose: a test file that only a
// build tag builds is a test no job runs unless a job sets the tag (the gofiles check of
// the CI refuses it), and the constant is all the tests need to know about -race.
const raceEnabled = false
