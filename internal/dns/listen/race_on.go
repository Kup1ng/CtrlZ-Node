//go:build race

package listen

// raceEnabled is true when the tests run under the race detector, which makes
// every handshake and every packet several times slower.
const raceEnabled = true
