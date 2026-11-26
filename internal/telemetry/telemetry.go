// Package telemetry builds log batches, counters and the activity heartbeat,
// seals them to the hub key, spools them on disk and deletes spool data only
// after a durable ack (contract section 12). What is sent depends on the
// Endpoint's analytics level; the activity heartbeat is sent at every level
// and never carries a name.
package telemetry
