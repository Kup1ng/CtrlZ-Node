module github.com/Kup1ng/CtrlZ-Node

go 1.27.4

require github.com/Kup1ng/CtrlZ-Shared v0.0.0

require (
	golang.org/x/net v0.62.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
	golang.org/x/text v0.43.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260817212433-ac3dfec99bb1 // indirect
	google.golang.org/grpc v1.85.0 // indirect
	google.golang.org/protobuf v1.36.12 // indirect
)

// shared/ is an identical copy of "Ctrl Z Panel/shared" (the canonical one),
// kept in sync by scripts/shared-sync and checked by scripts/shared-verify. A
// replace to a directory means the node builds against exactly the bytes that
// were verified, never against a tag someone could move.
replace github.com/Kup1ng/CtrlZ-Shared => ./shared
