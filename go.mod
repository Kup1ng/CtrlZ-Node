module github.com/Kup1ng/CtrlZ-Node

go 1.27.4

require (
	github.com/AdguardTeam/dnsproxy v0.86.0
	github.com/Kup1ng/CtrlZ-Shared v0.0.0
	github.com/miekg/dns v1.1.73
	github.com/quic-go/quic-go v0.65.0
	golang.org/x/net v0.62.0
	google.golang.org/grpc v1.85.0
	google.golang.org/protobuf v1.36.12
)

require (
	github.com/AdguardTeam/dnscrypt v0.0.2 // indirect
	github.com/AdguardTeam/golibs v0.35.13 // indirect
	github.com/ameshkov/dnsstamps v1.0.3 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	github.com/robfig/cron/v3 v3.0.1 // indirect
	golang.org/x/crypto v0.59.0 // indirect
	golang.org/x/exp v0.0.0-20260611194520-c48552f49976 // indirect
	golang.org/x/sys v0.50.0 // indirect
	golang.org/x/text v0.44.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260817212433-ac3dfec99bb1 // indirect
)

// shared/ is an identical copy of "Ctrl Z Panel/shared" (the canonical one),
// kept in sync by scripts/shared-sync and checked by scripts/shared-verify. A
// replace to a directory means the node builds against exactly the bytes that
// were verified, never against a tag someone could move.
replace github.com/Kup1ng/CtrlZ-Shared => ./shared
