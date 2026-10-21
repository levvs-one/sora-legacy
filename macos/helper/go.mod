module github.com/levvs-one/sora-client/macos/helper

go 1.26.9

require (
	github.com/creachadair/jrpc2 v1.3.5
	github.com/levvs-one/sora-client/core v0.0.0
	google.golang.org/protobuf v1.36.11
)

require (
	github.com/Microsoft/go-winio v0.6.2 // indirect
	github.com/andybalholm/brotli v1.0.6 // indirect
	github.com/creachadair/mds v0.26.1 // indirect
	github.com/godbus/dbus/v5 v5.2.2 // indirect
	github.com/gopacket/gopacket v1.7.4 // indirect
	github.com/klauspost/compress v1.17.4 // indirect
	github.com/refraction-networking/utls v1.8.2 // indirect
	golang.org/x/crypto v0.57.0 // indirect
	golang.org/x/net v0.60.0 // indirect
	golang.org/x/sync v0.23.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
	golang.org/x/text v0.42.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260706201446-f0a921348800 // indirect
	google.golang.org/grpc v1.83.2 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

// The helper is a client of the core module in this repository, never of
// a published copy: the contract (sora.core.v1, 1.7) must match the
// daemon it ships with in the same tree.
replace github.com/levvs-one/sora-client/core => ../../core
