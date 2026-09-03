module main

go 1.26.2

require (
	github.com/golang/glog v1.2.5
	github.com/google/uuid v1.6.0
	github.com/salrashid123/go_tpm_registrar/verifier v0.0.0
	golang.org/x/net v0.48.0 // indirect
	golang.org/x/text v0.32.0 // indirect
	google.golang.org/grpc v1.77.0
	google.golang.org/protobuf v1.36.11 // indirect
)

require (
	github.com/google/go-attestation v0.6.0
	github.com/google/go-tpm v0.9.7
	github.com/google/go-tpm-tools v0.4.7
	github.com/smallstep/certinfo v1.16.0
)

require (
	github.com/google/certificate-transparency-go v1.3.2 // indirect
	github.com/google/go-configfs-tsm v0.3.3 // indirect
	github.com/google/go-eventlog v0.0.2-0.20241003021507-01bb555f7cba // indirect
	github.com/google/go-sev-guest v0.14.1 // indirect
	github.com/google/go-tdx-guest v0.3.2-0.20241009005452-097ee70d0843 // indirect
	github.com/google/logger v1.1.1 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/crypto v0.46.0 // indirect
	golang.org/x/sys v0.39.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20251222181119-0a764e51fe1b // indirect
)

replace github.com/salrashid123/go_tpm_registrar/verifier => ./src/verifier
