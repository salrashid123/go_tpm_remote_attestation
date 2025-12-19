module main

go 1.24.0

require (
	github.com/golang/glog v1.2.5
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/google/go-tspi v0.3.0 // indirect
	github.com/google/uuid v1.6.0
	github.com/salrashid123/go_tpm_registrar/verifier v0.0.0
	golang.org/x/net v0.48.0
	golang.org/x/text v0.32.0 // indirect
	google.golang.org/grpc v1.77.0
	google.golang.org/protobuf v1.36.11 // indirect
)

require (
	github.com/google/go-attestation v0.5.1
	github.com/google/go-tpm v0.9.0
	github.com/google/go-tpm-tools v0.4.2
)

require (
	github.com/google/certificate-transparency-go v1.1.2 // indirect
	github.com/google/go-sev-guest v0.9.3 // indirect
	github.com/google/go-tdx-guest v0.2.3-0.20231011100059-4cf02bed9d33 // indirect
	github.com/google/logger v1.1.1 // indirect
	github.com/pborman/uuid v1.2.1 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/crypto v0.46.0 // indirect
	golang.org/x/sys v0.39.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20251213004720-97cd9d5aeac2 // indirect
)

replace github.com/salrashid123/go_tpm_registrar/verifier => ./src/verifier
