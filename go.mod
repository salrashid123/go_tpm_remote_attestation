module main

go 1.17

require (
	github.com/golang/glog v0.0.0-20210429001901-424d2337a529
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/google/go-tpm v0.3.3
	github.com/google/go-tpm-tools v0.3.12
	github.com/google/go-tspi v0.3.0 // indirect
	github.com/google/uuid v1.3.0
	github.com/salrashid123/go_tpm_registrar/verifier v0.0.0
	golang.org/x/exp v0.0.0-20200331195152-e8c3332aa8e5
	golang.org/x/net v0.0.0-20211112202133-69e39bad7dc2
	golang.org/x/text v0.3.6 // indirect
	google.golang.org/genproto v0.0.0-20210821163610-241b8fcbd6c8 // indirect
	google.golang.org/grpc v1.40.0
	google.golang.org/protobuf v1.28.0
)

require github.com/google/go-attestation v0.4.4-0.20220404204839-8820d49b18d9

require (
	github.com/google/certificate-transparency-go v1.1.2 // indirect
	github.com/google/go-sev-guest v0.6.1 // indirect
	github.com/google/logger v1.1.1 // indirect
	github.com/pborman/uuid v1.2.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	go.uber.org/atomic v1.7.0 // indirect
	go.uber.org/multierr v1.8.0 // indirect
	golang.org/x/crypto v0.0.0-20220525230936-793ad666bf5e // indirect
	golang.org/x/sys v0.5.0 // indirect
)

replace github.com/salrashid123/go_tpm_registrar/verifier => ./src/verifier
