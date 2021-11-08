module main

go 1.17

require (
	github.com/golang/glog v0.0.0-20210429001901-424d2337a529
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/google/go-tpm v0.3.3-0.20210409082102-d3310770bfec
	github.com/google/go-tpm-tools v0.3.1
	github.com/google/go-tspi v0.3.0 // indirect
	github.com/google/uuid v1.3.0
	github.com/salrashid123/go_tpm_registrar/verifier v0.0.0
	golang.org/x/exp v0.0.0-20200331195152-e8c3332aa8e5
	golang.org/x/net v0.0.0-20210226172049-e18ecbb05110
	golang.org/x/text v0.3.4 // indirect
	google.golang.org/genproto v0.0.0-20201214200347-8c77b98c765d // indirect
	google.golang.org/grpc v1.40.0
	google.golang.org/protobuf v1.27.1
)

require (
	github.com/google/certificate-transparency-go v1.1.1 // indirect
	github.com/google/go-attestation v0.3.2 // indirect
	golang.org/x/crypto v0.0.0-20210314154223-e6e6c4f2bb5b // indirect
	golang.org/x/sys v0.0.0-20210316092937-0b90fd5c4c48 // indirect
)

replace github.com/salrashid123/go_tpm_registrar/verifier => ./src/verifier
