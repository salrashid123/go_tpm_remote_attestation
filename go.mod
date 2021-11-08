module main

go 1.17

require (
	github.com/golang/glog v0.0.0-20160126235308-23def4e6c14b
	github.com/golang/protobuf v1.5.2
	github.com/google/go-tpm v0.3.3-0.20210409082102-d3310770bfec
	github.com/google/go-tpm-tools v0.3.1
	github.com/google/uuid v1.2.0
	github.com/salrashid123/go_tpm_registrar/verifier v0.0.0
	golang.org/x/crypto v0.0.0-20210921155107-089bfa567519 // indirect
	golang.org/x/exp v0.0.0-20200331195152-e8c3332aa8e5
	golang.org/x/net v0.0.0-20210226172049-e18ecbb05110
	google.golang.org/grpc v1.35.0
)

require (
	github.com/google/certificate-transparency-go v1.1.1 // indirect
	github.com/google/go-attestation v0.3.2 // indirect
	github.com/google/go-tspi v0.2.1-0.20190423175329-115dea689aad // indirect
	golang.org/x/sys v0.0.0-20210615035016-665e8c7367d1 // indirect
	golang.org/x/text v0.3.4 // indirect
	google.golang.org/genproto v0.0.0-20201214200347-8c77b98c765d // indirect
	google.golang.org/protobuf v1.27.1 // indirect
)

replace github.com/salrashid123/go_tpm_registrar/verifier => ./src/verifier

