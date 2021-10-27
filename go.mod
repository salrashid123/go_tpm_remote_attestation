module main

go 1.17

require (
	certparser v0.0.0
	github.com/aws/aws-sdk-go v1.37.5 // indirect
	github.com/coreos/go-oidc v2.2.1+incompatible // indirect
	github.com/golang/glog v0.0.0-20160126235308-23def4e6c14b
	github.com/golang/protobuf v1.5.2
	github.com/google/certificate-transparency-go v1.1.1
	github.com/google/go-tpm v0.3.3-0.20210409082102-d3310770bfec
	github.com/google/go-tpm-tools v0.3.0-alpha7.0.20210712215558-1689caf35bff
	github.com/google/uuid v1.2.0
	github.com/hashicorp/vault/api v1.0.4 // indirect
	github.com/lestrrat/go-jwx v0.0.0-20180221005942-b7d4802280ae
	github.com/lestrrat/go-pdebug v0.0.0-20180220043741-569c97477ae8 // indirect
	github.com/pquerna/cachecontrol v0.0.0-20201205024021-ac21108117ac // indirect
	github.com/salrashid123/go_tpm_registrar/verifier v0.0.0
	github.com/salrashid123/oauth2/google v0.0.0-20201023235943-0c6294e290c3
	golang.org/x/crypto v0.0.0-20210921155107-089bfa567519 // indirect
	golang.org/x/net v0.0.0-20210226172049-e18ecbb05110
	golang.org/x/oauth2 v0.0.0-20201208152858-08078c50e5b5
	google.golang.org/api v0.39.0
	google.golang.org/grpc v1.35.0
	oid v0.0.0
)

require (
	github.com/google/go-attestation v0.3.2 // indirect
	github.com/google/go-tspi v0.2.1-0.20190423175329-115dea689aad // indirect
	golang.org/x/sys v0.0.0-20210615035016-665e8c7367d1 // indirect
	google.golang.org/protobuf v1.27.1 // indirect
)

replace (
	certparser => ./src/certparser
	github.com/salrashid123/go_tpm_registrar/verifier => ./src/verifier
	oid => ./src/certparser/oid
)
