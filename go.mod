module main

go 1.15

require (
	github.com/golang/glog v0.0.0-20210429001901-424d2337a529
	github.com/golang/protobuf v1.5.2
	github.com/google/go-tpm v0.3.3-0.20210409082102-d3310770bfec
	github.com/google/go-tpm-tools v0.3.0-alpha7.0.20210712215558-1689caf35bff
	github.com/google/go-tspi v0.3.0 // indirect
	github.com/google/uuid v1.3.0
	github.com/lestrrat/go-jwx v0.0.0-20210302221443-a9d01c1b7121
	github.com/lestrrat/go-pdebug v0.0.0-20180220043741-569c97477ae8 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	golang.org/x/net v0.0.0-20210226172049-e18ecbb05110
	golang.org/x/text v0.3.4 // indirect
	google.golang.org/genproto v0.0.0-20201214200347-8c77b98c765d // indirect
	google.golang.org/grpc v1.40.0
	verifier v0.0.0
)

replace verifier => ./src/verifier
