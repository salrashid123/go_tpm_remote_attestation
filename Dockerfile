FROM golang:1.19 as build

RUN apt-get update -y && apt-get install -y build-essential wget unzip curl git libtspi-dev


RUN curl -OL https://github.com/google/protobuf/releases/download/v3.19.0/protoc-3.19.0-linux-x86_64.zip && \
    unzip protoc-3.19.0-linux-x86_64.zip -d protoc3 && \
    mv protoc3/bin/* /usr/local/bin/ && \
    mv protoc3/include/* /usr/local/include/

WORKDIR /app

ADD . /app

RUN go mod download
RUN GO111MODULE=on 
RUN go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
RUN go install github.com/golang/protobuf/protoc-gen-go@latest

RUN protoc --go_out=. --go_opt=paths=source_relative --go-grpc_opt=require_unimplemented_servers=false --go-grpc_out=. --go-grpc_opt=paths=source_relative src/verifier/verifier.proto

RUN export GOBIN=/app/bin && go install src/grpc_attestor.go
RUN export GOBIN=/app/bin && go install src/grpc_verifier.go


FROM gcr.io/distroless/base
COPY --from=build /app/certs/verify_crt.pem /certs/verify_crt.pem
COPY --from=build /app/certs/verify_key.pem /certs/verify_key.pem
COPY --from=build /app/certs/attestor_crt.pem /certs/attestor_crt.pem
COPY --from=build /app/certs/attestor_key.pem /certs/attestor_key.pem
COPY --from=build /app/certs/tpm_client.crt /certs/tpm_client.crt
COPY --from=build /app/certs/tpm_client.key /certs/tpm_client.key
COPY --from=build /app/certs/platform_cert.der /certs/platform_cert.der
COPY --from=build /app/certs/CA_crt.pem /certs/CA_crt.pem
COPY --from=build /app/certs/CA_key.pem /certs/CA_key.pem
COPY --from=build /app/bin /


EXPOSE 50051

#ENTRYPOINT ["grpc_attestor", "--grpcport", ":50051"]
#ENTRYPOINT ["grpc_verifier", "--host",  "server.domain.com:50051"]
