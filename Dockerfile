FROM golang:1.17 as build

RUN apt-get update -y && apt-get install -y build-essential wget unzip curl git libtspi-dev


RUN curl -OL https://github.com/google/protobuf/releases/download/v3.19.0/protoc-3.19.0-linux-x86_64.zip && \
    unzip protoc-3.19.0-linux-x86_64.zip -d protoc3 && \
    mv protoc3/bin/* /usr/local/bin/ && \
    mv protoc3/include/* /usr/local/include/


ENV GO111MODULE=on


RUN go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
RUN go install github.com/golang/protobuf/protoc-gen-go@latest

WORKDIR /app

ADD . /app

RUN go mod download


RUN protoc --go_out=. --go_opt=paths=source_relative --go-grpc_opt=require_unimplemented_servers=false --go-grpc_out=. --go-grpc_opt=paths=source_relative src/verifier/verifier.proto

RUN export GOBIN=/app/bin && go install src/attestor.go
RUN export GOBIN=/app/bin && go install src/verifier.go


FROM gcr.io/distroless/base
COPY --from=build /app/certs/server_crt.pem /
COPY --from=build /app/certs/server_key.pem /
COPY --from=build /app/certs/CA_crt.pem /
COPY --from=build /app/certs/CA_key.pem /
COPY --from=build /app/certs/client_crt.pem /
COPY --from=build /app/certs/client_key.pem /
COPY --from=build /app/bin /


EXPOSE 50051

#ENTRYPOINT ["attestor", "--grpcport", ":50051"]
#ENTRYPOINT ["verifier", "--host",  "verify.domain.com:50051"]
