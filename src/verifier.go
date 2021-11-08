// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"hash"
	"log"
	mrand "math/rand"
	"strconv"
	"strings"

	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"net"
	"os"
	"sync"
	"time"

	"github.com/golang/glog"
	"github.com/google/go-attestation/attributecert"
	"github.com/salrashid123/go_tpm_registrar/verifier"

	"golang.org/x/net/context"
	"google.golang.org/grpc"

	"google.golang.org/grpc/status"

	"github.com/golang/protobuf/proto"
	//"github.com/google/go-attestation/attest"
	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/proto/attest"
	"github.com/google/go-tpm-tools/proto/tpm"
	tpmpb "github.com/google/go-tpm-tools/proto/tpm"
	gotpmserver "github.com/google/go-tpm-tools/server"
	"github.com/google/go-tpm/tpm2"
	"golang.org/x/exp/utf8string"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

var (
	grpcport             = flag.String("grpcport", "", "grpcport")
	expectedPCRMapSHA256 = flag.String("expectedPCRMapSHA256", "0:24af52a4f429b71a3184a6d64cddad17e54ea030e2aa6576bf3a5a3d8bd3328f,7:dd0276b3bf0e30531a575a1cb5a02171ea0ad0f164d51e81f4cd0ab0bd5baadd", "Sealing and Quote PCRMap (as comma separated key:value).  pcr#:sha256,pcr#sha256.  Default value uses pcr0:sha256")
	expectedPCRMapSHA1   = flag.String("expectedPCRMapSHA1", "0:0f2d3a2a1adaa479aeeca8f5df76aadc41b862ea", "EventLog values PCR value map as sha1.  Used only if readEventLog is set to true")
	caCert               = flag.String("cacert", "certs/CA_crt.pem", "CA Certificate to issue certs")
	caKey                = flag.String("cackey", "certs/CA_key.pem", "CA PrivateKey to issue certs")
	serverCert           = flag.String("servercert", "certs/server_crt.pem", "Server SSL Certificate")
	serverKey            = flag.String("serverkey", "certs/server_key.pem", "Server SSL PrivateKey")
	usemTLS              = flag.Bool("usemTLS", true, "Validate original client request with mTLS")
	platformCA           = flag.String("platformCA", "certs/platform_ca.pem", "Platform CA")
	readEventLog         = flag.Bool("readEventLog", false, "Reading Event Log")
	registry             = make(map[string]verifier.MakeCredentialRequest)
	nonces               = make(map[string]string)
	rwc                  io.ReadWriteCloser
	importMode           = flag.String("importMode", "AES", "RSA|AES")
	aes256Key            = flag.String("aes256Key", "G-KaPdSgUkXp2s5v8y/B?E(H+MbQeThW", "AES Symmetric key for client")
	letterRunes          = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	handleNames          = map[string][]tpm2.HandleType{
		"all":       []tpm2.HandleType{tpm2.HandleTypeLoadedSession, tpm2.HandleTypeSavedSession, tpm2.HandleTypeTransient},
		"loaded":    []tpm2.HandleType{tpm2.HandleTypeLoadedSession},
		"saved":     []tpm2.HandleType{tpm2.HandleTypeSavedSession},
		"transient": []tpm2.HandleType{tpm2.HandleTypeTransient},
	}

	defaultKeyParams = tpm2.Public{
		Type:    tpm2.AlgRSA,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin |
			tpm2.FlagUserWithAuth | tpm2.FlagRestricted | tpm2.FlagSign,
		AuthPolicy: []byte{},
		RSAParameters: &tpm2.RSAParams{
			Sign: &tpm2.SigScheme{
				Alg:  tpm2.AlgRSASSA,
				Hash: tpm2.AlgSHA256,
			},
			KeyBits: 2048,
		},
	}

	unrestrictedKeyParams = tpm2.Public{
		Type:    tpm2.AlgRSA,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin |
			tpm2.FlagUserWithAuth | tpm2.FlagSign,
		AuthPolicy: []byte{},
		RSAParameters: &tpm2.RSAParams{
			Sign: &tpm2.SigScheme{
				Alg:  tpm2.AlgRSASSA,
				Hash: tpm2.AlgSHA256,
			},
			KeyBits: 2048,
		},
	}
)

const (
	tpmDevice = "/dev/tpm0"
)

type server struct {
}

type hserver struct {
	mu sync.Mutex
	// statusMap stores the serving status of the services this Server monitors.
	statusMap map[string]healthpb.HealthCheckResponse_ServingStatus
}

type contextKey string

func authUnaryInterceptor(
	ctx context.Context,
	req interface{},
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (interface{}, error) {
	glog.V(2).Infof(">> authenticating inbound request")
	// do any validation on the grpcHeaders here (eg bearer token)
	return handler(ctx, req)
}

// Check() and Watch() are for gRPC healthcheck protocols.
// currently it always returns healthy status.
func (s *hserver) Check(ctx context.Context, in *healthpb.HealthCheckRequest) (*healthpb.HealthCheckResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if in.Service == "" {
		// return overall status
		return &healthpb.HealthCheckResponse{Status: healthpb.HealthCheckResponse_SERVING}, nil
	}
	glog.V(10).Infof("HealthCheck called for Service [%s]", in.Service)
	s.statusMap["verifier.VerifierServer"] = healthpb.HealthCheckResponse_SERVING
	status, ok := s.statusMap[in.Service]
	if !ok {
		return &healthpb.HealthCheckResponse{Status: healthpb.HealthCheckResponse_UNKNOWN}, grpc.Errorf(codes.NotFound, "unknown service")
	}
	return &healthpb.HealthCheckResponse{Status: status}, nil
}

func (s *hserver) Watch(in *healthpb.HealthCheckRequest, srv healthpb.Health_WatchServer) error {
	return status.Error(codes.Unimplemented, "Watch is not implemented")
}

func main() {

	flag.Parse()

	if *grpcport == "" {
		fmt.Fprintln(os.Stderr, "missing -grpcport flag (:50051)")
		flag.Usage()
		os.Exit(2)
	}

	var err error
	rwc, err = tpm2.OpenTPM(tpmDevice)
	if err != nil {
		glog.Fatalf("can't open TPM %q: %v", tpmDevice, err)
	}
	defer func() {
		if err := rwc.Close(); err != nil {
			glog.Fatalf("can't close TPM %q: %v", tpmDevice, err)
		}
	}()

	totalHandles := 0
	for _, handleType := range handleNames["transient"] {
		handles, err := client.Handles(rwc, handleType)
		if err != nil {
			glog.Fatalf("getting handles: %v", err)
		}
		for _, handle := range handles {
			if err = tpm2.FlushContext(rwc, handle); err != nil {
				glog.Fatalf("flushing handle 0x%x: %v", handle, err)
			}
			glog.V(10).Infof("Handle 0x%x flushed\n", handle)
			totalHandles++
		}
	}

	var tlsConfig *tls.Config
	ca, err := ioutil.ReadFile(*caCert)
	if err != nil {
		glog.Fatalf("Faild to read CA Certificate file %s: %v", *caCert, err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(ca)

	serverCerts, err := tls.LoadX509KeyPair(*serverCert, *serverKey)
	if err != nil {
		glog.Fatalf("Failed to read Server Certificate files %s  %s: %v", *serverCert, *serverKey, err)
	}

	if *usemTLS {
		glog.V(5).Infoln("Using mTLS for initial server connection")

		clientCaCert, err := ioutil.ReadFile(*caCert)
		if err != nil {
			glog.Fatalf("Failed to read CA Certificate file %s: %v", *caCert, err)
		}
		clientCaCertPool := x509.NewCertPool()
		clientCaCertPool.AppendCertsFromPEM(clientCaCert)

		tlsConfig = &tls.Config{
			RootCAs:      caCertPool,
			ClientCAs:    clientCaCertPool,
			ClientAuth:   tls.RequireAndVerifyClientCert,
			Certificates: []tls.Certificate{serverCerts},
		}
	} else {
		tlsConfig = &tls.Config{
			RootCAs:      caCertPool,
			Certificates: []tls.Certificate{serverCerts},
		}
	}
	ce := credentials.NewTLS(tlsConfig)

	lis, err := net.Listen("tcp", *grpcport)
	if err != nil {
		glog.Fatalf("failed to listen: %v", err)
	}

	sopts := []grpc.ServerOption{grpc.MaxConcurrentStreams(10)}
	sopts = append(sopts, grpc.Creds(ce), grpc.UnaryInterceptor(authUnaryInterceptor))
	s := grpc.NewServer(sopts...)

	verifier.RegisterVerifierServer(s, &server{})
	healthpb.RegisterHealthServer(s, &hserver{
		statusMap: make(map[string]healthpb.HealthCheckResponse_ServingStatus),
	})

	glog.V(2).Infof("Starting gRPC server on port %v", *grpcport)

	s.Serve(lis)
}

func (s *server) OfferAttestation(ctx context.Context, in *verifier.OfferAttestationRequest) (*verifier.OfferAttestationResponse, error) {
	glog.V(2).Infof("======= OfferAttestation ========")
	glog.V(5).Infof("     client provided uid: %s", in.Uid)

	nonce := make([]rune, 16)
	for i := range nonce {
		nonce[i] = letterRunes[mrand.Intn(len(letterRunes))]
	}

	glog.V(2).Infof("     Sending Nonce %s,", string(nonce))
	id := in.Uid

	glog.V(2).Infof("     Returning ProvideAttestationResponse ========")
	nonces[id] = string(nonce)

	pcrSelected, _, err := getPCRMap(tpm.HashAlgo_SHA256)
	if err != nil {
		return &verifier.OfferAttestationResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Unable to find pcrs for  Quote %v", err))
	}
	var pcrs []int32
	for k := range pcrSelected {
		pcrs = append(pcrs, int32(k))
	}
	return &verifier.OfferAttestationResponse{
		Uid:   in.Uid,
		Nonce: string(nonce),
		Pcrs:  pcrs,
	}, nil
}

func (s *server) ProvideAttestation(ctx context.Context, in *verifier.ProvideAttestationRequest) (*verifier.ProvideAttestationResponse, error) {
	glog.V(2).Infof("======= ProvideAttestation ========")
	glog.V(5).Infof("     client provided uid: %s", in.Uid)
	ver := false
	id := in.Uid
	nn, ok := registry[id]
	if !ok {
		glog.Errorf(fmt.Sprintf("[%s] Unable to find prior make/activate request for uid", in.Uid))
		return &verifier.ProvideAttestationResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Unable to find prior make/activate request for uid"))
	}
	akPub := nn.AkPub

	val, ok := nonces[id]
	if !ok {
		glog.Errorf(fmt.Sprintf("[%s] Unable to find nonce request for uid", in.Uid))
	} else {
		delete(nonces, id)

		attestationMsg := &attest.Attestation{}
		err := proto.Unmarshal(in.Attestation, attestationMsg)
		if err != nil {
			glog.Errorf("     [%s] ProvideAttestation failed:  Could no unmarshall attestation, %v", in.Uid, err)
			return &verifier.ProvideAttestationResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Could no unmarshall attestation %v", err))
		}

		glog.V(2).Infof("     Decoding PublicKey for AK ========")
		p, err := tpm2.DecodePublic(akPub)
		if err != nil {
			glog.Errorf("     [%s] ProvideAttestation failed:  DecodePublic failed, %v", in.Uid, err)
			return &verifier.ProvideAttestationResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("DecodePublic failed: %v", err))
		}
		rsaPub := rsa.PublicKey{E: int(p.RSAParameters.Exponent()), N: p.RSAParameters.Modulus()}

		ap, err := p.Key()
		if err != nil {
			glog.Errorf("     [%s] ProvideAttestation failed:  aKPub.Key() failed: %s", in.Uid, err)
			return &verifier.ProvideAttestationResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("aKPub.Key() failed: %s", err))
		}
		akBytes, err := x509.MarshalPKIXPublicKey(ap)
		if err != nil {
			glog.Errorf("     [%s] ProvideAttestation failed:  Unable to convert akPub: %v", in.Uid, err)
			return &verifier.ProvideAttestationResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Unable to convert akPub: %v", err))
		}

		akPubPEM := pem.EncodeToMemory(
			&pem.Block{
				Type:  "PUBLIC KEY",
				Bytes: akBytes,
			},
		)
		glog.V(10).Infof("     Decoded EKPub: \n%v", string(akPubPEM))

		glog.V(2).Infof("     Verifying Attestation with AK Public Key: %v", rsaPub)
		ims, err := gotpmserver.VerifyAttestation(attestationMsg, gotpmserver.VerifyOpts{
			Nonce:      []byte(val),
			TrustedAKs: []crypto.PublicKey{ap},
		})
		if err != nil {
			glog.Errorf("     [%s] ProvideAttestation failed:  failed to verify %v", in.Uid, err)
			return &verifier.ProvideAttestationResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("failed to verify: %v", err))
		}
		glog.V(2).Infoln("     Attestation verified")
		for _, q := range attestationMsg.Quotes {
			log.Printf("Quotes Hash %s\n", q.Pcrs.Hash.String())
		}
		for _, evt := range ims.RawEvents {
			if utf8string.NewString(string(evt.Data)).IsASCII() {
				glog.V(2).Infof("      Event PCRIndex %d: Digest: %s  Data: %s", evt.PcrIndex, hex.EncodeToString(evt.Digest), string(evt.Data))
			} else {
				glog.V(2).Infof("      Event PCRIndex %d: Digest: %s  Data: %s", evt.PcrIndex, hex.EncodeToString(evt.Digest), hex.EncodeToString(evt.Data))
			}
		}

		if err == nil {
			ver = true
		} else {
			glog.Errorf(fmt.Sprintf("[%s] Unable to Verify Quote %v", in.Uid, err))
			return &verifier.ProvideAttestationResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Unable to Verify Quote %v", err))
		}
	}

	return &verifier.ProvideAttestationResponse{
		Uid:      id,
		Verified: ver,
	}, nil
}

func (s *server) OfferPlatformCert(ctx context.Context, in *verifier.OfferPlatformCertRequest) (*verifier.OfferPlatformCertResponse, error) {
	glog.V(2).Infof("======= OfferPlatformCert ========")
	glog.V(5).Infof("     client provided uid: %s", in.Uid)

	rootPEM, err := ioutil.ReadFile(*platformCA)
	if err != nil {
		glog.Errorf(fmt.Sprintf("Error [%s] Reading Root platform cert %v", in.Uid, err))
		return &verifier.OfferPlatformCertResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("ERROR:  Reading Root platform cert: %v", err))
	}

	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM([]byte(rootPEM))
	if !ok {
		glog.Errorf(fmt.Sprintf("Error [%s] failed to parse certificate %v", in.Uid, err))
		return &verifier.OfferPlatformCertResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("failed to parse platform root certificate"))
	}

	block, _ := pem.Decode([]byte(rootPEM))
	if block == nil {
		glog.Errorf(fmt.Sprintf("Error [%s] failed to parse certificate PEM %v", in.Uid, err))
		return &verifier.OfferPlatformCertResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("failed to parse certificate PEM"))
	}
	platformRoot, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		glog.Errorf(fmt.Sprintf("Error [%s] failed to parse certificate %v", in.Uid, err))
		return &verifier.OfferPlatformCertResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("failed to parse certificate: "+err.Error()))
	}

	attributecert, err := attributecert.ParseAttributeCertificate(in.PlatformCert)
	if err != nil {
		glog.Errorf(fmt.Sprintf("Error [%s] failed to parse  attribute certificate  %v", in.Uid, err))
		return &verifier.OfferPlatformCertResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("failed to parse Platform Certificate%s: %v", err))
	}

	err = attributecert.CheckSignatureFrom(platformRoot)
	if err != nil {
		glog.Errorf(fmt.Sprintf("Error [%s] failed to verify  attribute certificate  %v", in.Uid, err))
		return &verifier.OfferPlatformCertResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("failed to verify Platform Certificate%s: %v", err))

	}
	glog.V(5).Infof(" Verified Platform cert signed by privacyCA")

	// todo, save the serial number here...we need to compare the serail number seen here againt the EKCert (which we don't have at the point; i know
	// i can just change the protomessage to send it unilaterally...btw, the EKCert is sent in the makeCredential call just...so maybe save the serialnumber from
	// here
	glog.V(5).Infof(" Platform Cert's Holder SerialNumber %s\n", fmt.Sprintf("%x", attributecert.Holder.Serial))

	glog.V(5).Infof("     Platform Certificate Verification succeeded")

	return &verifier.OfferPlatformCertResponse{
		Uid: in.Uid,
		Ok:  true,
	}, nil
}

func (s *server) MakeCredential(ctx context.Context, in *verifier.MakeCredentialRequest) (*verifier.MakeCredentialResponse, error) {

	glog.V(2).Infof("======= MakeCredential ========")
	glog.V(5).Infof("     client provided uid: %s", in.Uid)
	glog.V(10).Infof("     Got AKName %s", in.AkName)
	glog.V(10).Infof("     Registry size %d\n", len(registry))

	if in.EkCert != nil {
		glog.V(10).Infof("     Decoding ekCert from client")
		encCert, err := x509.ParseCertificate(in.EkCert)
		if err != nil {
			glog.Errorf(fmt.Sprintf("Error [%s] Loading EKCert %v", in.Uid, err))
			return &verifier.MakeCredentialResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Error EKCert %v", err))
		}
		// https://pkg.go.dev/github.com/google/certificate-transparency-go/x509
		// you should verify the EKCert here and the serialNumber (which we just got in the OfferPlatformCert() call)
		glog.V(10).Infof("     EKCert Encryption Issuer x509 \n%v", encCert.Issuer)
		glog.V(10).Infof("     EKCert Encryption SerialNumber \n%s", fmt.Sprint(encCert.SerialNumber))

		certPEM := pem.EncodeToMemory(
			&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: in.EkCert,
			},
		)
		glog.V(10).Infof("     Encryption EKCert \n%s", string(certPEM))

		ekBytes, err := x509.MarshalPKIXPublicKey(encCert.PublicKey)
		if err != nil {
			glog.Errorf(fmt.Sprintf("ERROR:  [%s], could not get MarshalPKIXPublicKey: %v", in.Uid, err))
			return &verifier.MakeCredentialResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("ERROR:  could not get MarshalPKIXPublicKey: %v", err))
		}
		ekPubPEM := pem.EncodeToMemory(
			&pem.Block{
				Type:  "PUBLIC KEY",
				Bytes: ekBytes,
			},
		)
		glog.V(10).Infof("     EKPub from EKCert \n%s", string(ekPubPEM))
	}

	glog.V(10).Infof("     Decoding ekPub from client")
	ekPub, err := tpm2.DecodePublic(in.EkPub)
	if err != nil {
		glog.Errorf(fmt.Sprintf("[%s] Error DecodePublic EK %v", in.Uid, err))
		return &verifier.MakeCredentialResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Error DecodePublic EK %v", err))
	}

	ekPubKey, err := ekPub.Key()
	if err != nil {
		glog.Errorf(fmt.Sprintf("[%s] Error extracting ekPubKey: %s", in.Uid, err))
		return &verifier.MakeCredentialResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Error extracting ekPubKey: %s", err))
	}
	ekBytes, err := x509.MarshalPKIXPublicKey(ekPubKey)
	if err != nil {
		glog.Errorf(fmt.Sprintf("[%s] Unable to convert ekPub: %v", in.Uid, err))
		return &verifier.MakeCredentialResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Unable to convert ekPub: %v", err))
	}

	ekPubPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: ekBytes,
		},
	)
	glog.V(10).Infof("     EKPubPEM: \n%v", string(ekPubPEM))

	glog.V(2).Infof("     Verified EkPub here...somehow")

	registry[in.Uid] = *in

	nonce := make([]rune, 16)
	for i := range nonce {
		nonce[i] = letterRunes[mrand.Intn(len(letterRunes))]
	}

	glog.V(2).Infof("     Sending Nonce %s,", string(nonce))
	nonces[in.Uid] = string(nonce)

	credBlob, encryptedSecret, err := makeCredential(string(nonce), in.EkCert, in.EkPub, in.AkPub)
	if err != nil {
		glog.Errorf(fmt.Sprintf("[%s] Unable to makeCredential", in.Uid))
		return &verifier.MakeCredentialResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Unable to makeCredential"))
	}
	glog.V(2).Infof("     Returning MakeCredentialResponse ========")
	return &verifier.MakeCredentialResponse{
		Uid:             in.Uid,
		CredBlob:        credBlob,
		EncryptedSecret: encryptedSecret,
	}, nil
}

func (s *server) ActivateCredential(ctx context.Context, in *verifier.ActivateCredentialRequest) (*verifier.ActivateCredentialResponse, error) {

	glog.V(2).Infof("======= ActivateCredential ========")
	glog.V(5).Infof("     client provided uid: %s", in.Uid)
	glog.V(10).Infof("     Secret %s", in.Secret)

	if nonces[in.Uid] != in.Secret {
		glog.Errorf("     [%s] ActivateCredential failed:  provided Secret does not match expected Nonce", in.Uid)
		return &verifier.ActivateCredentialResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("ActivateCredential failed:  provided Secret does not match expected Nonce"))
	}

	glog.V(2).Infof("     Returning ActivateCredentialResponse ========")

	return &verifier.ActivateCredentialResponse{
		Uid:      in.Uid,
		Verified: true,
	}, nil
}

func (s *server) GetSecret(ctx context.Context, in *verifier.GetSecretRequest) (*verifier.GetSecretResponse, error) {

	glog.V(2).Infof("======= GetSecret ========")
	glog.V(5).Infof("     client provided uid: %s", in.Uid)

	id := in.Uid

	var key []byte
	var err error

	secretType := verifier.SecretType_AES
	if *importMode == "RSA" {
		_, key, err = generateCertificate(id)
		if err != nil {
			glog.Errorf(fmt.Sprintf("[%s]   Unable to gernate certificate %v", in.Uid, err))
			return &verifier.GetSecretResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Unable to gernate certificate %v", err))
		}
		secretType = verifier.SecretType_RSA
	}

	importBLob, err := createImportBlob(id, key)
	if err != nil {
		glog.Errorf(fmt.Sprintf("[%s]  Unable to gernate certificate %v", in.Uid, err))
		return &verifier.GetSecretResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Unable to create Import Blob %v", err))
	}

	glog.V(2).Infof("     Returning GetSecretResponse ========")

	return &verifier.GetSecretResponse{
		Uid:        in.Uid,
		ImportBlob: importBLob,
		SecretType: &secretType,
	}, nil
}

func (s *server) OfferQuote(ctx context.Context, in *verifier.OfferQuoteRequest) (*verifier.OfferQuoteResponse, error) {
	glog.V(2).Infof("======= OfferQuote ========")
	glog.V(5).Infof("     client provided uid: %s", in.Uid)

	nonce := make([]rune, 16)
	for i := range nonce {
		nonce[i] = letterRunes[mrand.Intn(len(letterRunes))]
	}

	glog.V(2).Infof("     Sending Nonce %s,", string(nonce))
	id := in.Uid

	glog.V(2).Infof("     Returning OfferQuoteResponse ========")
	nonces[id] = string(nonce)

	pcrSelected, _, err := getPCRMap(tpm.HashAlgo_SHA256)
	if err != nil {
		return &verifier.OfferQuoteResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Unable to find pcrs for  Quote %v", err))
	}
	var pcrs []int32
	for k := range pcrSelected {
		pcrs = append(pcrs, int32(k))
	}

	return &verifier.OfferQuoteResponse{
		Uid:   in.Uid,
		Pcrs:  pcrs,
		Nonce: string(nonce),
	}, nil
}

func (s *server) ProvideQuote(ctx context.Context, in *verifier.ProvideQuoteRequest) (*verifier.ProvideQuoteResponse, error) {
	glog.V(2).Infof("======= ProvideQuote ========")
	glog.V(5).Infof("     client provided uid: %s", in.Uid)

	ver := false
	id := in.Uid

	val, ok := nonces[id]
	if !ok {
		glog.Errorf(fmt.Sprintf("[%s] Unable to find nonce request for uid", in.Uid))
	} else {
		delete(nonces, id)
		err := verifyQuote(id, val, in.Attestation, in.Signature, in.Eventlog)
		if err == nil {
			ver = true
		} else {
			glog.Errorf(fmt.Sprintf("[%s] Unable to Verify Quote %v", in.Uid, err))
			return &verifier.ProvideQuoteResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Unable to Verify Quote %v", err))
		}
	}

	glog.V(2).Infof("     Returning ProvideQuoteResponse ========")
	return &verifier.ProvideQuoteResponse{
		Uid:      in.Uid,
		Verified: ver,
	}, nil
}

func verifyQuote(uid string, nonce string, attestation []byte, sigBytes []byte, eventLog []byte) (retErr error) {
	glog.V(2).Infof("     --> Starting verifyQuote()")

	nn, ok := registry[uid]
	if !ok {
		return fmt.Errorf("Unable to find prior make/activate request for uid")
	}
	akPub := nn.AkPub

	glog.V(10).Infof("     Read and Decode (attestion)")
	att, err := tpm2.DecodeAttestationData(attestation)
	if err != nil {
		return fmt.Errorf("DecodeAttestationData(%v) failed: %v", attestation, err)
	}

	glog.V(5).Infof("     Attestation ExtraData (nonce): %s ", string(att.ExtraData))
	glog.V(5).Infof("     Attestation PCR#: %v ", att.AttestedQuoteInfo.PCRSelection.PCRs)
	glog.V(5).Infof("     Attestation Hash: %v ", hex.EncodeToString(att.AttestedQuoteInfo.PCRDigest))

	if nonce != string(att.ExtraData) {
		return fmt.Errorf("Nonce Value mismatch Got: (%s) Expected: (%v)", string(att.ExtraData), nonce)
	}

	sigL := tpm2.SignatureRSA{
		HashAlg:   tpm2.AlgSHA256,
		Signature: sigBytes,
	}

	_, hash, err := getPCRMap(tpm.HashAlgo_SHA256)
	if err != nil {
		return fmt.Errorf("Error getting PCRMap: %v", err)
	}
	glog.V(5).Infof("     sha256 of Expected PCR Value: --> %x", hash)

	glog.V(2).Infof("     Decoding PublicKey for AK ========")
	p, err := tpm2.DecodePublic(akPub)
	if err != nil {
		return fmt.Errorf("DecodePublic failed: %v", err)
	}
	rsaPub := rsa.PublicKey{E: int(p.RSAParameters.Exponent()), N: p.RSAParameters.Modulus()}
	hsh := crypto.SHA256.New()
	hsh.Write(attestation)
	if err := rsa.VerifyPKCS1v15(&rsaPub, crypto.SHA256, hsh.Sum(nil), sigL.Signature); err != nil {
		return fmt.Errorf("VerifyPKCS1v15 failed: %v", err)
	}

	if fmt.Sprintf("%x", hash) != hex.EncodeToString(att.AttestedQuoteInfo.PCRDigest) {
		return fmt.Errorf("Unexpected PCR hash Value expected: %s  Got %s", fmt.Sprintf("%x", hash), hex.EncodeToString(att.AttestedQuoteInfo.PCRDigest))
	}

	if nonce != string(att.ExtraData) {
		return fmt.Errorf("Unexpected secret Value expected: %v  Got %v", nonce, string(att.ExtraData))
	}
	glog.V(2).Infof("     Attestation Signature Verified ")

	if *readEventLog {
		glog.V(2).Infof("     Reading EventLog")

		evtLogPcrMap, _, err := getPCRMap(tpm.HashAlgo_SHA1)
		if err != nil {
			return fmt.Errorf(fmt.Sprintf("[%s] Error getting PCRMap %v", uid, err))
		}
		pcrs := &tpmpb.PCRs{Hash: tpmpb.HashAlgo_SHA256, Pcrs: evtLogPcrMap}

		ms, err := gotpmserver.ParseMachineState(eventLog, pcrs)
		if err != nil {
			return fmt.Errorf("[%s] Failed to parse EventLog: %v", uid, err)
		}

		for _, event := range ms.RawEvents {
			glog.V(2).Infof("     Event Type %v\n", event.UntrustedType)
			glog.V(2).Infof("     PCR Index %d\n", event.PcrIndex)

			if utf8string.NewString(string(event.Data)).IsASCII() {
				glog.V(2).Infof("     Event Data %s\n", string(event.Data))
			} else {
				glog.V(2).Infof("     Event Data %s\n", hex.EncodeToString(event.Data))
			}
		}
		glog.V(2).Infof("     EventLog Verified ")

		// TODO: verify Secureboot

	}
	glog.V(2).Infof("     <-- End verifyQuote()")
	return nil
}

func makeCredential(sec string, ekCertBytes []byte, ekPubBytes []byte, akPubBytes []byte) (credBlob []byte, encryptedSecret []byte, retErr error) {

	glog.V(2).Infof("     --> Starting makeCredential()")
	glog.V(10).Infof("     Read (ekPub) from request")

	ekPub, err := tpm2.DecodePublic(ekPubBytes)
	if err != nil {
		return []byte(""), []byte(""), fmt.Errorf("Error DecodePublic AK %v", err)
	}

	ekh, keyName, err := tpm2.LoadExternal(rwc, ekPub, tpm2.Private{}, tpm2.HandleNull)
	if err != nil {
		return []byte(""), []byte(""), fmt.Errorf("Error loadingExternal EK %v", err)
	}
	defer tpm2.FlushContext(rwc, ekh)

	glog.V(10).Infof("     Read (eK) from request")

	if ekPub.MatchesTemplate(client.DefaultEKTemplateRSA()) {
		glog.V(10).Infof("     EK Default parameter match template")
	} else {
		return []byte(""), []byte(""), fmt.Errorf("EK does not have correct defaultParameters")
	}

	tPub, err := tpm2.DecodePublic(akPubBytes)
	if err != nil {
		return []byte(""), []byte(""), fmt.Errorf("Error DecodePublic AK %v", tPub)
	}

	ap, err := tPub.Key()
	if err != nil {
		return []byte(""), []byte(""), fmt.Errorf("aKPub.Key() failed: %s", err)
	}
	akBytes, err := x509.MarshalPKIXPublicKey(ap)
	if err != nil {
		return []byte(""), []byte(""), fmt.Errorf("Unable to convert akPub: %v", err)
	}

	akPubPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: akBytes,
		},
	)
	glog.V(10).Infof("     Decoded AKPub: \n%v", string(akPubPEM))

	if tPub.MatchesTemplate(client.AKTemplateRSA()) {
		glog.V(10).Infof("     AK Default parameter match template")
	} else {
		return []byte(""), []byte(""), fmt.Errorf("AK does not have correct defaultParameters")
	}
	h, keyName, err := tpm2.LoadExternal(rwc, tPub, tpm2.Private{}, tpm2.HandleNull)
	if err != nil {
		return []byte(""), []byte(""), fmt.Errorf("Error loadingExternal AK %v", err)
	}
	defer tpm2.FlushContext(rwc, h)
	glog.V(10).Infof("     Loaded EK KeyName %s", hex.EncodeToString(keyName))

	glog.V(5).Infof("     MakeCredential Start")
	credential := []byte(sec)
	credBlob, encryptedSecret0, err := tpm2.MakeCredential(rwc, ekh, credential, keyName)
	if err != nil {
		return []byte(""), []byte(""), fmt.Errorf("MakeCredential failed: %v", err)
	}
	glog.V(10).Infof("     credBlob %s", hex.EncodeToString(credBlob))
	glog.V(10).Infof("     encryptedSecret0 %s", hex.EncodeToString(encryptedSecret0))
	glog.V(2).Infof("     <-- End makeCredential()")
	return credBlob, encryptedSecret0, nil
}

func generateCertificate(cn string) (cert []byte, key []byte, retErr error) {
	glog.V(2).Infof("     --> Start generateCertificate()")
	glog.V(5).Infof("     Generating Certificate for cn=%s", cn)

	certPEMBytes, err := ioutil.ReadFile(*caCert)
	if err != nil {
		return []byte(""), []byte(""), fmt.Errorf("Unable to read %s %v", *caCert, err)
	}
	block, _ := pem.Decode(certPEMBytes)
	if block == nil {
		return []byte(""), []byte(""), fmt.Errorf("Unable to decode %s %v", *caCert, err)
	}
	ca, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return []byte(""), []byte(""), fmt.Errorf("Unable to parse %s %v", *caCert, err)
	}

	keyPEMBytes, err := ioutil.ReadFile(*caKey)
	if err != nil {
		return []byte(""), []byte(""), fmt.Errorf("Unable to read %s  %v", *caKey, err)
	}
	privPem, _ := pem.Decode(keyPEMBytes)
	parsedKey, err := x509.ParsePKCS1PrivateKey(privPem.Bytes)
	if err != nil {
		return []byte(""), []byte(""), fmt.Errorf("Unable to parse %s %v", *caKey, err)
	}

	var notBefore time.Time
	notBefore = time.Now()

	notAfter := notBefore.Add(time.Hour * 24 * 365)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return []byte(""), []byte(""), fmt.Errorf("Failed to generate serial number: %v", err)
	}
	glog.V(10).Infof("     Generated cert with Serial %s", serialNumber)

	cc := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization:       []string{"Acme Co"},
			OrganizationalUnit: []string{"Enterprise"},
			Locality:           []string{"Mountain View"},
			Province:           []string{"California"},
			Country:            []string{"US"},
			CommonName:         cn,
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		DNSNames:              []string{cn},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	pub := &priv.PublicKey

	cert_b, err := x509.CreateCertificate(rand.Reader, cc, ca, pub, parsedKey)
	if err != nil {
		return []byte(""), []byte(""), fmt.Errorf("Failed to createCertificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert_b,
		},
	)
	privPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(priv),
		},
	)

	glog.V(10).Infof("     Generating Test Signature with private Key")
	dataToSign := []byte("secret")
	digest := sha256.Sum256(dataToSign)
	signature, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, digest[:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error from signing: %s\n", err)
		return
	}

	glog.V(10).Infof("     Test signature data:  %s", base64.RawStdEncoding.EncodeToString(signature))
	glog.V(2).Infof("     <-- End generateCertificate()")
	return certPEM, privPEM, nil
}

func (s *server) OfferCSR(ctx context.Context, in *verifier.OfferCSRRequest) (*verifier.OfferCSRResponse, error) {
	glog.V(2).Infof("======= OfferCSR ========")
	glog.V(10).Infof("     client provided uid: %s", in.Uid)
	glog.V(10).Infof("     client provided csr: \n%s", string(in.Csr))

	glog.V(20).Infof("     SigningKey Attestation %s\n", base64.StdEncoding.EncodeToString(in.Attestation))
	glog.V(20).Infof("     SigningKey Attestation Signature %s\n", base64.StdEncoding.EncodeToString(in.AttestationSignature))

	glog.V(20).Infof("     Read and Decode (attestion)")
	att, err := tpm2.DecodeAttestationData(in.Attestation)
	if err != nil {
		glog.Errorf(fmt.Sprintf("[%s] Error DecodePublic AK %v", in.Uid, err))
		return &verifier.OfferCSRResponse{}, fmt.Errorf("DecodeAttestationData failed: %v", err)
	}
	glog.V(20).Infof("     Attestation AttestedCertifyInfo.Name.Digest.Value: %s", hex.EncodeToString(att.AttestedCertifyInfo.Name.Digest.Value))

	// Verify signature of Attestation by using the PEM Public key for AK
	nn, ok := registry[in.Uid]
	if !ok {
		glog.Errorf(fmt.Sprintf("[%s] Unable to find prior make/activate request for uid: %v", in.Uid, err))
		return &verifier.OfferCSRResponse{}, fmt.Errorf("Unable to find prior make/activate request for uid: %v", err)
	}
	akPub := nn.AkPub
	p, err := tpm2.DecodePublic(akPub)
	if err != nil {
		glog.Errorf(fmt.Sprintf("[%s] DecodePublic failed %v", in.Uid, err))
		return &verifier.OfferCSRResponse{}, fmt.Errorf("DecodePublic failed: %v", err)
	}
	rsaPub := rsa.PublicKey{E: int(p.RSAParameters.Exponent()), N: p.RSAParameters.Modulus()}
	ahsh := crypto.SHA256.New()
	ahsh.Write(in.Attestation)

	if err := rsa.VerifyPKCS1v15(&rsaPub, crypto.SHA256, ahsh.Sum(nil), in.AttestationSignature); err != nil {
		glog.Errorf(fmt.Sprintf("[%s] VerifyPKCS1v15 failed: %v", in.Uid, err))
		return &verifier.OfferCSRResponse{}, fmt.Errorf("VerifyPKCS1v15 failed: %v", err)
	}
	glog.V(10).Infof("     Attestation of Unrestricted Signing Key Verified")

	// now verify that the public key provided is the same as in the CSR and that the "Template" is what we expect
	tPub, err := tpm2.DecodePublic(in.PublicKey)
	if err != nil {
		glog.Errorf(fmt.Sprintf("[%s] Error Decode Unrestricted key Public: %v", in.Uid, err))
		return &verifier.OfferCSRResponse{}, fmt.Errorf("Error Decode Unrestricted key Public %v", tPub)
	}

	up, err := tPub.Key()
	if err != nil {
		glog.Errorf(fmt.Sprintf("[%s] ukPub.Key() failed: %v", in.Uid, err))
		return &verifier.OfferCSRResponse{}, fmt.Errorf("ukPub.Key() failed: %s", err)
	}
	ukBytes, err := x509.MarshalPKIXPublicKey(up)
	if err != nil {
		glog.Errorf(fmt.Sprintf("[%s] Unable to convert ukPub: %v", in.Uid, err))
		return &verifier.OfferCSRResponse{}, fmt.Errorf("Unable to convert ukPub: %v", err)
	}

	ukPubPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: ukBytes,
		},
	)
	glog.V(10).Infof("     Decoded UkPub: \n%v", string(ukPubPEM))

	if tPub.MatchesTemplate(unrestrictedKeyParams) {
		glog.V(10).Infof("     Unrestricted key parameter matchs template")
	} else {
		glog.Errorf(fmt.Sprintf("[%s] uK does not have correct template parameters: %v", in.Uid, err))
		return &verifier.OfferCSRResponse{}, fmt.Errorf("uK does not have correct template parameters")
	}

	// now extract the public key from the CSR
	b, _ := pem.Decode(in.Csr)
	var csrobj *x509.CertificateRequest
	csrobj, err = x509.ParseCertificateRequest(b.Bytes)
	if err != nil {
		glog.Errorf(fmt.Sprintf("[%s] Unable to parse CSR: %v", in.Uid, err))
		return &verifier.OfferCSRResponse{}, fmt.Errorf("Unable to parse CSR %v", err)
	}

	rkey, ok := csrobj.PublicKey.(*rsa.PublicKey)
	if !ok {
		glog.Errorf(fmt.Sprintf("[%s] Unable to extract public key from CSR: %v", in.Uid, err))
		return &verifier.OfferCSRResponse{}, fmt.Errorf("Unable to extract public key from CSR %v", err)
	}

	glog.V(10).Infof("     Verifying if Public key from CSR matches attested Public key")
	fkey, ok := up.(*rsa.PublicKey)
	if !ok {
		glog.Errorf(fmt.Sprintf("[%s] Unable to extract public key from CSR: %v", in.Uid, err))
		return &verifier.OfferCSRResponse{}, fmt.Errorf("Unable to extract public key from CSR %v", err)
	}

	if !rkey.Equal(fkey) {
		glog.Errorf(fmt.Sprintf("[%s] Public Key provided does not match key in CSR: %v", in.Uid, err))
		return &verifier.OfferCSRResponse{}, fmt.Errorf("Public Key provided does not match key in CSR")
	}
	// this is the critical step, confirm the that the attestationblob that we just verified contains the public key in the template
	// we expect

	// the tpm2.Public is the same unrestrictedKeyParams
	params := tpm2.Public{
		Type:    tpm2.AlgRSA,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin |
			tpm2.FlagUserWithAuth | tpm2.FlagSign,
		AuthPolicy: []byte{},
		RSAParameters: &tpm2.RSAParams{
			Sign: &tpm2.SigScheme{
				Alg:  tpm2.AlgRSASSA,
				Hash: tpm2.AlgSHA256,
			},
			KeyBits:    2048,
			ModulusRaw: fkey.N.Bytes(), // note, we're adding in the public key here to the template
		},
	}
	ok, err = att.AttestedCertifyInfo.Name.MatchesPublic(params)
	if err != nil {
		glog.Errorf(fmt.Sprintf("[%s]   AttestedCertifyInfo.MatchesPublic(%v) failed: %v", in.Uid, err))
		return &verifier.OfferCSRResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("     AttestedCertifyInfo.MatchesPublic(%v) failed: %v", att, err))
	}
	glog.V(10).Infof("     Unrestricted RSA Public key parameters matches AttestedCertifyInfo  %v", ok)

	crt, err := signCSR(in.Csr)
	if err != nil {
		glog.Errorf(fmt.Sprintf("[%s]   Unable to Generate CSR: %v", in.Uid, err))
		return &verifier.OfferCSRResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Unable to Generate CSR %v", err))
	}
	glog.V(2).Infof("     Returning OfferCSRResponse ========")
	return &verifier.OfferCSRResponse{
		Uid:  in.Uid,
		Cert: crt,
	}, nil
}

func signCSR(csrBytes []byte) (certBytes []byte, err error) {
	glog.V(2).Infof("     --> Start signCSR() ")

	certPEMBytes, err := ioutil.ReadFile(*caCert)
	if err != nil {
		return []byte(""), fmt.Errorf("Unable to read %s %v", *caCert, err)
	}
	block, _ := pem.Decode(certPEMBytes)
	if block == nil {
		return []byte(""), fmt.Errorf("Unable to decode %s %v", *caCert, err)
	}
	ca, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return []byte(""), fmt.Errorf("Unable to parse %s %v", *caCert, err)
	}

	keyPEMBytes, err := ioutil.ReadFile(*caKey)
	if err != nil {
		return []byte(""), fmt.Errorf("Unable to read %s  %v", *caKey, err)
	}
	privPem, _ := pem.Decode(keyPEMBytes)
	parsedKey, err := x509.ParsePKCS1PrivateKey(privPem.Bytes)
	if err != nil {
		return []byte(""), fmt.Errorf("Unable to parse %s %v", *caKey, err)
	}

	b, _ := pem.Decode(csrBytes)
	var csrobj *x509.CertificateRequest
	csrobj, err = x509.ParseCertificateRequest(b.Bytes)
	if err != nil {
		return []byte(""), fmt.Errorf("Unable to parse CSR %v", err)
	}
	// csrobj, err := x509.ParseCertificateRequest(pemdata)
	// if err != nil {
	// 	return []byte(""), fmt.Errorf("Unable to parse CSR %v", err)
	// }
	var notBefore time.Time
	notBefore = time.Now()

	notAfter := notBefore.Add(time.Hour * 24 * 365)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return []byte(""), fmt.Errorf("Failed to generate serial number: %v", err)
	}
	glog.V(10).Infof("     Generated cert with Serial %s", serialNumber)
	cc := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization:       []string{"Acme Co"},
			OrganizationalUnit: []string{"Enterprise"},
			Locality:           []string{"Mountain View"},
			Province:           []string{"California"},
			Country:            []string{"US"},
			CommonName:         csrobj.Subject.CommonName,
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		DNSNames:              csrobj.DNSNames,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	pub := &parsedKey.PublicKey

	cert_b, err := x509.CreateCertificate(rand.Reader, cc, ca, pub, parsedKey)
	if err != nil {
		return []byte(""), fmt.Errorf("Failed to createCertificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert_b,
		},
	)

	glog.V(10).Infof("     Returning Certificate:  \n%s", string(certPEM))

	return certPEM, nil
}

func createImportBlob(uid string, saKey []byte) (blob []byte, retErr error) {
	glog.V(2).Infof("     --> Start createImportBlob()")
	glog.V(10).Infof("     Load and decode ekPub from registry")
	nn, ok := registry[uid]
	if !ok {
		return []byte(""), fmt.Errorf("Unable to find prior make/activate request for uid")
	}
	tPub, err := tpm2.DecodePublic(nn.EkPub)
	if err != nil {
		return []byte(""), fmt.Errorf("Error DecodePublic K %v", tPub)
	}

	ap, err := tPub.Key()
	if err != nil {
		return []byte(""), fmt.Errorf("akPub.Key() failed: %s", err)
	}

	glog.V(5).Infof("     Decoding sealing PCR value in hex")

	pcrMap, _, err := getPCRMap(tpm.HashAlgo_SHA256)
	if err != nil {
		return []byte(""), fmt.Errorf("  Could not get PCRMap: %s", err)
	}
	var pcrs *tpmpb.PCRs

	pcrs = &tpmpb.PCRs{Hash: tpmpb.HashAlgo_SHA256, Pcrs: pcrMap}

	var sealedOutput []byte
	if *importMode == "RSA" {
		glog.V(2).Infof("     --> createSigningKeyImportBlob()")
		glog.V(5).Infof("     Generating to RSA sealedFile")

		privBlock, _ := pem.Decode(saKey)

		signingKey, err := x509.ParsePKCS1PrivateKey(privBlock.Bytes)
		if err != nil {
			return []byte(""), fmt.Errorf("Unable to read read rsa PrivateKey: %v", err)
		}

		importBlob, err := gotpmserver.CreateSigningKeyImportBlob(ap, signingKey, pcrs)
		if err != nil {
			return []byte(""), fmt.Errorf("Unable to CreateSigningKeyImportBlob: %v", err)
		}

		glog.V(5).Infof("     Returning sealed key")

		sealedOutput, err = proto.Marshal(importBlob)
		if err != nil {
			return []byte(""), fmt.Errorf("marshaling error: ", err)
		}

	} else if *importMode == "AES" {
		glog.V(2).Infof("     --> createImportBlob()")
		glog.V(5).Infof("     Generating to AES sealedFile")
		importBlob, err := gotpmserver.CreateImportBlob(ap, []byte(*aes256Key), pcrs)
		if err != nil {
			return []byte(""), fmt.Errorf("Unable to CreateImportBlob : %v", err)
		}
		sealedOutput, err = proto.Marshal(importBlob)
		if err != nil {
			return []byte(""), fmt.Errorf("Unable to marshall ImportBlob: ", err)
		}
	} else {
		return []byte(""), fmt.Errorf("Import mode must be RSA or AES")
	}

	glog.V(2).Infof("     <-- End createImportBlob()")

	return sealedOutput, nil
}

func getPCRMap(algo tpm.HashAlgo) (map[uint32][]byte, []byte, error) {

	pcrMap := make(map[uint32][]byte)
	var hsh hash.Hash
	// https://github.com/tpm2-software/tpm2-tools/blob/83f6f8ac5de5a989d447d8791525eb6b6472e6ac/lib/tpm2_openssl.c#L206
	if algo == tpm.HashAlgo_SHA1 {
		hsh = sha1.New()
	}
	if algo == tpm.HashAlgo_SHA256 {
		hsh = sha256.New()
	}
	if algo == tpm.HashAlgo_SHA1 || algo == tpm.HashAlgo_SHA256 {
		for _, v := range strings.Split(*expectedPCRMapSHA256, ",") {
			entry := strings.Split(v, ":")
			if len(entry) == 2 {
				uv, err := strconv.ParseUint(entry[0], 10, 32)
				if err != nil {
					return nil, nil, fmt.Errorf(" PCR key:value is invalid in parsing %s", v)
				}
				hexEncodedPCR, err := hex.DecodeString(entry[1])
				if err != nil {
					return nil, nil, fmt.Errorf(" PCR key:value is invalid in encoding %s", v)
				}
				pcrMap[uint32(uv)] = hexEncodedPCR
				hsh.Write(hexEncodedPCR)
			} else {
				return nil, nil, fmt.Errorf(" PCR key:value is invalid %s", v)
			}
		}
	} else {
		return nil, nil, fmt.Errorf("Unknown Hash Algorithm for TPM PCRs %v", algo)
	}
	if len(pcrMap) == 0 {
		return nil, nil, fmt.Errorf(" PCRMap is null")
	}
	return pcrMap, hsh.Sum(nil), nil
}
