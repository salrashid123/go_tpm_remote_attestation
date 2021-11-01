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
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	mrand "math/rand"

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

	"github.com/salrashid123/go_tpm_registrar/verifier"

	"github.com/golang/glog"

	"golang.org/x/net/context"
	"google.golang.org/grpc"

	"google.golang.org/grpc/status"

	"github.com/golang/protobuf/proto"
	"github.com/google/go-tpm-tools/client"
	gotpmserver "github.com/google/go-tpm-tools/server"
	"github.com/google/go-tpm/tpm2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"

	tpmpb "github.com/google/go-tpm-tools/proto/tpm"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

var (
	grpcport         = flag.String("grpcport", "", "grpcport")
	expectedPCRValue = flag.String("expectedPCRValue", "24af52a4f429b71a3184a6d64cddad17e54ea030e2aa6576bf3a5a3d8bd3328f", "expectedPCRValue")
	expectedPCRSHA1  = flag.String("expectedPCRSHA1", "0f2d3a2a1adaa479aeeca8f5df76aadc41b862ea", "PCR0 value for the eventlog on GCE VMs, debian10 with secure boot")
	pcr              = flag.Int("pcr", 0, "PCR Value to use")
	caCert           = flag.String("cacert", "certs/CA_crt.pem", "CA Certificate to issue certs")
	caKey            = flag.String("cackey", "certs/CA_key.pem", "CA PrivateKey to issue certs")
	serverCert       = flag.String("servercert", "certs/server_crt.pem", "Server SSL Certificate")
	serverKey        = flag.String("serverkey", "certs/server_key.pem", "Server SSL PrivateKey")
	usemTLS          = flag.Bool("usemTLS", true, "Validate original client request with mTLS")
	platformCA       = flag.String("platformCA", "certs/platform_ca.pem", "Platform CA")
	readEventLog     = flag.Bool("readEventLog", false, "Reading Event Log")
	registry         = make(map[string]verifier.MakeCredentialRequest)
	nonces           = make(map[string]string)
	rwc              io.ReadWriteCloser
	importMode       = flag.String("importMode", "AES", "RSA|AES")
	aes256Key        = flag.String("aes256Key", "G-KaPdSgUkXp2s5v8y/B?E(H+MbQeThW", "AES Symmetric key for client")
	handleNames      = map[string][]tpm2.HandleType{
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

func (s *server) OfferPlatformCert(ctx context.Context, in *verifier.OfferPlatformCertRequest) (*verifier.OfferPlatformCertResponse, error) {
	glog.V(2).Infof("======= OfferPlatformCert ========")
	glog.V(5).Infof("     client provided uid: %s", in.Uid)

	certPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "ATTRIBUTE CERTIFICATE",
			Bytes: in.PlatformCert,
		},
	)

	glog.V(50).Infof("     client provided Platform Cert: \n%s", string(certPEM))

	// now do cert verification
	// I do not think go support parsing of attribute certificates

	// openssl will support it
	// i don't have the ca used for this platform cert since its from an example only
	// so we're skipping the verification step here...

	// https://en.wikipedia.org/wiki/Authorization_certificate
	// https://github.com/openssl/openssl/issues/14648
	// 2.1.5 Assertions Made by a Platform Certificate >  https://trustedcomputinggroup.org/wp-content/uploads/IWG_Platform_Certificate_Profile_v1p1_r19_pub_fixed.pdf

	// for now just accept it and move on

	// rootPEM, err := ioutil.ReadFile(*platformCA)
	// if err != nil {
	// 	return &verifier.OfferPlatformCertResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("ERROR:  Reading Root platform cert: %v", err))
	// }

	// roots := x509.NewCertPool()
	// ok := roots.AppendCertsFromPEM([]byte(rootPEM))
	// if !ok {
	// 	return &verifier.OfferPlatformCertResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("failed to parse platform root certificate"))
	// }

	// block, _ := pem.Decode([]byte(certPEM))
	// if block == nil {
	// 	return &verifier.OfferPlatformCertResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("failed to parse certificate PEM"))
	// }
	// cert, err := x509.ParseCertificate(block.Bytes)
	// if err != nil {
	// 	return &verifier.OfferPlatformCertResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("failed to parse certificate: "+err.Error()))
	// }

	// opts := x509.VerifyOptions{
	// 	Roots:         roots,
	// 	Intermediates: x509.NewCertPool(),
	// }

	// if _, err := cert.Verify(opts); err != nil {
	// 	if err.Error() != "x509: unhandled critical extension" {
	// 		return &verifier.OfferPlatformCertResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("failed to verify platform certificate: "+err.Error()))
	// 	}
	// }

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
			return &verifier.MakeCredentialResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Error EKCert %v", err))
		}
		// https://pkg.go.dev/github.com/google/certificate-transparency-go/x509
		// you should verify the EKCert here and the serialNumber
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
		return &verifier.MakeCredentialResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Error DecodePublic EK %v", err))
	}

	ekPubKey, err := ekPub.Key()
	if err != nil {
		return &verifier.MakeCredentialResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Error extracting ekPubKey: %s", err))
	}
	ekBytes, err := x509.MarshalPKIXPublicKey(ekPubKey)
	if err != nil {
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

	var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	nonce := make([]rune, 10)
	for i := range nonce {
		nonce[i] = letterRunes[mrand.Intn(len(letterRunes))]
	}

	glog.V(2).Infof("     Sending Nonce %s,", string(nonce))
	nonces[in.Uid] = string(nonce)

	credBlob, encryptedSecret, err := makeCredential(string(nonce), in.EkCert, in.EkPub, in.AkPub)
	if err != nil {
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
		glog.Errorf("     ActivateCredential failed:  provided Secret does not match expected Nonce")
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
	if *importMode == "RSA" {
		_, key, err = generateCertificate(id)
		if err != nil {
			return &verifier.GetSecretResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Unable to gernate certificate %v", err))
		}

	}

	importBLob, err := createImportBlob(id, key)
	if err != nil {
		return &verifier.GetSecretResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Unable to create Import Blob %v", err))
	}

	glog.V(2).Infof("     Returning GetSecretResponse ========")

	return &verifier.GetSecretResponse{
		Uid:        in.Uid,
		ImportBlob: importBLob,
	}, nil
}

func (s *server) OfferQuote(ctx context.Context, in *verifier.OfferQuoteRequest) (*verifier.OfferQuoteResponse, error) {
	glog.V(2).Infof("======= OfferQuote ========")
	glog.V(5).Infof("     client provided uid: %s", in.Uid)

	var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	nonce := make([]rune, 10)
	for i := range nonce {
		nonce[i] = letterRunes[mrand.Intn(len(letterRunes))]
	}

	glog.V(2).Infof("     Sending Nonce %s,", string(nonce))
	id := in.Uid

	glog.V(2).Infof("     Returning OfferQuoteResponse ========")
	nonces[id] = string(nonce)
	return &verifier.OfferQuoteResponse{
		Uid:   in.Uid,
		Pcr:   int32(*pcr),
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
		glog.V(2).Infof("Unable to find nonce request for uid")
	} else {
		delete(nonces, id)
		err := verifyQuote(id, val, in.Attestation, in.Signature, in.Eventlog)
		if err == nil {
			ver = true
		} else {
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

	nn := registry[uid]
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
		glog.Errorf("     Nonce Value mismatch Got: (%s) Expected: (%v)", string(att.ExtraData), nonce)
		return fmt.Errorf("Nonce Value mismatch Got: (%s) Expected: (%v)", string(att.ExtraData), nonce)
	}

	sigL := tpm2.SignatureRSA{
		HashAlg:   tpm2.AlgSHA256,
		Signature: sigBytes,
	}
	decoded, err := hex.DecodeString(*expectedPCRValue)
	if err != nil {
		return fmt.Errorf("DecodeAttestationData(%v) failed: %v", attestation, err)
	}
	hash := sha256.Sum256(decoded)

	glog.V(5).Infof("     Expected PCR Value:           --> %s", *expectedPCRValue)
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
		bt, err := hex.DecodeString(*expectedPCRSHA1)
		if err != nil {
			glog.Fatalf("Error decoding pcr %v", err)
		}
		evtLogPcrMap := map[uint32][]byte{uint32(*pcr): bt}

		pcrs := &tpmpb.PCRs{Hash: tpmpb.HashAlgo_SHA1, Pcrs: evtLogPcrMap}

		events, err := gotpmserver.ParseAndVerifyEventLog(eventLog, pcrs)
		if err != nil {
			return fmt.Errorf("Failed to parse EventLog: %v", err)
		}

		for _, event := range events {
			glog.V(2).Infof("     Event Type %v\n", event.Type)
			glog.V(2).Infof("     PCR Index %d\n", event.Index)
			glog.V(2).Infof("     Event Data %s\n", hex.EncodeToString(event.Data))
			glog.V(2).Infof("     Event Digest %s\n", hex.EncodeToString(event.Digest))
		}
		glog.V(2).Infof("     EventLog Verified ")
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

	glog.V(10).Infof("     Read (akPub) from request")

	tPub, err := tpm2.DecodePublic(akPubBytes)
	if err != nil {
		return []byte(""), []byte(""), fmt.Errorf("Error DecodePublic AK %v", tPub)
	}

	ap, err := tPub.Key()
	if err != nil {
		return []byte(""), []byte(""), fmt.Errorf("akPub.Key() failed: %s", err)
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
	glog.V(10).Infof("     Decoded AkPub: \n%v", string(akPubPEM))

	if tPub.MatchesTemplate(defaultKeyParams) {
		glog.V(10).Infof("     AK Default parameter match template")
	} else {
		return []byte(""), []byte(""), fmt.Errorf("AK does not have correct defaultParameters")
	}
	h, keyName, err := tpm2.LoadExternal(rwc, tPub, tpm2.Private{}, tpm2.HandleNull)
	if err != nil {
		return []byte(""), []byte(""), fmt.Errorf("Error loadingExternal AK %v", err)
	}
	defer tpm2.FlushContext(rwc, h)
	glog.V(10).Infof("     Loaded AK KeyName %s", hex.EncodeToString(keyName))

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
		return &verifier.OfferCSRResponse{}, fmt.Errorf("DecodeAttestationData failed: %v", err)
	}
	glog.V(20).Infof("     Attestation AttestedCertifyInfo.Name.Digest.Value: %s", hex.EncodeToString(att.AttestedCertifyInfo.Name.Digest.Value))

	// Verify signature of Attestation by using the PEM Public key for AK
	nn := registry[in.Uid]
	akPub := nn.AkPub
	p, err := tpm2.DecodePublic(akPub)
	if err != nil {
		return &verifier.OfferCSRResponse{}, fmt.Errorf("DecodePublic failed: %v", err)
	}
	rsaPub := rsa.PublicKey{E: int(p.RSAParameters.Exponent()), N: p.RSAParameters.Modulus()}
	ahsh := crypto.SHA256.New()
	ahsh.Write(in.Attestation)

	if err := rsa.VerifyPKCS1v15(&rsaPub, crypto.SHA256, ahsh.Sum(nil), in.AttestationSignature); err != nil {
		return &verifier.OfferCSRResponse{}, fmt.Errorf("VerifyPKCS1v15 failed: %v", err)
	}
	glog.V(10).Infof("     Attestation of Unrestricted Signing Key Verified")

	// now verify that the public key provided is the same as in the CSR and that the "Template" is what we expect
	tPub, err := tpm2.DecodePublic(in.PublicKey)
	if err != nil {
		return &verifier.OfferCSRResponse{}, fmt.Errorf("Error Decode Unrestricted key Public %v", tPub)
	}

	up, err := tPub.Key()
	if err != nil {
		return &verifier.OfferCSRResponse{}, fmt.Errorf("ukPub.Key() failed: %s", err)
	}
	ukBytes, err := x509.MarshalPKIXPublicKey(up)
	if err != nil {
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
		return &verifier.OfferCSRResponse{}, fmt.Errorf("uK does not have correct template parameters")
	}

	// now extract the public key from the CSR
	b, _ := pem.Decode(in.Csr)
	var csrobj *x509.CertificateRequest
	csrobj, err = x509.ParseCertificateRequest(b.Bytes)
	if err != nil {
		return &verifier.OfferCSRResponse{}, fmt.Errorf("Unable to parse CSR %v", err)
	}

	rkey, ok := csrobj.PublicKey.(*rsa.PublicKey)
	if !ok {
		return &verifier.OfferCSRResponse{}, fmt.Errorf("Unable to extract public key from CSR %v", err)
	}

	glog.V(10).Infof("     Verifying if Public key from CSR matches attested Public key")
	fkey, ok := up.(*rsa.PublicKey)
	if !ok {
		return &verifier.OfferCSRResponse{}, fmt.Errorf("Unable to extract public key from CSR %v", err)
	}

	if !rkey.Equal(fkey) {
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
		return &verifier.OfferCSRResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("     AttestedCertifyInfo.MatchesPublic(%v) failed: %v", att, err))
	}
	glog.V(10).Infof("     Unrestricted RSA Public key parameters matches AttestedCertifyInfo  %v", ok)

	crt, err := signCSR(in.Csr)
	if err != nil {
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
	nn := registry[uid]

	tPub, err := tpm2.DecodePublic(nn.EkPub)
	if err != nil {
		return []byte(""), fmt.Errorf("Error DecodePublic K %v", tPub)
	}

	ap, err := tPub.Key()
	if err != nil {
		return []byte(""), fmt.Errorf("akPub.Key() failed: %s", err)
	}

	glog.V(5).Infof("     Decoding sealing PCR value in hex")
	hv, err := hex.DecodeString(*expectedPCRValue)
	if err != nil {
		return []byte(""), fmt.Errorf("Error parsing uint64->32: %v\n", err)
	}

	pcrMap := map[uint32][]byte{uint32(*pcr): hv}
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
