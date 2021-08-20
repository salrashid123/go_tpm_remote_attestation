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

	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	mrnd "math/rand"
	"net"
	"os"
	"sync"
	"time"
	"verifier"

	"github.com/golang/glog"

	"golang.org/x/net/context"

	"google.golang.org/grpc"

	"github.com/lestrrat/go-jwx/jwk"
	"google.golang.org/grpc/status"

	"github.com/golang/protobuf/proto"
	"github.com/google/go-tpm-tools/client"

	gotpmserver "github.com/google/go-tpm-tools/server"

	pb "github.com/google/go-tpm-tools/proto/tpm"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"

	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

var (
	grpcport         = flag.String("grpcport", "", "grpcport")
	expectedPCRValue = flag.String("expectedPCRValue", "24af52a4f429b71a3184a6d64cddad17e54ea030e2aa6576bf3a5a3d8bd3328f", "expectedPCRValue")
	pcr              = flag.Int("pcr", 23, "PCR Value to use")
	caCert           = flag.String("cacert", "CA_crt.pem", "CA Certificate to issue certs")
	caKey            = flag.String("cackey", "CA_key.pem", "CA PrivateKey to issue certs")
	serverCert       = flag.String("servercert", "server_crt.pem", "Server SSL Certificate")
	serverKey        = flag.String("serverkey", "server_key.pem", "Server SSL PrivateKey")
	usemTLS          = flag.Bool("usemTLS", false, "Validate original client request with mTLS")
	registry         = make(map[string]verifier.MakeCredentialRequest)
	nonces           = make(map[string]string)
	rwc              io.ReadWriteCloser
	jwtSet           *jwk.Set
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
	letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
)

const (
	targetAudience = "grpc://verify.esodemoapp2.com"
	tpmDevice      = "/dev/tpm0"
)

type server struct {
}

type hserver struct {
	mu sync.Mutex
	// statusMap stores the serving status of the services this Server monitors.
	statusMap map[string]healthpb.HealthCheckResponse_ServingStatus
}

type contextKey string

// gRPC middleware which validates the OIDC token sent in every request.
// This check verifies the id token is valid and then extracts the google specific annotations.
func authUnaryInterceptor(
	ctx context.Context,
	req interface{},
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (interface{}, error) {
	glog.V(2).Infof(">> inbound request")
	//md, _ := metadata.FromIncomingContext(ctx)

	newCtx := context.WithValue(ctx, contextKey("idtoken"), "someheader")
	return handler(newCtx, req)

	//return nil, grpc.Errorf(codes.Unauthenticated, "Authorization header not provided")
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
	for _, handleType := range handleNames["all"] {
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
	mrnd.Seed(time.Now().UnixNano())
	s.Serve(lis)
}

func (s *server) MakeCredential(ctx context.Context, in *verifier.MakeCredentialRequest) (*verifier.MakeCredentialResponse, error) {

	glog.V(2).Infof("======= MakeCredential ========")
	glog.V(5).Infof("     client provided uid: %s", in.Uid)
	glog.V(10).Infof("     Got AKName %s", in.AkName)
	glog.V(10).Infof("     Registry size %d\n", len(registry))

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

	// check if the request happened to contain a EKcert

	if len(in.EkCert) > 0 {
		encCert, err := x509.ParseCertificate(in.EkCert)
		if err != nil {
			return &verifier.MakeCredentialResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("ERROR:   ParseCertificate: %v", err))
		}
		glog.V(10).Infof("     EKPubCert Issuer CommonName: %s", string(encCert.Issuer.CommonName))
		glog.V(10).Infof("     EKPubCert SerialNumber: %s", encCert.SerialNumber.String())
	}

	//  NOTE: this is the point where you would usually have some way to verify that the EKPubPEM is infact
	//        for this TPM.  One way to do that is to check the EKCert that is signed by the TPM's manufacturer
	//        on GCP, the EKCert is provided by the client if you invoke the client with `--readCertsFromNV` flag.
	//        The EKCert for GCP is signed by google and has the actual instanceID, project and zone  embedded within in it as extended Claims
	//        You can extract the public key from the x509 and use that for remote attestation.

	//    This repo simply trusts the EKPubPEM just for simplicity...you really need to establish root of trust using the EKCert or some other mechanism.

	registry[in.Uid] = *in

	b := make([]rune, 32)
	for i := range b {
		b[i] = letterRunes[mrnd.Intn(len(letterRunes))]
	}
	nonce := string(b)
	nonces[in.Uid] = nonce

	credBlob, encryptedSecret, err := makeCredential(nonce, in.EkPub, in.AkPub)
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

	verified := false
	nonce := nonces[in.Uid]

	if nonce != in.Secret {
		glog.V(5).Infof("     client provided incorrect nonce for ActivateCredential wanted [%s], got [%s]", nonce, in.Uid)
	}

	return &verifier.ActivateCredentialResponse{
		Uid:      in.Uid,
		Verified: verified,
	}, nil
}

func (s *server) OfferQuote(ctx context.Context, in *verifier.OfferQuoteRequest) (*verifier.OfferQuoteResponse, error) {
	glog.V(2).Infof("======= OfferQuote ========")
	glog.V(5).Infof("     client provided uid: %s", in.Uid)

	nonce := uuid.New().String()

	id := in.Uid
	glog.V(2).Infof("     Returning OfferQuoteResponse ========")
	nonces[id] = nonce
	return &verifier.OfferQuoteResponse{
		Uid:   in.Uid,
		Pcr:   int32(*pcr),
		Nonce: nonce,
	}, nil
}

func (s *server) OfferImport(ctx context.Context, in *verifier.OfferImportRequest) (*verifier.OfferImportResponse, error) {
	glog.V(2).Infof("======= OfferImport ========")
	glog.V(5).Infof("     client provided uid: %s", in.Uid)

	nonce := uuid.New().String()

	id := in.Uid
	glog.V(2).Infof("     Returning OfferImportResponse ========")
	nonces[id] = nonce

	resp := &verifier.OfferImportResponse{
		SecretType: verifier.SecretType_AES,
	}
	var key []byte
	var err error
	if *importMode == "RSA" {
		_, key, err = generateCertificate(in.Uid)
		if err != nil {
			return &verifier.OfferImportResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Unable to gernate certificate %v", err))
		}
		resp.SecretType = verifier.SecretType_RSA
	}

	importBLob, err := createImportBlob(in.Uid, key)
	if err != nil {
		return &verifier.OfferImportResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Unable to create Import Blob %v", err))
	}
	glog.V(2).Infof("     Returning OfferImportResponse ========")

	resp.Uid = in.Uid
	resp.ImportBlob = importBLob

	return resp, nil
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
		err := verifyQuote(id, val, in.Attestation, in.Signature)
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

func verifyQuote(uid string, nonce string, attestation []byte, sigBytes []byte) (retErr error) {
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
	glog.V(2).Infof("     <-- End verifyQuote()")
	return nil
}

func makeCredential(sec string, ekPubBytes []byte, akPubBytes []byte) (credBlob []byte, encryptedSecret []byte, retErr error) {

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

	glog.V(10).Infof("     Generated cert with Serial %s", ca.SerialNumber.String())

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
	var pcrs *pb.PCRs

	pcrs = &pb.PCRs{Hash: pb.HashAlgo_SHA256, Pcrs: pcrMap}

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
			glog.Fatalf("Unable to CreateImportBlob : %v", err)
		}
		sealedOutput, err = proto.Marshal(importBlob)
		if err != nil {
			glog.Fatalf("Unable to marshall ImportBlob: ", err)
		}
	} else {
		glog.Fatalln("Import mode must be RSA or AES")
	}

	glog.V(2).Infof("     <-- End createImportBlob()")

	return sealedOutput, nil
}
