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
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"

	"flag"
	"fmt"
	"io"
	"io/ioutil"
	mrnd "math/rand"
	"net"
	"os"
	"sync"
	"time"
	"verifier"

	"github.com/golang/glog"

	"golang.org/x/net/context"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"

	"google.golang.org/grpc/status"

	"github.com/google/go-tpm-tools/client"

	tpmpb "github.com/google/go-tpm-tools/proto/tpm"
	"github.com/google/go-tpm/tpm2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

var (
	grpcport   = flag.String("grpcport", "", "grpcport")
	caCert     = flag.String("cacert", "certs/CA_crt.pem", "CA Certificate to trust")
	pcr        = flag.Int("pcr", 0, "PCR Value to use")
	serverCert = flag.String("servercert", "certs/server_crt.pem", "Server SSL Certificate")
	serverKey  = flag.String("serverkey", "certs/server_key.pem", "Server SSL PrivateKey")
	nonces     = make(map[string]string)

	platformCert = flag.String("platformCert", "certs/tpm_ek_intermediate_2.crt", "Platform x509 cert (DER)")
	rwc          io.ReadWriteCloser

	handleNames = map[string][]tpm2.HandleType{
		"all":       []tpm2.HandleType{tpm2.HandleTypeLoadedSession, tpm2.HandleTypeSavedSession, tpm2.HandleTypeTransient},
		"loaded":    []tpm2.HandleType{tpm2.HandleTypeLoadedSession},
		"saved":     []tpm2.HandleType{tpm2.HandleTypeSavedSession},
		"transient": []tpm2.HandleType{tpm2.HandleTypeTransient},
	}

	defaultEKTemplate = tpm2.Public{
		Type:    tpm2.AlgRSA,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin |
			tpm2.FlagAdminWithPolicy | tpm2.FlagRestricted | tpm2.FlagDecrypt,
		AuthPolicy: []byte{
			0x83, 0x71, 0x97, 0x67, 0x44, 0x84,
			0xB3, 0xF8, 0x1A, 0x90, 0xCC, 0x8D,
			0x46, 0xA5, 0xD7, 0x24, 0xFD, 0x52,
			0xD7, 0x6E, 0x06, 0x52, 0x0B, 0x64,
			0xF2, 0xA1, 0xDA, 0x1B, 0x33, 0x14,
			0x69, 0xAA,
		},
		RSAParameters: &tpm2.RSAParams{
			Symmetric: &tpm2.SymScheme{
				Alg:     tpm2.AlgAES,
				KeyBits: 128,
				Mode:    tpm2.AlgCFB,
			},
			KeyBits:    2048,
			ModulusRaw: make([]byte, 256),
		},
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
	tpmDevice             = "/dev/tpm0"
	encryptionCertNVIndex = 0x01c00002

	emptyPassword   = ""
	importedKeyFile = "importedKey.bin"
	akPubFile       = "akPub.bin"
	akPrivFile      = "akPriv.bin"
	ekFile          = "ek.bin"
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

func (s *server) GetPlatformCert(ctx context.Context, in *verifier.GetPlatformCertRequest) (*verifier.GetPlatformCertResponse, error) {
	glog.V(2).Infof("======= GetPlatformCert ========")
	glog.V(5).Infof("     client provided uid: %s", in.Uid)

	r, err := ioutil.ReadFile(*platformCert)
	if err != nil {
		return &verifier.GetPlatformCertResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Unable to load platform certificate from file %v", err))
	}
	block, _ := pem.Decode(r)
	fmt.Println(block.Type)

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return &verifier.GetPlatformCertResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Unable to load parse platform certificate %v", err))
	}
	glog.V(2).Infof("     Found Platform Cert Issuer %s ========", cert.Issuer.String())
	glog.V(2).Infof("     Returning GetPlatformCert ========")
	return &verifier.GetPlatformCertResponse{
		Uid:          in.Uid,
		PlatformCert: cert.Raw,
	}, nil
}

func (s *server) GetEKCert(ctx context.Context, in *verifier.GetEKCertRequest) (*verifier.GetEKCertResponse, error) {
	glog.V(2).Infof("======= GetEKCert ========")
	glog.V(5).Infof("     client provided uid: %s", in.Uid)

	var ekcertBytes []byte

	// First acquire the AK, EK keys, certificates from NV

	glog.V(5).Infof("=============== Load EncryptionKey and Certifcate from NV ===============")
	ekk, err := client.EndorsementKeyRSA(rwc)
	if err != nil {
		return &verifier.GetEKCertResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("ERROR:  could not get EndorsementKeyRSA: %v", err))
	}
	epubKey := ekk.PublicKey().(*rsa.PublicKey)
	ekBytes, err := x509.MarshalPKIXPublicKey(epubKey)
	if err != nil {
		return &verifier.GetEKCertResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("ERROR:  could not get MarshalPKIXPublicKey: %v", err))
	}
	ekPubPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: ekBytes,
		},
	)
	glog.V(10).Infof("     Encryption PEM \n%s", string(ekPubPEM))
	ekk.Close()

	// now reread the EKEncryption directly from NV
	//   the EKCertificate (x509) is saved at encryptionCertNVIndex
	//   the following steps attempts to read that value in directly from NV
	//   This is currently not supported but i'm adding in code anyway

	ekcertBytes, err = tpm2.NVReadEx(rwc, encryptionCertNVIndex, tpm2.HandleOwner, "", 0)
	if err != nil {
		return &verifier.GetEKCertResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("ERROR:  could not get NVReadEx: %v", err))
	}

	encCert, err := x509.ParseCertificate(ekcertBytes)
	if err != nil {
		return &verifier.GetEKCertResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("ERROR:   ParseCertificate: %v", err))
	}

	glog.V(10).Infof("     Encryption Issuer x509 %s", encCert.Issuer.CommonName)
	glog.V(2).Infof("     Returning GetEKCert ========")
	return &verifier.GetEKCertResponse{
		Uid:    in.Uid,
		EkCert: encCert.Raw,
	}, nil
}

func (s *server) GetAK(ctx context.Context, in *verifier.GetAKRequest) (*verifier.GetAKResponse, error) {
	glog.V(2).Infof("======= GetAK ========")
	glog.V(5).Infof("     client provided uid: %s", in.Uid)

	pcrList := []int{*pcr}
	pcrval, err := tpm2.ReadPCR(rwc, *pcr, tpm2.AlgSHA256)
	if err != nil {
		return &verifier.GetAKResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("ERROR:   Unable to  ReadPCR: %v", err))
	}
	glog.V(10).Infof("    Current PCR %v Value %d ", *pcr, hex.EncodeToString(pcrval))

	pcrSelection23 := tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: pcrList}
	emptyPassword := ""

	glog.V(10).Infof("     createPrimary")

	ekh, _, err := tpm2.CreatePrimary(rwc, tpm2.HandleEndorsement, pcrSelection23, emptyPassword, emptyPassword, defaultEKTemplate)
	if err != nil {
		return &verifier.GetAKResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Error creating EK: %v", err))
	}
	defer tpm2.FlushContext(rwc, ekh)

	// reread the pub eventhough tpm2.CreatePrimary* gives pub
	tpmEkPub, name, _, err := tpm2.ReadPublic(rwc, ekh)
	if err != nil {
		return &verifier.GetAKResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Error ReadPublic failed: %s", err))
	}

	p, err := tpmEkPub.Key()
	if err != nil {
		return &verifier.GetAKResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Error tpmEkPub.Key() failed: %s", err))
	}
	glog.V(10).Infof("     tpmEkPub: \n%v", p)

	b, err := x509.MarshalPKIXPublicKey(p)
	if err != nil {
		return &verifier.GetAKResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Unable to convert ekpub: %v", err))
	}

	ekPubPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: b,
		},
	)
	glog.V(5).Infof("     ekPub Name: %v", hex.EncodeToString(name))
	glog.V(10).Infof("     ekPubPEM: \n%v", string(ekPubPEM))

	ekPubBytes, err := tpmEkPub.Encode()
	if err != nil {
		return &verifier.GetAKResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Load failed for ekPubBytes: %v", err))
	}

	glog.V(10).Infof("     CreateKeyUsingAuth")

	sessCreateHandle, _, err := tpm2.StartAuthSession(
		rwc,
		tpm2.HandleNull,
		tpm2.HandleNull,
		make([]byte, 16),
		nil,
		tpm2.SessionPolicy,
		tpm2.AlgNull,
		tpm2.AlgSHA256)
	if err != nil {
		return &verifier.GetAKResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Unable to create StartAuthSession : %v", err))
	}
	defer tpm2.FlushContext(rwc, sessCreateHandle)

	if _, err := tpm2.PolicySecret(rwc, tpm2.HandleEndorsement, tpm2.AuthCommand{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession}, sessCreateHandle, nil, nil, nil, 0); err != nil {
		return &verifier.GetAKResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Unable to create PolicySecret: %v", err))
	}

	authCommandCreateAuth := tpm2.AuthCommand{Session: sessCreateHandle, Attributes: tpm2.AttrContinueSession}

	akPriv, akPub, creationData, creationHash, creationTicket, err := tpm2.CreateKeyUsingAuth(rwc, ekh, pcrSelection23, authCommandCreateAuth, emptyPassword, defaultKeyParams)
	if err != nil {
		return &verifier.GetAKResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("CreateKey failed: %s", err))
	}
	glog.V(10).Infof("     akPub: %v,", hex.EncodeToString(akPub))
	glog.V(10).Infof("     akPriv: %v,", hex.EncodeToString(akPriv))

	cr, err := tpm2.DecodeCreationData(creationData)
	if err != nil {
		return &verifier.GetAKResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Unable to  DecodeCreationData : %v", err))
	}

	glog.V(10).Infof("     CredentialData.ParentName.Digest.Value %v", hex.EncodeToString(cr.ParentName.Digest.Value))
	glog.V(10).Infof("     CredentialTicket %v", hex.EncodeToString(creationTicket.Digest))
	glog.V(10).Infof("     CredentialHash %v", hex.EncodeToString(creationHash))

	glog.V(10).Infof("     ContextSave (ek)")
	ekhBytes, err := tpm2.ContextSave(rwc, ekh)
	if err != nil {
		return &verifier.GetAKResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("ContextSave failed for ekh: %v", err))
	}
	err = ioutil.WriteFile(ekFile, ekhBytes, 0644)
	if err != nil {
		return &verifier.GetAKResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("ContextSave failed for ekh: %v", err))
	}
	tpm2.FlushContext(rwc, ekh)

	glog.V(10).Infof("     ContextLoad (ek)")
	ekhBytes, err = ioutil.ReadFile(ekFile)
	if err != nil {
		return &verifier.GetAKResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("ContextLoad failed for ekh: %v", err))
	}
	ekh, err = tpm2.ContextLoad(rwc, ekhBytes)
	if err != nil {
		return &verifier.GetAKResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("ContextLoad failed for ekh: %v", err))
	}
	defer tpm2.FlushContext(rwc, ekh)

	glog.V(10).Infof("     LoadUsingAuth")

	loadSession, _, err := tpm2.StartAuthSession(
		rwc,
		tpm2.HandleNull,
		tpm2.HandleNull,
		make([]byte, 16),
		nil,
		tpm2.SessionPolicy,
		tpm2.AlgNull,
		tpm2.AlgSHA256)
	if err != nil {
		return &verifier.GetAKResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Unable to create StartAuthSession : %v", err))
	}
	defer tpm2.FlushContext(rwc, loadSession)

	if _, err := tpm2.PolicySecret(rwc, tpm2.HandleEndorsement, tpm2.AuthCommand{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession}, loadSession, nil, nil, nil, 0); err != nil {
		return &verifier.GetAKResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Unable to create PolicySecret: %v", err))
	}

	authCommandLoad := tpm2.AuthCommand{Session: loadSession, Attributes: tpm2.AttrContinueSession}

	keyHandle, keyName, err := tpm2.LoadUsingAuth(rwc, ekh, authCommandLoad, akPub, akPriv)
	if err != nil {
		return &verifier.GetAKResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Load failed: %s", err))
	}
	defer tpm2.FlushContext(rwc, keyHandle)
	kn := hex.EncodeToString(keyName)
	glog.V(5).Infof("     AK keyName %v", kn)

	akPublicKey, akName, _, err := tpm2.ReadPublic(rwc, keyHandle)
	if err != nil {
		return &verifier.GetAKResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Error tpmEkPub.Key() failed: %s", err))
	}

	ap, err := akPublicKey.Key()
	if err != nil {
		return &verifier.GetAKResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("tpmEkPub.Key() failed: %s", err))
	}
	akBytes, err := x509.MarshalPKIXPublicKey(ap)
	if err != nil {
		return &verifier.GetAKResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Unable to convert ekpub: %v", err))
	}

	akPubPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: akBytes,
		},
	)
	glog.V(10).Infof("     akPubPEM: \n%v", string(akPubPEM))

	glog.V(10).Infof("     Write (akPub) ========")
	err = ioutil.WriteFile(akPubFile, akPub, 0644)
	if err != nil {
		return &verifier.GetAKResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Save failed for akPub: %v", err))
	}
	glog.V(10).Infof("     Write (akPriv) ========")
	err = ioutil.WriteFile(akPrivFile, akPriv, 0644)
	if err != nil {
		return &verifier.GetAKResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Save failed for akPriv: %v", err))
	}
	akPubBytes, err := akPublicKey.Encode()
	if err != nil {
		return &verifier.GetAKResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Load failed for akPubBytes: %v", err))
	}

	glog.V(2).Infof("     Returning GetAK ========")

	res := &verifier.GetAKResponse{
		Uid:    in.Uid,
		EkPub:  ekPubBytes,
		AkName: akName,
		AkPub:  akPubBytes,
	}
	return res, nil
}

func (s *server) ActivateCredential(ctx context.Context, in *verifier.ActivateCredentialRequest) (*verifier.ActivateCredentialResponse, error) {
	glog.V(2).Infof("======= ActivateCredential ========")
	glog.V(5).Infof("     client provided uid: %s", in.Uid)

	glog.V(10).Infof("     ContextLoad (ek)")
	ekhBytes, err := ioutil.ReadFile(ekFile)
	if err != nil {
		return &verifier.ActivateCredentialResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("ContextLoad failed for ekh: %v", err))
	}
	ekh, err := tpm2.ContextLoad(rwc, ekhBytes)
	if err != nil {
		return &verifier.ActivateCredentialResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("ContextLoad failed for ekh: %v", err))
	}
	defer tpm2.FlushContext(rwc, ekh)

	glog.V(10).Infof("     Read (akPub)")
	akPub, err := ioutil.ReadFile(akPubFile)
	if err != nil {
		return &verifier.ActivateCredentialResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Read failed for akPub: %v", err))
	}
	glog.V(10).Infof("     Read (akPriv)")
	akPriv, err := ioutil.ReadFile(akPrivFile)
	if err != nil {
		return &verifier.ActivateCredentialResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Read failed for akPriv: %v", err))
	}

	loadCreateHandle, _, err := tpm2.StartAuthSession(
		rwc,
		tpm2.HandleNull,
		tpm2.HandleNull,
		make([]byte, 16),
		nil,
		tpm2.SessionPolicy,
		tpm2.AlgNull,
		tpm2.AlgSHA256)
	if err != nil {
		return &verifier.ActivateCredentialResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Unable to create StartAuthSession : %v", err))
	}
	defer tpm2.FlushContext(rwc, loadCreateHandle)

	if _, err := tpm2.PolicySecret(rwc, tpm2.HandleEndorsement, tpm2.AuthCommand{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession}, loadCreateHandle, nil, nil, nil, 0); err != nil {
		return &verifier.ActivateCredentialResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Unable to create PolicySecret: %v", err))
	}

	authCommandLoad := tpm2.AuthCommand{Session: loadCreateHandle, Attributes: tpm2.AttrContinueSession}

	keyHandle, keyName, err := tpm2.LoadUsingAuth(rwc, ekh, authCommandLoad, akPub, akPriv)
	if err != nil {
		return &verifier.ActivateCredentialResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Load failed: %s", err))
	}
	defer tpm2.FlushContext(rwc, keyHandle)
	glog.V(5).Infof("     keyName %v", hex.EncodeToString(keyName))

	glog.V(5).Infof("     ActivateCredentialUsingAuth")

	sessActivateCredentialSessHandle1, _, err := tpm2.StartAuthSession(
		rwc,
		tpm2.HandleNull,
		tpm2.HandleNull,
		make([]byte, 16),
		nil,
		tpm2.SessionPolicy,
		tpm2.AlgNull,
		tpm2.AlgSHA256)
	if err != nil {
		return &verifier.ActivateCredentialResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Unable to create StartAuthSession : %v", err))
	}
	defer tpm2.FlushContext(rwc, sessActivateCredentialSessHandle1)

	if _, err := tpm2.PolicySecret(rwc, tpm2.HandleEndorsement, tpm2.AuthCommand{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession}, sessActivateCredentialSessHandle1, nil, nil, nil, 0); err != nil {
		return &verifier.ActivateCredentialResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Unable to create PolicySecret: %v", err))
	}

	authCommandActivate1 := tpm2.AuthCommand{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession}

	sessActivateCredentialSessHandle2, _, err := tpm2.StartAuthSession(
		rwc,
		tpm2.HandleNull,
		tpm2.HandleNull,
		make([]byte, 16),
		nil,
		tpm2.SessionPolicy,
		tpm2.AlgNull,
		tpm2.AlgSHA256)
	if err != nil {
		return &verifier.ActivateCredentialResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Unable to create StartAuthSession : %v", err))
	}
	defer tpm2.FlushContext(rwc, sessActivateCredentialSessHandle2)

	if _, err := tpm2.PolicySecret(rwc, tpm2.HandleEndorsement, tpm2.AuthCommand{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession}, sessActivateCredentialSessHandle2, nil, nil, nil, 0); err != nil {
		return &verifier.ActivateCredentialResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Unable to create PolicySecret: %v", err))
	}

	authCommandActivate2 := tpm2.AuthCommand{Session: sessActivateCredentialSessHandle2, Attributes: tpm2.AttrContinueSession}

	tl := []tpm2.AuthCommand{authCommandActivate1, authCommandActivate2}

	recoveredCredential1, err := tpm2.ActivateCredentialUsingAuth(rwc, tl, keyHandle, ekh, in.CredBlob, in.EncryptedSecret)
	if err != nil {
		return &verifier.ActivateCredentialResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("ActivateCredential failed: %v", err))
	}
	glog.V(5).Infof("     <--  activateCredential()")

	res := &verifier.ActivateCredentialResponse{
		Uid:    in.Uid,
		Secret: recoveredCredential1,
	}
	return res, nil
}

func (s *server) Quote(ctx context.Context, in *verifier.QuoteRequest) (*verifier.QuoteResponse, error) {
	glog.V(2).Infof("======= Quote ========")
	glog.V(5).Infof("     client provided uid: %s", in.Uid)

	pcrList := []int{int(in.Pcr)}
	pcrval, err := tpm2.ReadPCR(rwc, int(in.Pcr), tpm2.AlgSHA256)
	if err != nil {
		glog.Fatalf("Unable to  ReadPCR : %v", err)
	}
	glog.V(5).Infof("     PCR %d Value %v ", in.Pcr, hex.EncodeToString(pcrval))

	pcrSelection23 := tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: pcrList}
	emptyPassword := ""

	glog.V(10).Infof("     ContextLoad (ek) ========")
	ekhBytes, err := ioutil.ReadFile(ekFile)
	if err != nil {
		return &verifier.QuoteResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("ContextLoad failed for ekh: %v", err))
	}
	ekh, err := tpm2.ContextLoad(rwc, ekhBytes)
	if err != nil {
		return &verifier.QuoteResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("ContextLoad failed for ekh: %v", err))
	}
	defer tpm2.FlushContext(rwc, ekh)
	glog.V(10).Infof("     LoadUsingAuth ========")

	loadCreateHandle, _, err := tpm2.StartAuthSession(
		rwc,
		tpm2.HandleNull,
		tpm2.HandleNull,
		make([]byte, 16),
		nil,
		tpm2.SessionPolicy,
		tpm2.AlgNull,
		tpm2.AlgSHA256)
	if err != nil {
		return &verifier.QuoteResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Unable to create StartAuthSession : %v", err))
	}
	defer tpm2.FlushContext(rwc, loadCreateHandle)

	if _, err := tpm2.PolicySecret(rwc, tpm2.HandleEndorsement, tpm2.AuthCommand{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession}, loadCreateHandle, nil, nil, nil, 0); err != nil {
		return &verifier.QuoteResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Unable to create PolicySecret: %v", err))
	}

	authCommandLoad := tpm2.AuthCommand{Session: loadCreateHandle, Attributes: tpm2.AttrContinueSession}

	glog.V(10).Infof("     Read (akPub) ========")
	akPub, err := ioutil.ReadFile(akPubFile)
	if err != nil {
		return &verifier.QuoteResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Read failed for akPub: %v", err))
	}
	glog.V(10).Infof("     Read (akPriv) ========")
	akPriv, err := ioutil.ReadFile(akPrivFile)
	if err != nil {
		return &verifier.QuoteResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Read failed for akPriv: %v", err))
	}

	keyHandle, keyName, err := tpm2.LoadUsingAuth(rwc, ekh, authCommandLoad, akPub, akPriv)
	if err != nil {
		return &verifier.QuoteResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Load failed: %s", err))
	}
	defer tpm2.FlushContext(rwc, keyHandle)
	kn := hex.EncodeToString(keyName)
	glog.V(10).Infof("     AK keyName %s", kn)

	attestation, sig, err := tpm2.Quote(rwc, keyHandle, emptyPassword, emptyPassword, []byte(in.Secret), pcrSelection23, tpm2.AlgNull)
	if err != nil {
		return &verifier.QuoteResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Failed to quote: %s", err))
	}
	glog.V(10).Infof("     Quote Hex %v", hex.EncodeToString(attestation))
	glog.V(10).Infof("     Quote Sig %v", hex.EncodeToString(sig.RSA.Signature))
	glog.V(5).Infof("     <-- End Quote")

	res := &verifier.QuoteResponse{
		Uid:         in.Uid,
		Attestation: attestation,
		Signature:   sig.RSA.Signature,
	}
	return res, nil
}

func (s *server) PushSecret(ctx context.Context, in *verifier.PushSecretRequest) (*verifier.PushSecretResponse, error) {
	glog.V(2).Infof("======= PushSecret ========")
	glog.V(5).Infof("     client provided uid: %s", in.Uid)
	var verification []byte

	glog.V(5).Infof("     Loading EndorsementKeyRSA")
	ek, err := client.EndorsementKeyRSA(rwc)
	if err != nil {
		return &verifier.PushSecretResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Unable to get EndorsementKeyRSA: %v", err))
	}
	defer ek.Close()

	blob := &tpmpb.ImportBlob{}
	err = proto.Unmarshal(in.ImportBlob, blob)
	if err != nil {
		return &verifier.PushSecretResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Error Unmarshalling ImportBlob error: ", err))
	}

	if in.SecretType == verifier.SecretType_AES {

		glog.V(5).Infof("     Importing External Key")
		k, err := ek.Import(blob)
		if err != nil {
			return &verifier.PushSecretResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Unable to Import sealed data: %v", err))
		}
		glog.V(5).Infof("     <-- End importKey()")
		hasher := sha256.New()
		hasher.Write(k)
		verification = hasher.Sum(nil)
		glog.V(5).Infof("     Hash of imported Key %s", base64.StdEncoding.EncodeToString(verification))

	} else if in.SecretType == verifier.SecretType_RSA {

		glog.V(5).Infof("     Loading ImportSigningKey")
		key, err := ek.ImportSigningKey(blob)
		defer key.Close()
		if err != nil {
			return &verifier.PushSecretResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("error ImportSigningKey: %v", err))
		}

		ap := key.PublicKey()
		importedBytes, err := x509.MarshalPKIXPublicKey(ap)
		if err != nil {
			return &verifier.PushSecretResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Unable to convert akPub: %v", err))
		}

		importedPubPEM := pem.EncodeToMemory(
			&pem.Block{
				Type:  "PUBLIC KEY",
				Bytes: importedBytes,
			},
		)
		glog.V(10).Infof("     Public portion of RSA Keypair to import: \n%s", string(importedPubPEM))

		glog.V(10).Infof("     Saving Key Handle as %s", importedKeyFile)
		keyHandle := key.Handle()
		defer key.Close()
		keyBytes, err := tpm2.ContextSave(rwc, keyHandle)
		if err != nil {
			return &verifier.PushSecretResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("ContextSave failed for keyHandle: %v", err))
		}
		err = ioutil.WriteFile(importedKeyFile, keyBytes, 0644)
		if err != nil {
			return &verifier.PushSecretResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("FileSave ContextSave failed for keyBytes: %v", err))
		}
		defer tpm2.FlushContext(rwc, keyHandle)

		glog.V(10).Infof("    Generating Test Signature ========")
		session, _, err := tpm2.StartAuthSession(
			rwc,
			tpm2.HandleNull,
			tpm2.HandleNull,
			make([]byte, 32),
			nil,
			tpm2.SessionPolicy,
			tpm2.AlgNull,
			tpm2.AlgSHA256)
		if err != nil {
			glog.Fatalf("StartAuthSession failed: %v", err)
		}
		defer tpm2.FlushContext(rwc, session)

		dataToSign := []byte("secret")
		digest := sha256.Sum256(dataToSign)

		if err = tpm2.PolicyPCR(rwc, session, nil, tpm2.PCRSelection{tpm2.AlgSHA256, []int{*pcr}}); err != nil {
			glog.Fatalf("PolicyPCR failed: %v", err)
		}
		sig, err := tpm2.SignWithSession(rwc, session, keyHandle, emptyPassword, digest[:], nil, &tpm2.SigScheme{
			Alg:  tpm2.AlgRSASSA,
			Hash: tpm2.AlgSHA256,
		})
		if err != nil {
			glog.Fatalf("Error Signing: %v", err)
		}

		glog.V(10).Infof("     Test Signature data:  %s", base64.RawStdEncoding.EncodeToString([]byte(sig.RSA.Signature)))
		verification = []byte(sig.RSA.Signature)

	}

	res := &verifier.PushSecretResponse{
		Uid:          in.Uid,
		Verification: verification,
	}
	return res, nil
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

	tlsConfig = &tls.Config{
		RootCAs:      caCertPool,
		Certificates: []tls.Certificate{serverCerts},
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
