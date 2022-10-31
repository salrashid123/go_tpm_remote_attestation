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
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"strconv"
	"strings"

	"flag"
	"fmt"
	"io"
	"io/ioutil"
	mrnd "math/rand"
	"net"
	"os"
	"sync"
	"time"

	"github.com/salrashid123/go_tpm_registrar/verifier"

	"github.com/golang/glog"

	"golang.org/x/net/context"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"

	"google.golang.org/grpc/status"

	"github.com/google/go-tpm-tools/client"

	tpmpb "github.com/google/go-tpm-tools/proto/tpm"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

var (
	grpcport           = flag.String("grpcport", "", "grpcport")
	caCertTLS          = flag.String("caCertTLS", "certs/CA_crt.pem", "CA Certificate to trust")
	pcr                = flag.String("unsealPcrs", "0,7", "pcrs used to unseal against")
	serverCert         = flag.String("servercert", "certs/attestor_crt.pem", "Server SSL Certificate")
	serverKey          = flag.String("serverkey", "certs/attestor_key.pem", "Server SSL PrivateKey")
	nonces             = make(map[string]string)
	readEventLog       = flag.Bool("readEventLog", false, "Reading Event Log")
	useFullAttestation = flag.Bool("useFullAttestation", false, "Use Attestation")
	platformCertFile   = flag.String("platformCertFile", "certs/platform_cert.der", "Platform Certificate File")
	pcrList            = []int{}
	rwc                io.ReadWriteCloser

	handleNames = map[string][]tpm2.HandleType{
		"all":       []tpm2.HandleType{tpm2.HandleTypeLoadedSession, tpm2.HandleTypeSavedSession, tpm2.HandleTypeTransient},
		"loaded":    []tpm2.HandleType{tpm2.HandleTypeLoadedSession},
		"saved":     []tpm2.HandleType{tpm2.HandleTypeSavedSession},
		"transient": []tpm2.HandleType{tpm2.HandleTypeTransient},
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

	letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
)

const (
	tpmDevice             = "/dev/tpm0"
	encryptionCertNVIndex = 0x01c00002

	emptyPassword   = ""
	importedKeyFile = "importedKey.bin"
	akPubFile       = "akPub.bin"
	akPrivFile      = "akPriv.bin"
	ukPubFile       = "ukPub.bin"
	ukPrivFile      = "ukPriv.bin"
	ekFile          = "ek.bin"

	platformCertNVIndex = 0x01c00006 // i don't know where the platform cert is saved if in NV, this is just a guess
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
	// optionally check for metadata or custom headers
	// md, ok := metadata.FromIncomingContext(ctx)
	// if !ok {
	// 	return nil, grpc.Errorf(codes.Unauthenticated, "could not recall RPC metadata")
	// }
	// newCtx := context.WithValue(ctx, contextKey("someKey"), "someValue")
	// return handler(newCtx, req)

	return handler(ctx, req)
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

	// I just statically generated the platform cert on another sheildedVM with a different EKCert/TPM
	//  i did that since i don't know how to generate and issue a platformcert in golang
	//  but i do know how to issue one win JAVA
	//  so, what i did created a new attribute cert on a different vm but used the same trusted CA to sign it.
	//  the verifer will check the signature but will pretend the EKCert the attestor has has the same static serial number
	// https://github.com/salrashid123/attribute_certificate
	// https://en.wikipedia.org/wiki/Authorization_certificate
	// https://github.com/openssl/openssl/issues/14648
	// 2.1.5 Assertions Made by a Platform Certificate >  https://trustedcomputinggroup.org/wp-content/uploads/IWG_Platform_Certificate_Profile_v1p1_r19_pub_fixed.pdf

	// for now just accept it w/o verifying its claims and move on
	platformCert, err := ioutil.ReadFile(*platformCertFile)
	if err != nil {
		glog.Errorf("ERROR: Unable to load parse platform certificate %v", err)
		return &verifier.GetPlatformCertResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Failed to read platformcert %v", err))
	}
	glog.V(2).Infof("     Returning GetPlatformCert ========")
	return &verifier.GetPlatformCertResponse{
		Uid:          in.Uid,
		PlatformCert: platformCert,
	}, nil
}

func (s *server) Attest(ctx context.Context, in *verifier.AttestRequest) (*verifier.AttestResponse, error) {
	glog.V(2).Infof("======= Attest ========")
	glog.V(5).Infof("     client provided uid: %s", in.Uid)

	if !*useFullAttestation {
		glog.Errorf("     Attestation Called but not enabled for endpoint")
		return &verifier.AttestResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Attest endpoint not enabled"))
	}

	glog.V(10).Infof("     ContextLoad (ek) ========")
	ekhBytes, err := ioutil.ReadFile(ekFile)
	if err != nil {
		glog.Errorf("     ContextLoad failed for ekh: %v", err)
		return &verifier.AttestResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("ContextLoad failed for ekh: %v", err))
	}
	ekh, err := tpm2.ContextLoad(rwc, ekhBytes)
	if err != nil {
		glog.Errorf("     ContextLoad failed for ekhBytes: %v", err)
		return &verifier.AttestResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("ContextLoad failed for ekh: %v", err))
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
		glog.Errorf("     StartAuthSession failed: %v", err)
		return &verifier.AttestResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf(" StartAuthSession failed: %v", err))
	}
	defer tpm2.FlushContext(rwc, loadCreateHandle)

	if _, err := tpm2.PolicySecret(rwc, tpm2.HandleEndorsement, tpm2.AuthCommand{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession}, loadCreateHandle, nil, nil, nil, 0); err != nil {
		glog.Errorf("     Unable to create PolicySecret: %v", err)
		return &verifier.AttestResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Unable to create PolicySecret: %v", err))
	}

	authCommandLoad := tpm2.AuthCommand{Session: loadCreateHandle, Attributes: tpm2.AttrContinueSession}

	glog.V(10).Infof("     Read (akPub) ========")
	akPub, err := ioutil.ReadFile(akPubFile)
	if err != nil {
		glog.Errorf("     Read failed for akPub: %v", err)
		return &verifier.AttestResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Read failed for akPub: %v", err))
	}
	glog.V(10).Infof("     Read (akPriv) ========")
	akPriv, err := ioutil.ReadFile(akPrivFile)
	if err != nil {
		glog.Errorf("     Read failed for akPriv: %v", err)
		return &verifier.AttestResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Read failed for akPriv: %v", err))
	}

	keyHandle, keyName, err := tpm2.LoadUsingAuth(rwc, ekh, authCommandLoad, akPub, akPriv)
	if err != nil {
		glog.Errorf("     LoadUsingAuth failed: : %v", err)
		return &verifier.AttestResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Load failed: %s", err))
	}
	defer tpm2.FlushContext(rwc, keyHandle)
	kn := hex.EncodeToString(keyName)
	glog.V(10).Infof("     AK keyName %s", kn)

	kk, err := client.NewCachedKey(rwc, tpm2.HandleEndorsement, client.AKTemplateRSA(), keyHandle)
	if err != nil {
		glog.Errorf("     NewCachedKey failed: : %v", err)
		return &verifier.AttestResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Load failed for AK: %s", err))
	}
	glog.V(10).Infof("     AK CachedKey Name %s", hex.EncodeToString(kk.Name().Digest.Value))
	attestationBlob, err := kk.Attest(client.AttestOpts{Nonce: []byte(in.Secret)})
	if err != nil {
		glog.Errorf("     Error generating attestation %v", err)
		return &verifier.AttestResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("failed to attest: %v", err))
	}
	buf, err := proto.Marshal(attestationBlob)
	if err != nil {
		glog.Errorf("     Error marshalling attestation failed: : %v", err)
		return &verifier.AttestResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("failed to attest:  Error marshalling attestation %v", err))
	}

	glog.V(2).Infof("     Returning Attest ========")
	return &verifier.AttestResponse{
		Uid:         in.Uid,
		Attestation: buf,
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
		glog.Errorf("ERROR:  could not get EndorsementKeyRSA: %v", err)
		return &verifier.GetEKCertResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("ERROR:  could not get EndorsementKeyRSA: %v", err))
	}
	defer ekk.Close()
	epubKey := ekk.PublicKey().(*rsa.PublicKey)
	ekBytes, err := x509.MarshalPKIXPublicKey(epubKey)
	if err != nil {
		glog.Errorf("ERROR:  could not get MarshalPKIXPublicKey: %v", err)
		return &verifier.GetEKCertResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("ERROR:  could not get MarshalPKIXPublicKey: %v", err))
	}
	ekPubPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: ekBytes,
		},
	)
	glog.V(10).Infof("     Encryption PEM \n%s", string(ekPubPEM))

	tpmEkPub, _, _, err := tpm2.ReadPublic(rwc, ekk.Handle())
	if err != nil {
		return &verifier.GetEKCertResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Error ReadPublic failed: %s", err))
	}

	ekPubBytes, err := tpmEkPub.Encode()
	if err != nil {
		return &verifier.GetEKCertResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Load failed for ekPubBytes: %v", err))
	}

	// now reread the EKEncryption directly from NV
	//   the EKCertificate (x509) is saved at encryptionCertNVIndex
	//   the following steps attempts to read that value in directly from NV
	//   This is currently not supported but i'm adding in code anyway

	ekcertBytes, err = tpm2.NVReadEx(rwc, encryptionCertNVIndex, tpm2.HandleOwner, "", 0)
	if err != nil {
		glog.Errorf("ERROR:   could not get NVReadEx: %v", err)
		return &verifier.GetEKCertResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("ERROR:  could not get NVReadEx: %v", err))
	}

	encCert, err := x509.ParseCertificate(ekcertBytes)
	if err != nil {
		glog.Errorf("ERROR:   ParseCertificate: %v", err)
		return &verifier.GetEKCertResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("ERROR:   ParseCertificate: %v", err))
	}

	glog.V(10).Infof("     Encryption Issuer x509 %s", encCert.Issuer.CommonName)

	glog.V(2).Infof("     Returning GetEKCert")
	return &verifier.GetEKCertResponse{
		Uid:    in.Uid,
		EkCert: encCert.Raw,
		EkPub:  ekPubBytes,
	}, nil
}

func (s *server) GetAK(ctx context.Context, in *verifier.GetAKRequest) (*verifier.GetAKResponse, error) {
	glog.V(2).Infof("======= GetAK ========")
	glog.V(5).Infof("     client provided uid: %s", in.Uid)

	for _, i := range pcrList {
		pcrval, err := tpm2.ReadPCR(rwc, int(i), tpm2.AlgSHA256)
		if err != nil {
			glog.Errorf("ERROR:   Unable to  ReadPCR : %v", err)
			return &verifier.GetAKResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Unable to  ReadPCR : %v", err))
		}
		glog.V(5).Infof("     PCR [%d] Value %v ", i, hex.EncodeToString(pcrval))
	}

	pcrSelection23 := tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: pcrList}
	emptyPassword := ""

	glog.V(10).Infof("     createPrimary")

	// ekh, err := client.EndorsementKeyRSA(rwc)
	// if err != nil {
	// 	glog.Errorf("ERROR:   Unable to create StartAuthSession: %v", err)
	// 	return &verifier.GetAKResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Unable to create StartAuthSession : %v", err))
	// }

	ekh, _, err := tpm2.CreatePrimary(rwc, tpm2.HandleEndorsement, pcrSelection23, emptyPassword, emptyPassword, client.DefaultEKTemplateRSA())
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

	if err != nil {
		glog.Errorf("ERROR:   tpmEkPub.Key() failed %v", err)
		return &verifier.GetAKResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Error tpmEkPub.Key() failed: %s", err))
	}
	glog.V(20).Infof("     tpmEkPub: \n%v", p)

	ekPubBytes, err := tpmEkPub.Encode()
	if err != nil {
		glog.Errorf("ERROR:   Load failed for ekPubBytes: %v", err)
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
		glog.Errorf("ERROR:   Unable to create StartAuthSession: %v", err)
		return &verifier.GetAKResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Unable to create StartAuthSession : %v", err))
	}
	defer tpm2.FlushContext(rwc, sessCreateHandle)

	if _, err := tpm2.PolicySecret(rwc, tpm2.HandleEndorsement, tpm2.AuthCommand{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession}, sessCreateHandle, nil, nil, nil, 0); err != nil {
		glog.Errorf("ERROR:   Unable to create PolicySecret: %v", err)
		return &verifier.GetAKResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Unable to create PolicySecret: %v", err))
	}

	// Alternatively, on GCE
	//  https://pkg.go.dev/github.com/google/go-tpm-tools@v0.3.0-alpha7/client#GceAttestationKeyRSA
	authCommandCreateAuth := tpm2.AuthCommand{Session: sessCreateHandle, Attributes: tpm2.AttrContinueSession}

	akPriv, akPub, creationData, creationHash, creationTicket, err := tpm2.CreateKeyUsingAuth(rwc, ekh, pcrSelection23, authCommandCreateAuth, emptyPassword, client.AKTemplateRSA())
	if err != nil {
		glog.Errorf("ERROR:   CreateKey failed: %s", err)
		return &verifier.GetAKResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("CreateKey failed: %s", err))
	}

	err = tpm2.FlushContext(rwc, sessCreateHandle)
	if err != nil {
		glog.Errorf("ERROR:   Error clearing Session object: %v", err)
		return &verifier.GetAKResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Error clearing Session object: %v", err))
	}

	glog.V(20).Infof("     akPub: %s,", hex.EncodeToString(akPub))
	glog.V(20).Infof("     akPriv: %s,", hex.EncodeToString(akPriv))

	cr, err := tpm2.DecodeCreationData(creationData)
	if err != nil {
		glog.Errorf("ERROR:   Unable to  DecodeCreationData : %v", err)
		return &verifier.GetAKResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Unable to  DecodeCreationData : %v", err))
	}

	glog.V(20).Infof("     CredentialData.ParentName.Digest.Value %s", hex.EncodeToString(cr.ParentName.Digest.Value))
	glog.V(20).Infof("     CredentialTicket %s", hex.EncodeToString(creationTicket.Digest))
	glog.V(20).Infof("     CredentialHash %s", hex.EncodeToString(creationHash))

	glog.V(10).Infof("     ContextSave (ek)")
	ekhBytes, err := tpm2.ContextSave(rwc, ekh)
	if err != nil {
		glog.Errorf("ERROR:   ContextSave failed for ekh: %v", err)
		return &verifier.GetAKResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("ContextSave failed for ekh: %v", err))
	}
	err = ioutil.WriteFile(ekFile, ekhBytes, 0644)
	if err != nil {
		glog.Errorf("ERROR:   ContextWrite failed for ekh: %v", err)
		return &verifier.GetAKResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("ContextWrite failed for ekh: %v", err))
	}
	tpm2.FlushContext(rwc, ekh)

	glog.V(10).Infof("     ContextLoad (ek)")
	ekhBytes, err = ioutil.ReadFile(ekFile)
	if err != nil {
		glog.Errorf("ERROR:   ContextRead failed for ekh: %v", err)
		return &verifier.GetAKResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("ContextRead failed for ekh: %v", err))
	}
	ekh, err = tpm2.ContextLoad(rwc, ekhBytes)
	if err != nil {
		glog.Errorf("ERROR:   ContextLoad failed for ekh: %v", err)
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
		glog.Errorf("ERROR:   Unable to create StartAuthSession : %v", err)
		return &verifier.GetAKResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Unable to create StartAuthSession : %v", err))
	}
	defer tpm2.FlushContext(rwc, loadSession)

	if _, err := tpm2.PolicySecret(rwc, tpm2.HandleEndorsement, tpm2.AuthCommand{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession}, loadSession, nil, nil, nil, 0); err != nil {
		glog.Errorf("ERROR:  Unable to create PolicySecret: %v", err)
		return &verifier.GetAKResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Unable to create PolicySecret: %v", err))
	}

	authCommandLoad := tpm2.AuthCommand{Session: loadSession, Attributes: tpm2.AttrContinueSession}

	keyHandle, keyName, err := tpm2.LoadUsingAuth(rwc, ekh, authCommandLoad, akPub, akPriv)
	if err != nil {
		return &verifier.GetAKResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Load failed: %s", err))
	}
	defer tpm2.FlushContext(rwc, keyHandle)

	err = tpm2.FlushContext(rwc, loadSession)
	if err != nil {
		glog.Errorf("ERROR:   Error clearing Session object: %v", err)
		return &verifier.GetAKResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Error clearing Session object: %v", err))
	}

	kn := hex.EncodeToString(keyName)
	glog.V(5).Infof("     AK keyName %s", kn)

	akPublicKey, akName, _, err := tpm2.ReadPublic(rwc, keyHandle)
	if err != nil {
		glog.Errorf("Error ReadPublic.Key() for AK failed: %s", err)
		return &verifier.GetAKResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Error ReadPublic.Key() for AK failed:: %s", err))
	}

	ap, err := akPublicKey.Key()
	if err != nil {
		glog.Errorf("Error akPublicKey.Key() failed: %s", err)
		return &verifier.GetAKResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Reading AK Key() failed: %s", err))
	}
	akBytes, err := x509.MarshalPKIXPublicKey(ap)
	if err != nil {
		glog.Errorf("Error Unable to convert ak to PublicKeyBytes %v", err)
		return &verifier.GetAKResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Unable to convert ak to PublicKeyBytes: %v", err))
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
		glog.Errorf("ERROR: write failed for akPub: %v", err)
		return &verifier.GetAKResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("write failed for akPub: %v", err))
	}
	glog.V(10).Infof("     Write (akPriv) ========")
	err = ioutil.WriteFile(akPrivFile, akPriv, 0644)
	if err != nil {
		glog.Errorf("ERROR: write failed for akPriv: %v", err)
		return &verifier.GetAKResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("write failed for akPriv: %v", err))
	}
	akPubBytes, err := akPublicKey.Encode()
	if err != nil {
		glog.Errorf("ERROR: Encoding failed for akPubBytes: %v", err)
		return &verifier.GetAKResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Encoding failed for akPubBytes: %v", err))
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
		glog.Errorf("ERROR: ActivateCredential ReadFile failed for ekh:: %v", err)
		return &verifier.ActivateCredentialResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("ReadFile failed for ekh: %v", err))
	}
	ekh, err := tpm2.ContextLoad(rwc, ekhBytes)
	if err != nil {
		glog.Errorf("ERROR: ActivateCredential ContextLoad failed for ekh:: %v", err)
		return &verifier.ActivateCredentialResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("ContextLoad failed for ekh: %v", err))
	}
	defer tpm2.FlushContext(rwc, ekh)

	glog.V(10).Infof("     Read (akPub)")
	akPub, err := ioutil.ReadFile(akPubFile)
	if err != nil {
		glog.Errorf("ERROR: ActivateCredential Readfile failed for akPubFile:: %v", err)
		return &verifier.ActivateCredentialResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("ReadFile failed for akPub: %v", err))
	}
	glog.V(10).Infof("     Read (akPriv)")
	akPriv, err := ioutil.ReadFile(akPrivFile)
	if err != nil {
		glog.Errorf("ERROR: ActivateCredential Readfile failed for akPrivFile:: %v", err)
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
		glog.Errorf("ERROR: ActivateCredential  Unable to create StartAuthSession : %v", err)
		return &verifier.ActivateCredentialResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Unable to create StartAuthSession : %v", err))
	}
	defer tpm2.FlushContext(rwc, loadCreateHandle)

	if _, err := tpm2.PolicySecret(rwc, tpm2.HandleEndorsement, tpm2.AuthCommand{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession}, loadCreateHandle, nil, nil, nil, 0); err != nil {
		glog.Errorf("ERROR: ActivateCredential  Unable to create PolicySecret : %v", err)
		return &verifier.ActivateCredentialResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Unable to create PolicySecret: %v", err))
	}

	authCommandLoad := tpm2.AuthCommand{Session: loadCreateHandle, Attributes: tpm2.AttrContinueSession}

	keyHandle, keyName, err := tpm2.LoadUsingAuth(rwc, ekh, authCommandLoad, akPub, akPriv)
	if err != nil {
		glog.Errorf("ERROR: ActivateCredential  Unable to create LoadUsingAuth : %v", err)
		return &verifier.ActivateCredentialResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf(" Unable to create LoadUsingAuth %s", err))
	}
	defer tpm2.FlushContext(rwc, keyHandle)

	err = tpm2.FlushContext(rwc, loadCreateHandle)
	if err != nil {
		glog.Errorf("ERROR: ActivateCredential  Unable to flush StartAuthSession : %v", err)
		return &verifier.ActivateCredentialResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Unable to create StartAuthSession : %v", err))
	}

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
		glog.Errorf("ERROR: ActivateCredential  Unable to create StartAuthSession : %v", err)
		return &verifier.ActivateCredentialResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Unable to create StartAuthSession : %v", err))
	}
	defer tpm2.FlushContext(rwc, sessActivateCredentialSessHandle1)

	if _, err := tpm2.PolicySecret(rwc, tpm2.HandleEndorsement, tpm2.AuthCommand{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession}, sessActivateCredentialSessHandle1, nil, nil, nil, 0); err != nil {
		glog.Errorf("ERROR: ActivateCredential  Unable to create PolicySecret : %v", err)
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
		glog.Errorf("ERROR: ActivateCredential  Unable to create StartAuthSession : %v", err)
		return &verifier.ActivateCredentialResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Unable to create StartAuthSession : %v", err))
	}
	defer tpm2.FlushContext(rwc, sessActivateCredentialSessHandle2)

	if _, err := tpm2.PolicySecret(rwc, tpm2.HandleEndorsement, tpm2.AuthCommand{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession}, sessActivateCredentialSessHandle2, nil, nil, nil, 0); err != nil {
		glog.Errorf("ERROR: ActivateCredential  Unable to create PolicySecret : %v", err)
		return &verifier.ActivateCredentialResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Unable to create PolicySecret: %v", err))
	}

	authCommandActivate2 := tpm2.AuthCommand{Session: sessActivateCredentialSessHandle2, Attributes: tpm2.AttrContinueSession}

	tl := []tpm2.AuthCommand{authCommandActivate1, authCommandActivate2}

	recoveredCredential1, err := tpm2.ActivateCredentialUsingAuth(rwc, tl, keyHandle, ekh, in.CredBlob, in.EncryptedSecret)
	if err != nil {
		glog.Errorf("ERROR: ActivateCredential  Unable to create ActivateCredentialUsingAuth : %v", err)
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

	for _, i := range pcrList {
		pcrval, err := tpm2.ReadPCR(rwc, int(i), tpm2.AlgSHA256)
		if err != nil {
			glog.Errorf("ERROR:   Unable to  ReadPCR : %v", err)
			return &verifier.QuoteResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Unable to  ReadPCR : %v", err))
		}
		glog.V(5).Infof("     PCR [%d] Value %v ", i, hex.EncodeToString(pcrval))
	}

	pcrSelection23 := tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: pcrList}
	emptyPassword := ""

	glog.V(10).Infof("     ContextLoad (ek) ========")
	ekhBytes, err := ioutil.ReadFile(ekFile)
	if err != nil {
		glog.Errorf("ERROR:   ContextLoad failed for ekh: %v", err)
		return &verifier.QuoteResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("ContextLoad failed for ekh file: %v", err))
	}
	ekh, err := tpm2.ContextLoad(rwc, ekhBytes)
	if err != nil {
		glog.Errorf("ERROR:   ContextLoad failed for ekhBytes: %v", err)
		return &verifier.QuoteResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("ContextLoad failed for ekhBytes: %v", err))
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
		glog.Errorf("ERROR:   Unable to create StartAuthSession : %v", err)
		return &verifier.QuoteResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Unable to create StartAuthSession : %v", err))
	}
	defer tpm2.FlushContext(rwc, loadCreateHandle)

	if _, err := tpm2.PolicySecret(rwc, tpm2.HandleEndorsement, tpm2.AuthCommand{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession}, loadCreateHandle, nil, nil, nil, 0); err != nil {
		glog.Errorf("ERROR:   Unable to create PolicySecret : %v", err)
		return &verifier.QuoteResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Unable to create PolicySecret: %v", err))
	}

	authCommandLoad := tpm2.AuthCommand{Session: loadCreateHandle, Attributes: tpm2.AttrContinueSession}

	glog.V(10).Infof("     Read (akPub) ========")
	akPub, err := ioutil.ReadFile(akPubFile)
	if err != nil {
		glog.Errorf("ERROR:   Read failed for akPub file: %v", err)
		return &verifier.QuoteResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Read failed for akPub file: %v", err))
	}
	glog.V(10).Infof("     Read (akPriv) ========")
	akPriv, err := ioutil.ReadFile(akPrivFile)
	if err != nil {
		glog.Errorf("ERROR:   Read failed for akPriv file: %v", err)
		return &verifier.QuoteResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Read failed for akPriv file: %v", err))
	}

	keyHandle, keyName, err := tpm2.LoadUsingAuth(rwc, ekh, authCommandLoad, akPub, akPriv)
	if err != nil {
		glog.Errorf("ERROR:   LoadUsingAuth failed for ak: %v", err)
		return &verifier.QuoteResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("LoadUsingAuth failed for AK: %s", err))
	}
	defer tpm2.FlushContext(rwc, keyHandle)
	kn := hex.EncodeToString(keyName)
	glog.V(10).Infof("     AK keyName %s", kn)

	attestation, sig, err := tpm2.Quote(rwc, keyHandle, emptyPassword, emptyPassword, []byte(in.Secret), pcrSelection23, tpm2.AlgNull)
	if err != nil {
		glog.Errorf("ERROR:   Failed to quote: %v", err)
		return &verifier.QuoteResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Failed to quote: %s", err))
	}
	glog.V(20).Infof("     Quote Hex %v", hex.EncodeToString(attestation))
	glog.V(20).Infof("     Quote Sig %v", hex.EncodeToString(sig.RSA.Signature))

	evtLog := []byte("")
	if *readEventLog {
		glog.V(20).Infof("     Getting EventLog")
		evtLog, err = client.GetEventLog(rwc)
		if err != nil {
			glog.Errorf("ERROR:   failed to get event log: %v", err)
			return &verifier.QuoteResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("failed to get event log: %v", err))
		}
	}
	glog.V(5).Infof("     <-- End Quote")

	res := &verifier.QuoteResponse{
		Uid:         in.Uid,
		Attestation: attestation,
		Signature:   sig.RSA.Signature,
		Eventlog:    evtLog,
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
		glog.Errorf("ERROR:  Unable to get EndorsementKeyRSA: %v", err)
		return &verifier.PushSecretResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Unable to get EndorsementKeyRSA: %v", err))
	}
	defer ek.Close()

	blob := &tpmpb.ImportBlob{}
	err = proto.Unmarshal(in.ImportBlob, blob)
	if err != nil {
		glog.Errorf("ERROR:  Error Unmarshalling ImportBlob error: %v", err)
		return &verifier.PushSecretResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Error Unmarshalling ImportBlob error: ", err))
	}

	if in.SecretType == verifier.SecretType_AES {

		glog.V(5).Infof("     Importing External Key")
		k, err := ek.Import(blob)
		if err != nil {
			glog.Errorf("ERROR:  Unable to Import sealed data: %v", err)
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
			glog.Errorf("ERROR:  error ImportSigningKey: %v", err)
			return &verifier.PushSecretResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("error ImportSigningKey: %v", err))
		}

		ap := key.PublicKey()
		importedBytes, err := x509.MarshalPKIXPublicKey(ap)
		if err != nil {
			glog.Errorf("ERROR:  Unable to convert akPub:: %v", err)
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
			glog.Errorf("ERROR:  ContextSave failed for keyHandle:: %v", err)
			return &verifier.PushSecretResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("ContextSave failed for keyHandle: %v", err))
		}
		err = ioutil.WriteFile(importedKeyFile, keyBytes, 0644)
		if err != nil {
			glog.Errorf("ERROR:  FileSave ContextSave failed for keyBytes %v", err)
			return &verifier.PushSecretResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("FileSave ContextSave failed for keyBytes: %v", err))
		}
		defer tpm2.FlushContext(rwc, keyHandle)

		glog.V(10).Infof("     Generating Test Signature ========")
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
			glog.Errorf("ERROR:  StartAuthSession failed  %v", err)
			return &verifier.PushSecretResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("StartAuthSession failed: %v", err))
		}
		defer tpm2.FlushContext(rwc, session)

		glog.V(10).Infof("     Data to sign: %s", in.Uid)
		dataToSign := []byte(in.Uid)
		digest := sha256.Sum256(dataToSign)

		if err = tpm2.PolicyPCR(rwc, session, nil, tpm2.PCRSelection{tpm2.AlgSHA256, pcrList}); err != nil {
			glog.Errorf("ERROR:  PolicyPCR failed  %v", err)
			return &verifier.PushSecretResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("PolicyPCR failed: %v", err))
		}
		sig, err := tpm2.SignWithSession(rwc, session, keyHandle, emptyPassword, digest[:], nil, &tpm2.SigScheme{
			Alg:  tpm2.AlgRSASSA,
			Hash: tpm2.AlgSHA256,
		})
		if err != nil {
			glog.Errorf("ERROR:  Signing  failed  %v", err)
			return &verifier.PushSecretResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Signing  failed : %v", err))
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

// Returns a Public key and signature for a file that is associated with
func (s *server) PullRSAKey(ctx context.Context, in *verifier.PullRSAKeyRequest) (*verifier.PullRSAKeyResponse, error) {
	glog.V(2).Infof("======= PullRSAKey ========")
	glog.V(5).Infof("     client provided uid: %s", in.Uid)

	glog.V(5).Infof("======= Generate UnrestrictedKey ========")

	glog.V(10).Infof("     ContextLoad (ek) ========")
	ekhBytes, err := ioutil.ReadFile(ekFile)
	if err != nil {
		glog.Errorf("ERROR:  ReadFile failed for ekh: %v", err)
		return &verifier.PullRSAKeyResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("ReadFile failed for ekh: %v", err))
	}
	ekh, err := tpm2.ContextLoad(rwc, ekhBytes)
	if err != nil {
		glog.Errorf("ERROR:  ContextLoad failed for ekh: %v", err)
		return &verifier.PullRSAKeyResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("ContextLoad failed for ekh: %v", err))
	}
	defer tpm2.FlushContext(rwc, ekh)

	glog.V(5).Infof("     Loading AttestationKey")
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
		glog.Errorf("ERROR:  Unable to create StartAuthSession  %v", err)
		return &verifier.PullRSAKeyResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Unable to create StartAuthSession : %v", err))
	}
	defer tpm2.FlushContext(rwc, loadCreateHandle)

	if _, err := tpm2.PolicySecret(rwc, tpm2.HandleEndorsement, tpm2.AuthCommand{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession}, loadCreateHandle, nil, nil, nil, 0); err != nil {
		glog.Errorf("ERROR:  Unable to create PolicySecret  %v", err)
		return &verifier.PullRSAKeyResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Unable to create PolicySecret: %v", err))
	}

	authCommandLoad := tpm2.AuthCommand{Session: loadCreateHandle, Attributes: tpm2.AttrContinueSession}

	akPub, err := ioutil.ReadFile(akPubFile)
	if err != nil {
		glog.Errorf("ERROR:  ReadFile failed for akPub:  %v", err)
		return &verifier.PullRSAKeyResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("ReadFile failed for akPub: %v", err))
	}

	akPriv, err := ioutil.ReadFile(akPrivFile)
	if err != nil {
		glog.Errorf("ERROR:  ReadFile failed for akPriv:  %v", err)
		return &verifier.PullRSAKeyResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Readfile failed for akPriv: %v", err))
	}

	aKkeyHandle, keyName, err := tpm2.LoadUsingAuth(rwc, ekh, authCommandLoad, akPub, akPriv)
	defer tpm2.FlushContext(rwc, aKkeyHandle)
	if err != nil {
		glog.Errorf("ERROR:  LoadUsingAuth failed for AK:  %v", err)
		return &verifier.PullRSAKeyResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("LoadUsingAuth AK failed: %s", err))
	}
	glog.V(5).Infof("     AK keyName: %s,", base64.StdEncoding.EncodeToString(keyName))

	tpm2.FlushContext(rwc, loadCreateHandle)

	tPub, err := tpm2.DecodePublic(akPub)
	if err != nil {
		glog.Errorf("ERROR:  DecodePublic failed for AK:  %v", err)
		return &verifier.PullRSAKeyResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Error DecodePublic AK %v", tPub))
	}

	ap, err := tPub.Key()
	if err != nil {
		glog.Errorf("ERROR:  akPub.key() failed for AK:  %v", err)
		return &verifier.PullRSAKeyResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("akPub.Key() failed: %s", err))
	}
	akBytes, err := x509.MarshalPKIXPublicKey(ap)
	if err != nil {
		glog.Errorf("ERROR:  MarshalPKIXPublicKey failed for AK:  %v", err)
		return &verifier.PullRSAKeyResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("MarshalPKIXPublicKey failed for akPub: %v", err))
	}
	akPubPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: akBytes,
		},
	)

	glog.V(10).Infof("     akPub PEM \n%s", string(akPubPEM))

	// Create Child of AK that is Unrestricted (does not have tpm2.FlagRestricted)
	// Under endorsement handle
	glog.V(5).Infof("     ======= CreateKeyUsingAuthUnrestricted ========")

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
		glog.Errorf("ERROR:  StartAuthSession failed  %v", err)
		return &verifier.PullRSAKeyResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Unable to create StartAuthSession : %v", err))
	}
	defer tpm2.FlushContext(rwc, sessCreateHandle)

	// if err = tpm2.PolicyPCR(rwc, sessCreateHandle, nil, pcrSelection23); err != nil {
	// 	log.Fatalf("PolicyPCR failed: %v", err)
	// }

	if _, err := tpm2.PolicySecret(rwc, tpm2.HandleEndorsement, tpm2.AuthCommand{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession}, sessCreateHandle, nil, nil, nil, 0); err != nil {
		glog.Errorf("ERROR:  PolicySecret failed  %v", err)
		return &verifier.PullRSAKeyResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Unable to create PolicySecret: %v", err))
	}
	authCommandCreateAuth := tpm2.AuthCommand{Session: sessCreateHandle, Attributes: tpm2.AttrContinueSession}

	for _, i := range pcrList {
		pcrval, err := tpm2.ReadPCR(rwc, int(i), tpm2.AlgSHA256)
		if err != nil {
			glog.Errorf("ERROR:   Unable to  ReadPCR : %v", err)
			return &verifier.PullRSAKeyResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Unable to  ReadPCR : %v", err))
		}
		glog.V(5).Infof("     PCR [%d] Value %v ", i, hex.EncodeToString(pcrval))
	}

	pcrSelection23 := tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: pcrList}

	// what i'd really want is a child key of aKkeyHandle but there's some policy i'm missing
	// error code 0x1d : a policy check failed exit status 1
	//ukPriv, ukPub, _, _, _, err := tpm2.CreateKey(rwc, aKkeyHandle, pcrSelection23, emptyPassword, emptyPassword, unrestrictedKeyParams)

	ukPriv, ukPub, _, _, _, err := tpm2.CreateKeyUsingAuth(rwc, ekh, pcrSelection23, authCommandCreateAuth, emptyPassword, unrestrictedKeyParams)

	if err != nil {
		glog.Errorf("ERROR:  CreateKeyUsingAuth for unrestricted key failed: %v", err)
		return &verifier.PullRSAKeyResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("CreateKeyUsingAuth for unrestricted key failed: %s", err))
	}
	glog.V(20).Infof("     Unrestricted ukPub: %v,", hex.EncodeToString(ukPub))
	glog.V(20).Infof("     Unrestricted ukPriv: %v,", hex.EncodeToString(ukPriv))

	glog.V(10).Infof("     Write (ukPub) ========")
	err = ioutil.WriteFile(ukPubFile, ukPub, 0644)
	if err != nil {
		glog.Errorf("ERROR:  WriteFile for unrestricted ukPub failed: %v", err)
		return &verifier.PullRSAKeyResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("WriteFile failed for ukPub: %v", err))
	}
	glog.V(10).Infof("     Write (ukPriv) ========")
	err = ioutil.WriteFile(ukPrivFile, ukPriv, 0644)
	if err != nil {
		glog.Errorf("ERROR:  WriteFile for unrestricted ukPriv failed: %v", err)
		return &verifier.PullRSAKeyResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Save failed for ukPriv: %v", err))
	}

	tpm2.FlushContext(rwc, sessCreateHandle)

	// Load the unrestricted key
	sessLoadHandle, _, err := tpm2.StartAuthSession(
		rwc,
		tpm2.HandleNull,
		tpm2.HandleNull,
		make([]byte, 16),
		nil,
		tpm2.SessionPolicy,
		tpm2.AlgNull,
		tpm2.AlgSHA256)
	if err != nil {
		glog.Errorf("ERROR:  Unable to create StartAuthSession: %v", err)
		return &verifier.PullRSAKeyResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Unable to create StartAuthSession : %v", err))
	}
	defer tpm2.FlushContext(rwc, sessLoadHandle)

	if _, err := tpm2.PolicySecret(rwc, tpm2.HandleEndorsement, tpm2.AuthCommand{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession}, sessLoadHandle, nil, nil, nil, 0); err != nil {
		glog.Errorf("ERROR:  Unable to create PolicySecret: %v", err)
		return &verifier.PullRSAKeyResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Unable to create PolicySecret: %v", err))
	}
	authCommandLoad = tpm2.AuthCommand{Session: sessLoadHandle, Attributes: tpm2.AttrContinueSession}

	ukeyHandle, ukeyName, err := tpm2.LoadUsingAuth(rwc, ekh, authCommandLoad, ukPub, ukPriv)
	if err != nil {
		glog.Errorf("ERROR: LoadUsingAuth failed for unrestricted key: %v", err)
		return &verifier.PullRSAKeyResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("LoadUsingAuth failed for unrestricted key %s", err))
	}
	defer tpm2.FlushContext(rwc, ukeyHandle)
	glog.V(20).Infof("     ukeyName: %v,", base64.StdEncoding.EncodeToString(ukeyName))

	utPub, err := tpm2.DecodePublic(ukPub)
	if err != nil {
		glog.Errorf("ERROR: DecodePublic failed for unrestricted key: %v", err)
		return &verifier.PullRSAKeyResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Error DecodePublic AK %v", utPub))
	}

	uap, err := utPub.Key()
	if err != nil {
		glog.Errorf("ERROR:  failed to get utPub.Key() for unrestricted key: %v", err)
		return &verifier.PullRSAKeyResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("akPub.Key() failed: %s", err))
	}
	uBytes, err := x509.MarshalPKIXPublicKey(uap)
	if err != nil {
		glog.Errorf("ERROR:  failed to MarshalPKIXPublicKey for unrestricted key: %v", err)
		return &verifier.PullRSAKeyResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Unable to convert akPub to MarshalPKIXPublicKey: %v", err))
	}

	ukPubPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: uBytes,
		},
	)

	glog.V(10).Infof("     uakPub PEM \n%s", string(ukPubPEM))

	// Certify the Unrestricted key using the AK
	// override tpm2.Certify until https://github.com/google/go-tpm/issues/262 is fixed
	attestation, csig, err := Certify(rwc, emptyPassword, emptyPassword, ukeyHandle, aKkeyHandle, nil)
	//attestation, csig, err := tpm2.Certify(rwc, emptyPassword, emptyPassword, ukeyHandle, aKkeyHandle, nil)
	if err != nil {
		glog.Errorf("ERROR:  failed to Certify for unrestricted key: %v", err)
		return &verifier.PullRSAKeyResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("failed to Certify for unrestricted key: %s", err))
	}
	glog.V(20).Infof("     Certify Attestation: %v,", hex.EncodeToString(attestation))
	glog.V(20).Infof("     Certify Signature: %v,", hex.EncodeToString(csig))
	tpm2.FlushContext(rwc, sessLoadHandle)

	// // Now Sign some arbitrary data with the unrestricted Key

	glog.V(10).Infof("     Data to sign: %s", in.Uid)
	dataToSign := []byte(in.Uid)
	digest, hashValidation, err := tpm2.Hash(rwc, tpm2.AlgSHA256, dataToSign, tpm2.HandleOwner)
	if err != nil {
		glog.Errorf("ERROR:  Hash failed unexpectedly: %v", err)
		return &verifier.PullRSAKeyResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Hash failed unexpectedly: %v", err))
	}

	sig, err := tpm2.Sign(rwc, ukeyHandle, "", digest[:], hashValidation, &tpm2.SigScheme{
		Alg:  tpm2.AlgRSASSA,
		Hash: tpm2.AlgSHA256,
	})
	if err != nil {
		glog.Errorf("ERROR: Error Signing:: %v", err)
		return &verifier.PullRSAKeyResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Error Signing: %v", err))
	}
	glog.V(10).Infof("     Test Signature:  %s", base64.RawStdEncoding.EncodeToString([]byte(sig.RSA.Signature)))

	// Verify the Certification value:
	glog.V(20).Infof("     Read and Decode (attestion)")
	att, err := tpm2.DecodeAttestationData(attestation)
	if err != nil {
		glog.Errorf("ERROR: Error DecodeAttestationData:: %v", err)
		return &verifier.PullRSAKeyResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("DecodeAttestationData(%v) failed: %v", attestation, err))
	}

	ablock, _ := pem.Decode(ukPubPEM)
	if ablock == nil {
		glog.Errorf("ERROR: Error pem.Decode : %v", err)
		return &verifier.PullRSAKeyResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Unable to decode akPubPEM %v", err))
	}

	rra, err := x509.ParsePKIXPublicKey(ablock.Bytes)
	if err != nil {
		glog.Errorf("ERROR: Error ParsePKIXPublicKey: %v", err)
		return &verifier.PullRSAKeyResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Unable to create rsa Key from PEM %v", err))
	}
	arsaPub := *rra.(*rsa.PublicKey)

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
			ModulusRaw: arsaPub.N.Bytes(),
		},
	}
	ok, err := att.AttestedCertifyInfo.Name.MatchesPublic(params)
	if err != nil {
		glog.Errorf("ERROR: unrestricted key does not math tpm template parameters: %v", err)
		return &verifier.PullRSAKeyResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("unrestricted key does not math tpm template parameters:  %v", attestation, err))
	}
	glog.V(20).Infof("     Attestation : MatchesPublic %v", ok)
	glog.V(20).Infof("     Attestation att.AttestedCertifyInfo.Name: %s", base64.StdEncoding.EncodeToString(att.AttestedCertifyInfo.Name.Digest.Value))

	sigL := tpm2.SignatureRSA{
		HashAlg:   tpm2.AlgSHA256,
		Signature: csig,
	}

	// Verify signature of Attestation by using the PEM Public key for AK
	glog.V(10).Infof("     Decoding PublicKey for AK ========")

	block, _ := pem.Decode(akPubPEM)
	if block == nil {
		glog.Errorf("ERROR: Unable to decode akPubPEM: %v", err)
		return &verifier.PullRSAKeyResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Unable to decode akPubPEM %v", err))
	}

	r, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		glog.Errorf("ERROR: Unable to decode akPubPEM ParsePKIXPublicKey: %v", err)
		return &verifier.PullRSAKeyResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Unable to create rsa Key from PEM %v", err))
	}
	rsaPub := *r.(*rsa.PublicKey)

	// p, err := tpm2.DecodePublic(akPub)
	// if err != nil {
	// 	log.Fatalf("DecodePublic failed: %v", err)
	// }
	// rsaPub := rsa.PublicKey{E: int(p.RSAParameters.Exponent()), N: p.RSAParameters.Modulus()}
	// rsaPub = *ap.(*rsa.PublicKey)

	hsh := crypto.SHA256.New()
	hsh.Write(attestation)

	if err := rsa.VerifyPKCS1v15(&rsaPub, crypto.SHA256, hsh.Sum(nil), sigL.Signature); err != nil {
		glog.Errorf("ERROR: local cert verification failedVerifyPKCS1v15: %v", err)
		return &verifier.PullRSAKeyResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("VerifyPKCS1v15 failed: %v", err))
	}
	glog.V(10).Infof("     Signature Verified")

	ukPubEncoded, err := utPub.Encode()
	if err != nil {
		glog.Errorf("ERROR: Failed to extract TPM Wireformat for unrestricted key: %v", err)
		return &verifier.PullRSAKeyResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Failed to extract TPM Wireformat for unrestricted key: %v", err))
	}

	res := &verifier.PullRSAKeyResponse{
		Uid:                  in.Uid,
		TpmPublicKey:         ukPubEncoded,
		TestSignature:        []byte(sig.RSA.Signature),
		AttestationSignature: csig,
		Attestation:          attestation,
	}
	glog.V(10).Infof("     Returning PullRSAKeyResponse")
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

	// init the pcrs to use
	for _, v := range strings.Split(*pcr, ",") {
		i, err := strconv.Atoi(v)
		if err != nil {
			glog.Fatalf("Unable to  convert pcr to int : %v", err)
		}
		pcrList = append(pcrList, int(i))
	}

	var tlsConfig *tls.Config
	ca, err := ioutil.ReadFile(*caCertTLS)
	if err != nil {
		glog.Fatalf("Faild to read CA Certificate file %s: %v", *caCertTLS, err)
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

/// *************************
//  The rest of this file is just code copied from go-tpm and overrides the
//  tpm2.Certify() call due to  https://github.com/google/go-tpm/issues/262

func Certify(rw io.ReadWriter, objectAuth, signerAuth string, object, signer tpmutil.Handle, qualifyingData []byte) ([]byte, []byte, error) {
	cmd, err := encodeCertify(objectAuth, signerAuth, object, signer, qualifyingData)
	if err != nil {
		return nil, nil, err
	}
	resp, err := runCommand(rw, tpm2.TagSessions, tpm2.CmdCertify, tpmutil.RawBytes(cmd))
	if err != nil {
		return nil, nil, err
	}
	return decodeCertify(resp)
}

// SigScheme represents a signing scheme.
type SigScheme struct {
	Alg   tpm2.Algorithm
	Hash  tpm2.Algorithm
	Count uint32
}

func (s *SigScheme) encode() ([]byte, error) {
	if s == nil || s.Alg.IsNull() {
		return tpmutil.Pack(tpm2.AlgNull)
	}
	if s.Alg.UsesCount() {
		return tpmutil.Pack(s.Alg, s.Hash, s.Count)
	}
	return tpmutil.Pack(s.Alg, s.Hash)
}

func encodeCertify(objectAuth, signerAuth string, object, signer tpmutil.Handle, qualifyingData tpmutil.U16Bytes) ([]byte, error) {
	ha, err := tpmutil.Pack(object, signer)
	if err != nil {
		return nil, err
	}

	auth, err := encodeAuthArea(tpm2.AuthCommand{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession, Auth: []byte(objectAuth)}, tpm2.AuthCommand{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession, Auth: []byte(signerAuth)})
	if err != nil {
		return nil, err
	}

	scheme := SigScheme{Alg: tpm2.AlgRSASSA, Hash: tpm2.AlgSHA256}
	// Use signing key's scheme.
	s, err := scheme.encode()
	if err != nil {
		return nil, err
	}
	data, err := tpmutil.Pack(qualifyingData)
	if err != nil {
		return nil, err
	}
	return concat(ha, auth, data, s)
}

func runCommand(rw io.ReadWriter, tag tpmutil.Tag, Cmd tpmutil.Command, in ...interface{}) ([]byte, error) {
	resp, code, err := tpmutil.RunCommand(rw, tag, Cmd, in...)
	if err != nil {
		return nil, err
	}
	if code != tpmutil.RCSuccess {
		return nil, decodeResponse(code)
	}
	return resp, decodeResponse(code)
}

func decodeResponse(code tpmutil.ResponseCode) error {
	if code == tpmutil.RCSuccess {
		return nil
	}
	if code&0x180 == 0 { // Bits 7:8 == 0 is a TPM1 error
		return fmt.Errorf("response status 0x%x", code)
	}
	if code&0x80 == 0 { // Bit 7 unset
		if code&0x400 > 0 { // Bit 10 set, vendor specific code
			return tpm2.VendorError{uint32(code)}
		}
		if code&0x800 > 0 { // Bit 11 set, warning with code in bit 0:6
			return tpm2.Warning{tpm2.RCWarn(code & 0x7f)}
		}
		// error with code in bit 0:6
		return tpm2.Error{tpm2.RCFmt0(code & 0x7f)}
	}
	if code&0x40 > 0 { // Bit 6 set, code in 0:5, parameter number in 8:11
		return tpm2.ParameterError{tpm2.RCFmt1(code & 0x3f), tpm2.RCIndex((code & 0xf00) >> 8)}
	}
	if code&0x800 == 0 { // Bit 11 unset, code in 0:5, handle in 8:10
		return tpm2.HandleError{tpm2.RCFmt1(code & 0x3f), tpm2.RCIndex((code & 0x700) >> 8)}
	}
	// Code in 0:5, Session in 8:10
	return tpm2.SessionError{tpm2.RCFmt1(code & 0x3f), tpm2.RCIndex((code & 0x700) >> 8)}
}

func decodeCertify(resp []byte) ([]byte, []byte, error) {
	var paramSize uint32
	var attest, signature tpmutil.U16Bytes
	var sigAlg, hashAlg tpm2.Algorithm

	buf := bytes.NewBuffer(resp)
	if err := tpmutil.UnpackBuf(buf, &paramSize); err != nil {
		return nil, nil, err
	}
	buf.Truncate(int(paramSize))
	if err := tpmutil.UnpackBuf(buf, &attest, &sigAlg); err != nil {
		return nil, nil, err
	}
	// If sigAlg is AlgNull, there will be no hashAlg or signature.
	// This will happen if AlgNull was passed in the Certify() as
	// the signing key (no need to sign the response).
	// See TPM2 spec part4 pg227 SignAttestInfo()
	if sigAlg != tpm2.AlgNull {
		if sigAlg == tpm2.AlgECDSA {
			var r, s tpmutil.U16Bytes
			if err := tpmutil.UnpackBuf(buf, &hashAlg, &r, &s); err != nil {
				return nil, nil, err
			}
			signature = append(r, s...)
		} else {
			if err := tpmutil.UnpackBuf(buf, &hashAlg, &signature); err != nil {
				return nil, nil, err
			}
		}
	}
	return attest, signature, nil
}

func encodeAuthArea(sections ...tpm2.AuthCommand) ([]byte, error) {
	var res tpmutil.RawBytes
	for _, s := range sections {
		buf, err := tpmutil.Pack(s)
		if err != nil {
			return nil, err
		}
		res = append(res, buf...)
	}

	size, err := tpmutil.Pack(uint32(len(res)))
	if err != nil {
		return nil, err
	}

	return concat(size, res)
}

func concat(chunks ...[]byte) ([]byte, error) {
	return bytes.Join(chunks, nil), nil
}
