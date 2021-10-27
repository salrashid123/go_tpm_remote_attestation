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
	"context"
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
	"log"
	"time"

	pb "github.com/salrashid123/go_tpm_registrar/verifier"

	"github.com/golang/glog"
	"github.com/google/go-tpm-tools/client"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"github.com/google/uuid"
	"google.golang.org/grpc"

	"github.com/golang/protobuf/proto"
	tpmpb "github.com/google/go-tpm-tools/proto/tpm"
	"google.golang.org/grpc/credentials"

	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

const (
	defaultRSAExponent = 1<<16 + 1
	targetAudience     = "grpc://verify.esodemoapp2.com"
	tpmDevice          = "/dev/tpm0"
	emptyPassword      = ""
	importedKeyFile    = "importedKey.bin"
	akPubFile          = "akPub.bin"
	akPrivFile         = "akPriv.bin"
	ekFile             = "ek.bin"
	ukPubFile          = "ukPub.bin"
	ukPrivFile         = "ukPriv.bin"

	signCertNVIndex       = 0x01c10000
	signKeyNVIndex        = 0x01c10001
	encryptionCertNVIndex = 0x01c00002
)

var (
	rwc        io.ReadWriteCloser
	importMode = flag.String("importMode", "AES", "RSA|AES")
	pcr        = flag.Int("unsealPcr", 0, "pcr value to unseal against")
	caCert     = flag.String("cacert", "certs/CA_crt.pem", "CA Certificate to trust")

	clientCert      = flag.String("clientcert", "certs/client_crt.pem", "Client SSL Certificate")
	clientKey       = flag.String("clientkey", "certs/client_key.pem", "Client SSL PrivateKey")
	usemTLS         = flag.Bool("usemTLS", true, "Validate original client request with mTLS")
	readCertsFromNV = flag.Bool("readCertsFromNV", true, "Try to read read certificates from NV")

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

func main() {

	address := flag.String("host", "verify.esodemoapp2.com:50051", "host:port of gRPC server")
	u := flag.String("uid", uuid.New().String(), "uid of client")
	flag.Parse()

	var err error
	rwc, err = tpm2.OpenTPM(tpmDevice)
	if err != nil {
		glog.Fatalf("can't open TPM %q: %v", tpmDevice, err)
	}
	defer func() {
		if err := rwc.Close(); err != nil {
			glog.Fatalf("%v\ncan't close TPM: %v", tpmDevice, err)
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
			log.Printf("Handle 0x%x flushed\n", handle)
			totalHandles++
		}
	}

	var tlsCfg tls.Config
	rootCAs := x509.NewCertPool()
	ca_pem, err := ioutil.ReadFile(*caCert)
	if err != nil {
		glog.Fatalf("failed to load root CA certificates  error=%v", err)
	}
	if !rootCAs.AppendCertsFromPEM(ca_pem) {
		glog.Fatalf("no root CA certs parsed from file ")
	}
	tlsCfg.RootCAs = rootCAs
	tlsCfg.ServerName = "verify.esodemoapp2.com"

	if *usemTLS {
		glog.V(2).Infof("Using mTLS")
		certificate, err := tls.LoadX509KeyPair(*clientCert, *clientKey)
		if err != nil {
			glog.Fatalf("could not load client key pair: %s", err)
		}
		tlsCfg.Certificates = []tls.Certificate{certificate}
	}

	ce := credentials.NewTLS(&tlsCfg)

	ctx := context.Background()

	conn, err := grpc.Dial(*address, grpc.WithTransportCredentials(ce))
	if err != nil {
		glog.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()

	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	resp, err := healthpb.NewHealthClient(conn).Check(ctx, &healthpb.HealthCheckRequest{Service: "verifier.VerifierServer"})
	if err != nil {
		glog.Fatalf("HealthCheck failed %+v", err)
	}

	if resp.GetStatus() != healthpb.HealthCheckResponse_SERVING {
		log.Fatalf("service not in serving state: ", resp.GetStatus().String())
	}
	glog.V(2).Infof("RPC HealthChekStatus:%v", resp.GetStatus())

	// Try to read the AK/EK Certificates

	// First acquire the AK, EK keys, certificates from NV

	glog.V(5).Infof("=============== Load EncryptionKey and Certifcate from NV ===============")
	ekk, err := client.EndorsementKeyRSA(rwc)
	if err != nil {
		glog.Errorf("ERROR:  could not get EndorsementKeyRSA: %v", err)
		return
	}
	epubKey := ekk.PublicKey().(*rsa.PublicKey)
	ekBytes, err := x509.MarshalPKIXPublicKey(epubKey)
	if err != nil {
		glog.Errorf("ERROR:  could not get MarshalPKIXPublicKey: %v", err)
		return
	}
	ekPubPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: ekBytes,
		},
	)
	glog.V(10).Infof("     Encryption PEM \n%s", string(ekPubPEM))
	ekk.Close()

	// now reread the EKCert directly from NV
	//   the EKCertificate (x509) is saved at encryptionCertNVIndex
	//   the following steps attempts to read that value in directly from NV
	//   This is currently not supported but i'm adding in code anyway

	ekcertBytes, err := tpm2.NVReadEx(rwc, encryptionCertNVIndex, tpm2.HandleOwner, "", 0)
	if err != nil {
		glog.Errorf("ERROR:  could not get NVReadEx: %v", err)
		return
	}

	encCert, err := x509.ParseCertificate(ekcertBytes)
	if err != nil {
		glog.Errorf("ERROR:   ParseCertificate: %v", err)
		return
	}
	// https://pkg.go.dev/github.com/google/certificate-transparency-go/x509
	glog.V(10).Infof("     EKCert Encryption Issuer x509 \n%v", encCert.Issuer)

	// GCE VMs saves a signed AKCert to NV, w'ere commenting this out
	// glog.V(10).Infof("     Load SigningKey and Certifcate ")
	// kk, err := client.EndorsementKeyFromNvIndex(rwc, signKeyNVIndex)
	// if err != nil {
	// 	glog.Errorf("ERROR:  could not get EndorsementKeyFromNvIndex: %v", err)
	// 	return
	// }
	// pubKey := kk.PublicKey().(*rsa.PublicKey)
	// akBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	// if err != nil {
	// 	glog.Errorf("ERROR:  could not get MarshalPKIXPublicKey: %v", err)
	// 	return
	// }
	// akPubPEM := pem.EncodeToMemory(
	// 	&pem.Block{
	// 		Type:  "PUBLIC KEY",
	// 		Bytes: akBytes,
	// 	},
	// )
	// glog.V(10).Infof("     Signing PEM \n%s", string(akPubPEM))
	// kk.Close()

	// glog.V(5).Infof("     Signing PEM from NV \n[%s]", string(skPubPEM))

	c := pb.NewVerifierClient(conn)

	glog.V(5).Infof("=============== MakeCredential ===============")
	akName, ekPub, akPub, err := createKeys()
	if err != nil {
		glog.Fatalf("Unable to generate EK/AK: %v", err)
	}
	req := &pb.MakeCredentialRequest{
		Uid:    *u,
		AkName: akName,
		EkCert: ekcertBytes,
		EkPub:  ekPub,
		AkPub:  akPub,
	}

	r, err := c.MakeCredential(ctx, req)
	if err != nil {
		glog.Fatalf("Error MakeCredential: %v", err)
	}
	time.Sleep(1 * time.Second)
	glog.V(5).Infof("     MakeCredential RPC Response with provided uid [%s]", r.Uid)

	glog.V(5).Infof("=============== ActivateCredential  ===============")
	secret, err := activateCredential(r.Uid, r.CredBlob, r.EncryptedSecret)
	if err != nil {
		glog.Fatalf("could not activateCredential: %v", err)
	}

	areq := &pb.ActivateCredentialRequest{
		Uid:    *u,
		Secret: secret,
	}
	glog.V(5).Infof("    Activate Credential Secret %s", secret)
	ar, err := c.ActivateCredential(ctx, areq)
	if err != nil {
		glog.Fatalf("could not call ActivateCredential: %v", err)
	}
	glog.V(5).Infof("    Activate Credential Status %t", ar.Verified)

	glog.V(5).Infof("=============== GetSecret  ===============")
	sreq := &pb.GetSecretRequest{
		Uid: *u,
	}

	asr, err := c.GetSecret(ctx, sreq)
	if err != nil {
		glog.Fatalf("could not call GetSecret: %v", err)
	}

	if *importMode == "RSA" {
		glog.V(5).Infof("===============  Importing sealed RSA Key ===============")
		err = importRSAKey(*asr)
		if err != nil {
			glog.Fatalf("Unable to Import RSA Key: %v", err)
		}
	} else if *importMode == "AES" {
		glog.V(5).Infof("===============  Importing sealed AES Key ===============")
		secret, err := importKey(*asr)
		if err != nil {
			glog.Fatalf("Unable to Import AES Key: %v", err)
		}
		glog.V(5).Infof("     Unsealed Secret %s", secret)
	} else {
		glog.Fatalln("importMode must be either RSA or AES")
	}

	glog.V(5).Infof("=============== OfferQuote ===============")

	aqr := &pb.OfferQuoteRequest{
		Uid: *u,
	}
	qr, err := c.OfferQuote(ctx, aqr)
	if err != nil {
		glog.Fatalf("could not call OfferQuote: %v", err)
	}
	glog.V(5).Infof("     Quote Requested with nonce %s, pcr: %d", qr.Nonce, qr.Pcr)

	glog.V(5).Infof("=============== Generating Quote ===============")
	att, sig, evtLog, err := quote(int(qr.Pcr), qr.Nonce)
	if err != nil {
		glog.Fatalf("could not create Quote: %v", err)
	}
	glog.V(5).Infof("=============== Providing Quote ===============")
	pqr := &pb.ProvideQuoteRequest{
		Uid:         *u,
		Attestation: att,
		Signature:   sig,
		Eventlog:    evtLog,
	}
	pqesp, err := c.ProvideQuote(ctx, pqr)
	if err != nil {
		glog.Fatalf("could not provideQuote: %v", err)
	}
	glog.V(5).Infof("     Provided Quote verified: %t", pqesp.Verified)

	glog.V(5).Infof("=============== Offer CSR ===============")

	uPubKey, csr, attestationSignature, attestationBytes, err := generateCSR("client.domain.com", "client.domain.com")
	if err != nil {
		glog.Fatalf("Unable to generate CSR: %v", err)
	}
	csrR := &pb.OfferCSRRequest{
		Uid:                  *u,
		PublicKey:            uPubKey,
		Csr:                  csr,
		AttestationSignature: attestationSignature,
		Attestation:          attestationBytes,
	}

	oCSR, err := c.OfferCSR(ctx, csrR)
	if err != nil {
		glog.Fatalf("could not call OfferCSR: %v", err)
	}

	signedCert := pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: oCSR.Cert,
		},
	)

	glog.V(10).Infof("     X509 issued by Verifier for unrestricted Key: \n%v", string(signedCert))

}

func generateCSR(cn, san string) (publicKey []byte, csr []byte, attestationSignature []byte, attestation []byte, err error) {

	glog.V(5).Infof("     ======= CreateKeyUsingAuthUnrestricted ========")

	glog.V(10).Infof("     ContextLoad (ek)")
	ekhBytes, err := ioutil.ReadFile(ekFile)
	if err != nil {
		return []byte(""), []byte(""), []byte(""), []byte(""), fmt.Errorf("ContextLoad failed for ekh: %v", err)
	}
	ekh, err := tpm2.ContextLoad(rwc, ekhBytes)
	if err != nil {
		return []byte(""), []byte(""), []byte(""), []byte(""), fmt.Errorf("ContextLoad failed for ekh: %v", err)
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
		return []byte(""), []byte(""), []byte(""), []byte(""), fmt.Errorf("Unable to create StartAuthSession : %v", err)
	}
	defer tpm2.FlushContext(rwc, loadCreateHandle)

	if _, err := tpm2.PolicySecret(rwc, tpm2.HandleEndorsement, tpm2.AuthCommand{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession}, loadCreateHandle, nil, nil, nil, 0); err != nil {
		return []byte(""), []byte(""), []byte(""), []byte(""), fmt.Errorf("Unable to create PolicySecret: %v", err)
	}

	authCommandLoad := tpm2.AuthCommand{Session: loadCreateHandle, Attributes: tpm2.AttrContinueSession}

	akPub, err := ioutil.ReadFile(akPubFile)
	if err != nil {
		return []byte(""), []byte(""), []byte(""), []byte(""), fmt.Errorf("Read failed for akPub: %v", err)
	}

	akPriv, err := ioutil.ReadFile(akPrivFile)
	if err != nil {
		return []byte(""), []byte(""), []byte(""), []byte(""), fmt.Errorf("Read failed for akPriv: %v", err)
	}

	aKkeyHandle, keyName, err := tpm2.LoadUsingAuth(rwc, ekh, authCommandLoad, akPub, akPriv)
	defer tpm2.FlushContext(rwc, aKkeyHandle)
	if err != nil {
		return []byte(""), []byte(""), []byte(""), []byte(""), fmt.Errorf("Load AK failed: %s", err)
	}
	glog.V(5).Infof("     AK keyName: %s,", base64.StdEncoding.EncodeToString(keyName))

	err = tpm2.FlushContext(rwc, loadCreateHandle)
	if err != nil {
		return []byte(""), []byte(""), []byte(""), []byte(""), fmt.Errorf("Unable to  flush loadCreateHandle : %v", err)
	}

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
		return []byte(""), []byte(""), []byte(""), []byte(""), fmt.Errorf("Unable to create StartAuthSession : %v", err)
	}

	// if err = tpm2.PolicyPCR(rwc, sessCreateHandle, nil, pcrSelection23); err != nil {
	// 	log.Fatalf("PolicyPCR failed: %v", err)
	// }

	if _, err := tpm2.PolicySecret(rwc, tpm2.HandleEndorsement, tpm2.AuthCommand{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession}, sessCreateHandle, nil, nil, nil, 0); err != nil {
		return []byte(""), []byte(""), []byte(""), []byte(""), fmt.Errorf("Unable to create PolicySecret: %v", err)
	}
	authCommandCreateAuth := tpm2.AuthCommand{Session: sessCreateHandle, Attributes: tpm2.AttrContinueSession}

	pcrList := []int{*pcr}
	pcrval, err := tpm2.ReadPCR(rwc, int(*pcr), tpm2.AlgSHA256)
	if err != nil {
		return []byte(""), []byte(""), []byte(""), []byte(""), fmt.Errorf("Unable to  ReadPCR : %v", err)
	}
	glog.V(5).Infof("     PCR %d Value %v ", *pcr, hex.EncodeToString(pcrval))

	pcrSelection23 := tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: pcrList}

	// what i'd really want is a child key of aKkeyHandle but there's some policy i'm missing
	// error code 0x1d : a policy check failed exit status 1
	//ukPriv, ukPub, _, _, _, err := tpm2.CreateKey(rwc, aKkeyHandle, pcrSelection23, emptyPassword, emptyPassword, unrestrictedKeyParams)

	ukPriv, ukPub, _, _, _, err := tpm2.CreateKeyUsingAuth(rwc, ekh, pcrSelection23, authCommandCreateAuth, emptyPassword, unrestrictedKeyParams)

	if err != nil {
		return []byte(""), []byte(""), []byte(""), []byte(""), fmt.Errorf("UnrestrictedCreateKey failed: %s", err)
	}
	glog.V(20).Infof("     Unrestricted ukPub: %v,", hex.EncodeToString(ukPub))
	glog.V(20).Infof("     Unrestricted ukPriv: %v,", hex.EncodeToString(ukPriv))

	glog.V(10).Infof("     Write (ukPub) ========")
	err = ioutil.WriteFile(ukPubFile, ukPub, 0644)
	if err != nil {
		return []byte(""), []byte(""), []byte(""), []byte(""), fmt.Errorf("Save failed for ukPub: %v", err)
	}
	glog.V(10).Infof("     Write (ukPriv) ========")
	err = ioutil.WriteFile(ukPrivFile, ukPriv, 0644)
	if err != nil {
		return []byte(""), []byte(""), []byte(""), []byte(""), fmt.Errorf("Save failed for ukPriv: %v", err)
	}

	tpm2.FlushContext(rwc, sessCreateHandle)
	if err != nil {
		return []byte(""), []byte(""), []byte(""), []byte(""), fmt.Errorf("Unable to  flush sessCreateHandle : %v", err)
	}
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
		return []byte(""), []byte(""), []byte(""), []byte(""), fmt.Errorf("Unable to create StartAuthSession : %v", err)
	}
	defer tpm2.FlushContext(rwc, sessLoadHandle)

	if _, err := tpm2.PolicySecret(rwc, tpm2.HandleEndorsement, tpm2.AuthCommand{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession}, sessLoadHandle, nil, nil, nil, 0); err != nil {
		return []byte(""), []byte(""), []byte(""), []byte(""), fmt.Errorf("Unable to create PolicySecret: %v", err)
	}
	authCommandLoad = tpm2.AuthCommand{Session: sessLoadHandle, Attributes: tpm2.AttrContinueSession}

	ukeyHandle, ukeyName, err := tpm2.LoadUsingAuth(rwc, ekh, authCommandLoad, ukPub, ukPriv)
	if err != nil {
		return []byte(""), []byte(""), []byte(""), []byte(""), fmt.Errorf("Load failed: %s", err)
	}
	defer tpm2.FlushContext(rwc, ukeyHandle)
	glog.V(20).Infof("     ukeyName: %v,", base64.StdEncoding.EncodeToString(ukeyName))

	err = tpm2.FlushContext(rwc, ekh)
	if err != nil {
		return []byte(""), []byte(""), []byte(""), []byte(""), fmt.Errorf("Unable to  flush ekh : %v", err)
	}

	utPub, err := tpm2.DecodePublic(ukPub)
	if err != nil {
		return []byte(""), []byte(""), []byte(""), []byte(""), fmt.Errorf("Error DecodePublic AK %v", utPub)
	}

	uap, err := utPub.Key()
	if err != nil {
		return []byte(""), []byte(""), []byte(""), []byte(""), fmt.Errorf("akPub.Key() failed: %s", err)
	}
	uBytes, err := x509.MarshalPKIXPublicKey(uap)
	if err != nil {
		return []byte(""), []byte(""), []byte(""), []byte(""), fmt.Errorf("Unable to convert akPub: %v", err)
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
		return []byte(""), []byte(""), []byte(""), []byte(""), fmt.Errorf("Load failed: %s", err)
	}
	glog.V(20).Infof("     Certify Attestation: %v,", hex.EncodeToString(attestation))
	glog.V(20).Infof("     Certify Signature: %v,", hex.EncodeToString(csig))

	err = tpm2.FlushContext(rwc, sessLoadHandle)
	if err != nil {
		return []byte(""), []byte(""), []byte(""), []byte(""), fmt.Errorf("Unable to  flush sessLoadHandle : %v", err)
	}

	glog.V(10).Infof("Creating CSR")

	kk, err := client.NewCachedKey(rwc, tpm2.HandleEndorsement, unrestrictedKeyParams, ukeyHandle)
	s, err := kk.GetSigner()
	if err != nil {
		return []byte(""), []byte(""), []byte(""), []byte(""), fmt.Errorf("can't getSigner : %v", err)
	}

	var csrtemplate = x509.CertificateRequest{
		Subject: pkix.Name{
			Organization:       []string{"Acme Co"},
			OrganizationalUnit: []string{"Enterprise"},
			Locality:           []string{"Mountain View"},
			Province:           []string{"California"},
			Country:            []string{"US"},
			CommonName:         cn,
		},
		DNSNames:           []string{san},
		SignatureAlgorithm: x509.SHA256WithRSAPSS,
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &csrtemplate, s)
	if err != nil {
		return []byte(""), []byte(""), []byte(""), []byte(""), fmt.Errorf("Failed to create CSR: %s", err)
	}

	pemdata := pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE REQUEST",
			Bytes: csrBytes,
		},
	)
	glog.V(10).Infof("CSR \n%s\n", string(pemdata))
	return ukPubPEM, pemdata, csig, attestation, nil

}

func importKey(ar pb.GetSecretResponse) (secret string, err error) {
	glog.V(5).Infof("     --> Starting importKey()")

	glog.V(5).Infof("     Loading EndorsementKeyRSA")
	ek, err := client.EndorsementKeyRSA(rwc)
	if err != nil {
		glog.Fatalf("Unable to get EndorsementKeyRSA: %v", err)
	}
	defer ek.Close()

	blob := &tpmpb.ImportBlob{}
	err = proto.Unmarshal(ar.ImportBlob, blob)
	if err != nil {
		glog.Fatal("Error Unmarshalling ImportBlob error: ", err)
	}
	myDecodedSecret, err := ek.Import(blob)
	if err != nil {
		glog.Fatalf("Unable to Import sealed data: %v", err)
	}
	glog.V(5).Infof("     <-- End importKey()")
	return string(myDecodedSecret), nil
}

func importRSAKey(ar pb.GetSecretResponse) (err error) {

	glog.V(5).Infof("     --> Starting importRSAKey()")

	glog.V(5).Infof("     Loading EndorsementKeyRSA")
	ek, err := client.EndorsementKeyRSA(rwc)
	if err != nil {
		glog.Fatalf("Unable to get EndorsementKeyRSA: %v", err)
	}
	defer ek.Close()

	glog.V(5).Infof("     Loading sealedkey")
	importblob := &tpmpb.ImportBlob{}
	importdata := ar.ImportBlob
	err = proto.Unmarshal(importdata, importblob)
	if err != nil {
		glog.Fatalf("Unmarshal error: %v", err)
	}

	glog.V(5).Infof("     Loading ImportSigningKey")
	key, err := ek.ImportSigningKey(importblob)
	defer key.Close()
	if err != nil {
		glog.Fatalf("error ImportSigningKey: %v", err)
	}

	ap := key.PublicKey()
	importedBytes, err := x509.MarshalPKIXPublicKey(ap)
	if err != nil {
		glog.Fatalf("Unable to convert akPub: %v", err)
	}

	importedPubPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: importedBytes,
		},
	)
	glog.V(10).Infof("     Imported keyPublic portion: \n%v", string(importedPubPEM))

	glog.V(10).Infof("     Saving Key Handle as %s", importedKeyFile)
	keyHandle := key.Handle()
	defer key.Close()
	keyBytes, err := tpm2.ContextSave(rwc, keyHandle)
	if err != nil {
		glog.Fatalf("ContextSave failed for keyHandle: %v", err)
	}
	err = ioutil.WriteFile(importedKeyFile, keyBytes, 0644)
	if err != nil {
		glog.Fatalf("FileSave ContextSave failed for keyBytes: %v", err)
	}
	tpm2.FlushContext(rwc, keyHandle)

	glog.V(10).Infof("     Loading Key Handle")

	glog.V(10).Infof("     ContextLoad (%s) ========", importedKeyFile)
	pHBytes, err := ioutil.ReadFile(importedKeyFile)
	if err != nil {
		glog.Fatalf("ContextLoad failed for importedKey: %v", err)
	}
	pH, err := tpm2.ContextLoad(rwc, pHBytes)
	if err != nil {
		glog.Fatalf("ContextLoad failed for importedKey: %v", err)
	}
	defer tpm2.FlushContext(rwc, pH)

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
	sig, err := tpm2.SignWithSession(rwc, session, pH, emptyPassword, digest[:], nil, &tpm2.SigScheme{
		Alg:  tpm2.AlgRSASSA,
		Hash: tpm2.AlgSHA256,
	})
	if err != nil {
		glog.Fatalf("Error Signing: %v", err)
	}

	glog.V(10).Infof("     Test Signature data:  %s", base64.RawStdEncoding.EncodeToString([]byte(sig.RSA.Signature)))
	glog.V(5).Infof("     <-- End importRSAKey()")
	return nil
}

func quote(reqPCR int, secret string) (attestation []byte, signature []byte, eventLog []byte, retErr error) {

	glog.V(5).Infof("     --> Start Quote")

	pcrList := []int{reqPCR}
	pcrval, err := tpm2.ReadPCR(rwc, *pcr, tpm2.AlgSHA256)
	if err != nil {
		glog.Fatalf("Unable to  ReadPCR : %v", err)
	}
	glog.V(5).Infof("     PCR %d Value %v ", *pcr, hex.EncodeToString(pcrval))

	pcrSelection23 := tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: pcrList}
	emptyPassword := ""

	glog.V(10).Infof("     ContextLoad (ek) ========")
	ekhBytes, err := ioutil.ReadFile(ekFile)
	if err != nil {
		return []byte(""), []byte(""), []byte(""), fmt.Errorf("ContextLoad failed for ekh: %v", err)
	}
	ekh, err := tpm2.ContextLoad(rwc, ekhBytes)
	if err != nil {
		return []byte(""), []byte(""), []byte(""), fmt.Errorf("ContextLoad failed for ekh: %v", err)
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
		return []byte(""), []byte(""), []byte(""), fmt.Errorf("Unable to create StartAuthSession : %v", err)
	}
	defer tpm2.FlushContext(rwc, loadCreateHandle)

	if _, err := tpm2.PolicySecret(rwc, tpm2.HandleEndorsement, tpm2.AuthCommand{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession}, loadCreateHandle, nil, nil, nil, 0); err != nil {
		return []byte(""), []byte(""), []byte(""), fmt.Errorf("Unable to create PolicySecret: %v", err)
	}

	authCommandLoad := tpm2.AuthCommand{Session: loadCreateHandle, Attributes: tpm2.AttrContinueSession}

	glog.V(10).Infof("     Read (akPub) ========")
	akPub, err := ioutil.ReadFile(akPubFile)
	if err != nil {
		return []byte(""), []byte(""), []byte(""), fmt.Errorf("Read failed for akPub: %v", err)
	}
	glog.V(10).Infof("     Read (akPriv) ========")
	akPriv, err := ioutil.ReadFile(akPrivFile)
	if err != nil {
		return []byte(""), []byte(""), []byte(""), fmt.Errorf("Read failed for akPriv: %v", err)
	}

	keyHandle, keyName, err := tpm2.LoadUsingAuth(rwc, ekh, authCommandLoad, akPub, akPriv)
	if err != nil {
		return []byte(""), []byte(""), []byte(""), fmt.Errorf("Load failed: %s", err)
	}
	defer tpm2.FlushContext(rwc, keyHandle)
	kn := hex.EncodeToString(keyName)
	glog.V(10).Infof("     AK keyName %s", kn)

	attestation, sig, err := tpm2.Quote(rwc, keyHandle, emptyPassword, emptyPassword, []byte(secret), pcrSelection23, tpm2.AlgNull)
	if err != nil {
		return []byte(""), []byte(""), []byte(""), fmt.Errorf("Failed to quote: %s", err)
	}
	glog.V(10).Infof("     Quote Hex %v", hex.EncodeToString(attestation))
	glog.V(10).Infof("     Quote Sig %v", hex.EncodeToString(sig.RSA.Signature))

	glog.V(20).Infof("     Getting EventLog")
	evtLog, err := client.GetEventLog(rwc)
	if err != nil {
		return []byte(""), []byte(""), []byte(""), fmt.Errorf("failed to get event log: %v", err)
	}

	glog.V(5).Infof("     <-- End Quote")
	return attestation, sig.RSA.Signature, evtLog, nil
}

func createKeys() (keyName string, ekPub []byte, akPub []byte, retErr error) {

	glog.V(5).Infof("     --> CreateKeys()")

	pcrList := []int{*pcr}
	pcrval, err := tpm2.ReadPCR(rwc, *pcr, tpm2.AlgSHA256)
	if err != nil {
		return "", []byte(""), []byte(""), fmt.Errorf("Unable to  ReadPCR : %v", err)
	}
	glog.V(10).Infof("    Current PCR %v Value %s ", *pcr, hex.EncodeToString(pcrval))

	pcrSelection23 := tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: pcrList}
	emptyPassword := ""

	glog.V(10).Infof("     createPrimary")

	ekh, _, err := tpm2.CreatePrimary(rwc, tpm2.HandleEndorsement, pcrSelection23, emptyPassword, emptyPassword, defaultEKTemplate)
	if err != nil {
		return "", []byte(""), []byte(""), fmt.Errorf("Error creating EK: %v", err)
	}
	defer tpm2.FlushContext(rwc, ekh)

	// reread the pub eventhough tpm2.CreatePrimary* gives pub
	tpmEkPub, name, _, err := tpm2.ReadPublic(rwc, ekh)
	if err != nil {
		return "", []byte(""), []byte(""), fmt.Errorf("Error ReadPublic failed: %s", err)
	}

	p, err := tpmEkPub.Key()
	if err != nil {
		return "", []byte(""), []byte(""), fmt.Errorf("Error tpmEkPub.Key() failed: %s", err)
	}
	glog.V(10).Infof("     tpmEkPub: \n%v", p)

	b, err := x509.MarshalPKIXPublicKey(p)
	if err != nil {
		return "", []byte(""), []byte(""), fmt.Errorf("Unable to convert ekpub: %v", err)
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
		return "", []byte(""), []byte(""), fmt.Errorf("Load failed for ekPubBytes: %v", err)
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
		return "", []byte(""), []byte(""), fmt.Errorf("Unable to create StartAuthSession : %v", err)
	}
	defer tpm2.FlushContext(rwc, sessCreateHandle)

	if _, err := tpm2.PolicySecret(rwc, tpm2.HandleEndorsement, tpm2.AuthCommand{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession}, sessCreateHandle, nil, nil, nil, 0); err != nil {
		return "", []byte(""), []byte(""), fmt.Errorf("Unable to create PolicySecret: %v", err)
	}

	authCommandCreateAuth := tpm2.AuthCommand{Session: sessCreateHandle, Attributes: tpm2.AttrContinueSession}

	akPriv, akPub, creationData, creationHash, creationTicket, err := tpm2.CreateKeyUsingAuth(rwc, ekh, pcrSelection23, authCommandCreateAuth, emptyPassword, defaultKeyParams)
	if err != nil {
		return "", []byte(""), []byte(""), fmt.Errorf("CreateKey failed: %s", err)
	}
	glog.V(10).Infof("     akPub: %v,", hex.EncodeToString(akPub))
	glog.V(10).Infof("     akPriv: %v,", hex.EncodeToString(akPriv))

	cr, err := tpm2.DecodeCreationData(creationData)
	if err != nil {
		return "", []byte(""), []byte(""), fmt.Errorf("Unable to  DecodeCreationData : %v", err)
	}

	glog.V(10).Infof("     CredentialData.ParentName.Digest.Value %v", hex.EncodeToString(cr.ParentName.Digest.Value))
	glog.V(10).Infof("     CredentialTicket %v", hex.EncodeToString(creationTicket.Digest))
	glog.V(10).Infof("     CredentialHash %v", hex.EncodeToString(creationHash))

	glog.V(10).Infof("     ContextSave (ek)")
	ekhBytes, err := tpm2.ContextSave(rwc, ekh)
	if err != nil {
		return "", []byte(""), []byte(""), fmt.Errorf("ContextSave failed for ekh: %v", err)
	}
	err = ioutil.WriteFile(ekFile, ekhBytes, 0644)
	if err != nil {
		return "", []byte(""), []byte(""), fmt.Errorf("ContextSave failed for ekh: %v", err)
	}
	tpm2.FlushContext(rwc, ekh)

	glog.V(10).Infof("     ContextLoad (ek)")
	ekhBytes, err = ioutil.ReadFile(ekFile)
	if err != nil {
		return "", []byte(""), []byte(""), fmt.Errorf("ContextLoad failed for ekh: %v", err)
	}
	ekh, err = tpm2.ContextLoad(rwc, ekhBytes)
	if err != nil {
		return "", []byte(""), []byte(""), fmt.Errorf("ContextLoad failed for ekh: %v", err)
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
		return "", []byte(""), []byte(""), fmt.Errorf("Unable to create StartAuthSession : %v", err)
	}
	defer tpm2.FlushContext(rwc, loadSession)

	if _, err := tpm2.PolicySecret(rwc, tpm2.HandleEndorsement, tpm2.AuthCommand{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession}, loadSession, nil, nil, nil, 0); err != nil {
		return "", []byte(""), []byte(""), fmt.Errorf("Unable to create PolicySecret: %v", err)
	}

	authCommandLoad := tpm2.AuthCommand{Session: loadSession, Attributes: tpm2.AttrContinueSession}

	keyHandle, akeyName, err := tpm2.LoadUsingAuth(rwc, ekh, authCommandLoad, akPub, akPriv)
	if err != nil {
		return "", []byte(""), []byte(""), fmt.Errorf("Load failed: %s", err)
	}
	defer tpm2.FlushContext(rwc, keyHandle)
	kn := hex.EncodeToString(akeyName)
	glog.V(5).Infof("     AK keyName %v", kn)

	akPublicKey, _, _, err := tpm2.ReadPublic(rwc, keyHandle)
	if err != nil {
		return "", []byte(""), []byte(""), fmt.Errorf("Error tpmEkPub.Key() failed: %s", err)
	}

	ap, err := akPublicKey.Key()
	if err != nil {
		return "", []byte(""), []byte(""), fmt.Errorf("tpmEkPub.Key() failed: %s", err)
	}
	akBytes, err := x509.MarshalPKIXPublicKey(ap)
	if err != nil {
		return "", []byte(""), []byte(""), fmt.Errorf("Unable to convert ekpub: %v", err)
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
		return "", []byte(""), []byte(""), fmt.Errorf("Save failed for akPub: %v", err)
	}
	glog.V(10).Infof("     Write (akPriv) ========")
	err = ioutil.WriteFile(akPrivFile, akPriv, 0644)
	if err != nil {
		return "", []byte(""), []byte(""), fmt.Errorf("Save failed for akPriv: %v", err)
	}

	glog.V(5).Infof("     <-- CreateKeys()")
	return kn, ekPubBytes, akPub, nil
}

func activateCredential(uid string, credBlob []byte, encryptedSecret []byte) (n string, retErr error) {

	glog.V(5).Infof("     --> activateCredential()")

	glog.V(10).Infof("     ContextLoad (ek)")
	ekhBytes, err := ioutil.ReadFile(ekFile)
	if err != nil {
		return "", fmt.Errorf("ContextLoad failed for ekh: %v", err)
	}
	ekh, err := tpm2.ContextLoad(rwc, ekhBytes)
	if err != nil {
		return "", fmt.Errorf("ContextLoad failed for ekh: %v", err)
	}
	defer tpm2.FlushContext(rwc, ekh)

	glog.V(10).Infof("     Read (akPub)")
	akPub, err := ioutil.ReadFile(akPubFile)
	if err != nil {
		return "", fmt.Errorf("Read failed for akPub: %v", err)
	}
	glog.V(10).Infof("     Read (akPriv)")
	akPriv, err := ioutil.ReadFile(akPrivFile)
	if err != nil {
		return "", fmt.Errorf("Read failed for akPriv: %v", err)
	}

	glog.V(5).Infof("     LoadUsingAuth")

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
		return "", fmt.Errorf("Unable to create StartAuthSession : %v", err)
	}
	defer tpm2.FlushContext(rwc, loadCreateHandle)

	if _, err := tpm2.PolicySecret(rwc, tpm2.HandleEndorsement, tpm2.AuthCommand{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession}, loadCreateHandle, nil, nil, nil, 0); err != nil {
		return "", fmt.Errorf("Unable to create PolicySecret: %v", err)
	}

	authCommandLoad := tpm2.AuthCommand{Session: loadCreateHandle, Attributes: tpm2.AttrContinueSession}

	keyHandle, keyName, err := tpm2.LoadUsingAuth(rwc, ekh, authCommandLoad, akPub, akPriv)
	if err != nil {
		return "", fmt.Errorf("Load failed: %s", err)
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
		return "", fmt.Errorf("Unable to create StartAuthSession : %v", err)
	}
	defer tpm2.FlushContext(rwc, sessActivateCredentialSessHandle1)

	if _, err := tpm2.PolicySecret(rwc, tpm2.HandleEndorsement, tpm2.AuthCommand{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession}, sessActivateCredentialSessHandle1, nil, nil, nil, 0); err != nil {
		return "", fmt.Errorf("Unable to create PolicySecret: %v", err)
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
		return "", fmt.Errorf("Unable to create StartAuthSession : %v", err)
	}
	defer tpm2.FlushContext(rwc, sessActivateCredentialSessHandle2)

	if _, err := tpm2.PolicySecret(rwc, tpm2.HandleEndorsement, tpm2.AuthCommand{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession}, sessActivateCredentialSessHandle2, nil, nil, nil, 0); err != nil {
		return "", fmt.Errorf("Unable to create PolicySecret: %v", err)
	}

	authCommandActivate2 := tpm2.AuthCommand{Session: sessActivateCredentialSessHandle2, Attributes: tpm2.AttrContinueSession}

	tl := []tpm2.AuthCommand{authCommandActivate1, authCommandActivate2}

	recoveredCredential1, err := tpm2.ActivateCredentialUsingAuth(rwc, tl, keyHandle, ekh, credBlob, encryptedSecret)
	if err != nil {
		return "", fmt.Errorf("ActivateCredential failed: %v", err)
	}
	glog.V(5).Infof("     <--  activateCredential()")
	return string(recoveredCredential1), nil
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
