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
	"context"
	"crypto"
	"crypto/rand"
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
	"log"
	mrnd "math/rand"
	"time"
	"verifier"
	pb "verifier"

	"github.com/golang/glog"
	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/server"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"

	tpmpb "github.com/google/go-tpm-tools/proto/tpm"
	"google.golang.org/grpc/credentials"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

const (
	tpmDevice = "/dev/tpm0"
)

var (
	expectedPCRValue = flag.String("expectedPCRValue", "24af52a4f429b71a3184a6d64cddad17e54ea030e2aa6576bf3a5a3d8bd3328f", "expectedPCRValue")
	pcr              = flag.Int("pcr", 0, "PCR Value to use")
	u                = flag.String("uid", uuid.New().String(), "uid of client")

	caCert          = flag.String("cacert", "certs/CA_crt.pem", "CA Certificate to trust")
	rwc             io.ReadWriteCloser
	importMode      = flag.String("importMode", "AES", "RSA|AES")
	aes256Key       = flag.String("aes256Key", "G-KaPdSgUkXp2s5v8y/B?E(H+MbQeThW", "AES key to export")
	exportedRSACert = flag.String("rsaCert", "certs/tpm_client.crt", "RSA Public certificate for the key to export")
	exportedRSAKey  = flag.String("rsaKey", "certs/tpm_client.key", "RSA key to export")
	letterRunes     = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	address         = flag.String("host", "verify.esodemoapp2.com:50051", "host:port of Attestor")
	handleNames     = map[string][]tpm2.HandleType{
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
)

func main() {

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

	mrnd.Seed(time.Now().UTC().UnixNano())

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

	c := pb.NewVerifierClient(conn)

	glog.V(5).Infof("=============== GetPlatformCert ===============")
	req := &pb.GetPlatformCertRequest{
		Uid: *u,
	}
	platformCertResponse, err := c.GetPlatformCert(ctx, req)
	if err != nil {
		glog.Fatalf("Error GetPlatformCert: %v", err)
	}
	if len(platformCertResponse.PlatformCert) > 0 {
		glog.V(5).Infof("=============== GetPlatformCert Returned from remote ===============")
		ct, err := x509.ParseCertificate(platformCertResponse.PlatformCert)
		if err != nil {
			glog.Fatalf("ERROR:   ParseCertificate: %v", err)
		}
		// spubKey := ct.PublicKey.(*rsa.PublicKey)

		// skBytes, err := x509.MarshalPKIXPublicKey(spubKey)
		// if err != nil {
		// 	glog.Fatalf("ERROR:  could  MarshalPKIXPublicKey: %v", err)

		// }
		// skPubPEM := pem.EncodeToMemory(
		// 	&pem.Block{
		// 		Type:  "PUBLIC KEY",
		// 		Bytes: skBytes,
		// 	},
		// )
		glog.V(10).Infof("    Platform Cert Issuer %s\n", ct.Issuer.CommonName)
	}

	var ekcert *x509.Certificate

	ekReq := &pb.GetEKCertRequest{
		Uid: *u,
	}
	ekCertResponse, err := c.GetEKCert(ctx, ekReq)
	if err != nil {
		glog.Fatalf("Error GetEKCert: %v", err)
	}
	if len(ekCertResponse.EkCert) > 0 {
		glog.V(5).Infof("=============== GetEKCert Returned from remote ===============")
		ekcert, err = x509.ParseCertificate(ekCertResponse.EkCert)
		if err != nil {
			glog.Fatalf("ERROR:   ParseCertificate: %v", err)
		}
		spubKey := ekcert.PublicKey.(*rsa.PublicKey)

		skBytes, err := x509.MarshalPKIXPublicKey(spubKey)
		if err != nil {
			glog.Fatalf("ERROR:  could  MarshalPKIXPublicKey: %v", err)

		}
		ekPubPEM := pem.EncodeToMemory(
			&pem.Block{
				Type:  "PUBLIC KEY",
				Bytes: skBytes,
			},
		)
		glog.V(10).Infof("    EkCert Cert Issuer %s\n", ekcert.Issuer.CommonName)
		glog.V(10).Infof("    EkCert Public Key \n%s\n", ekPubPEM)
	}

	glog.V(5).Infof("=============== GetAKCert ===============")
	akReq := &pb.GetAKRequest{
		Uid: *u,
	}
	akResponse, err := c.GetAK(ctx, akReq)
	if err != nil {
		glog.Fatalf("Error GetEKCert: %v", err)
	}

	glog.V(10).Infof("     akPub: %v,", hex.EncodeToString(akResponse.AkPub))
	glog.V(10).Infof("     akName: %v,", hex.EncodeToString(akResponse.AkName))

	glog.V(5).Infof("=============== MakeCredential ===============")

	ekPub, err := tpm2.DecodePublic(akResponse.EkPub)
	if err != nil {
		glog.Fatalf("Error DecodePublic EK %v", err)
	}

	ep, err := ekPub.Key()
	if err != nil {
		glog.Fatalf("ekPub.Key() failed: %s", err)
	}
	ekBytes, err := x509.MarshalPKIXPublicKey(ep)
	if err != nil {
		glog.Fatalf("Unable to convert akPub: %v", err)
	}

	ekPubPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: ekBytes,
		},
	)
	glog.V(10).Infof("     Decoded EkPublic Key: \n%v", string(ekPubPEM))

	ekh, keyName, err := tpm2.LoadExternal(rwc, ekPub, tpm2.Private{}, tpm2.HandleNull)
	if err != nil {
		glog.Fatalf("Error loadingExternal EK %v", err)
	}
	defer tpm2.FlushContext(rwc, ekh)

	glog.V(10).Infof("     Read (akPub) from registry")

	tPub, err := tpm2.DecodePublic(akResponse.AkPub)
	if err != nil {
		glog.Fatalf("Error DecodePublic AK %v", tPub)
	}

	ap, err := tPub.Key()
	if err != nil {
		glog.Fatalf("akPub.Key() failed: %s", err)
	}
	akBytes, err := x509.MarshalPKIXPublicKey(ap)
	if err != nil {
		glog.Fatalf("Unable to convert akPub: %v", err)
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
		glog.Fatalf("AK does not have correct defaultParameters")
	}
	h, keyName, err := tpm2.LoadExternal(rwc, tPub, tpm2.Private{}, tpm2.HandleNull)
	if err != nil {
		glog.Fatalf("Error loadingExternal AK %v", err)
	}
	defer tpm2.FlushContext(rwc, h)
	glog.V(10).Infof("     Loaded AK KeyName %s", hex.EncodeToString(keyName))

	glog.V(5).Infof("     MakeCredential Start")
	b := make([]rune, 32)
	for i := range b {
		b[i] = letterRunes[mrnd.Intn(len(letterRunes))]
	}
	nonce := string(b)
	credBlob, encryptedSecret0, err := tpm2.MakeCredential(rwc, ekh, []byte(nonce), keyName)
	if err != nil {
		glog.Fatalf("MakeCredential failed: %v", err)
	}
	glog.V(10).Infof("     credBlob %s", hex.EncodeToString(credBlob))
	glog.V(10).Infof("     encryptedSecret0 %s", hex.EncodeToString(encryptedSecret0))
	glog.V(2).Infof("     <-- End makeCredential()")

	glog.V(10).Infof("     EncryptedSecret: %s,", hex.EncodeToString(encryptedSecret0))
	glog.V(10).Infof("     CredentialBlob: %v,", hex.EncodeToString(credBlob))

	glog.V(5).Infof("=============== ActivateCredential ===============")
	acReq := &pb.ActivateCredentialRequest{
		Uid:             *u,
		CredBlob:        credBlob,
		EncryptedSecret: encryptedSecret0,
	}
	acResponse, err := c.ActivateCredential(ctx, acReq)
	if err != nil {
		glog.Fatalf("Error ActivateCredential: %v", err)
	}

	glog.V(10).Infof("     Secret: %s", string(acResponse.Secret))
	glog.V(10).Infof("     Nonce: %s", nonce)

	glog.V(5).Infof("=============== Quote/Verify ===============")
	cc := make([]rune, 32)
	for i := range b {
		cc[i] = letterRunes[mrnd.Intn(len(letterRunes))]
	}
	qReq := &pb.QuoteRequest{
		Uid:    *u,
		Pcr:    int32(*pcr),
		Secret: string(cc),
	}
	qResponse, err := c.Quote(ctx, qReq)
	if err != nil {
		glog.Fatalf("Error Quote: %v", err)
	}

	glog.V(10).Infof("     Attestation: %s", hex.EncodeToString(qResponse.Attestation))
	glog.V(10).Infof("     Signature: %s", hex.EncodeToString(qResponse.Signature))

	attestation := qResponse.Attestation
	signature := qResponse.Signature

	att, err := tpm2.DecodeAttestationData(attestation)
	if err != nil {
		glog.Fatalf("DecodeAttestationData(%v) failed: %v", attestation, err)
	}

	glog.V(5).Infof("     Attestation ExtraData (nonce): %s ", string(att.ExtraData))
	glog.V(5).Infof("     Attestation PCR#: %v ", att.AttestedQuoteInfo.PCRSelection.PCRs)
	glog.V(5).Infof("     Attestation Hash: %v ", hex.EncodeToString(att.AttestedQuoteInfo.PCRDigest))

	if string(cc) != string(att.ExtraData) {
		glog.Fatalf("Nonce Value mismatch Got: (%s) Expected: (%v)", string(att.ExtraData), string(cc))
	}

	sigL := tpm2.SignatureRSA{
		HashAlg:   tpm2.AlgSHA256,
		Signature: signature,
	}
	decoded, err := hex.DecodeString(*expectedPCRValue)
	if err != nil {
		glog.Fatalf("DecodeAttestationData(%v) failed: %v", attestation, err)
	}
	hash := sha256.Sum256(decoded)

	glog.V(5).Infof("     Expected PCR Value:           --> %s", *expectedPCRValue)
	glog.V(5).Infof("     sha256 of Expected PCR Value: --> %x", hash)

	glog.V(2).Infof("     Decoding PublicKey for AK ========")

	// use the AK from the original attestation
	rsaPub := rsa.PublicKey{E: int(tPub.RSAParameters.Exponent()), N: tPub.RSAParameters.Modulus()}
	hsh := crypto.SHA256.New()
	hsh.Write(attestation)
	if err := rsa.VerifyPKCS1v15(&rsaPub, crypto.SHA256, hsh.Sum(nil), sigL.Signature); err != nil {
		glog.Fatalf("VerifyPKCS1v15 failed: %v", err)
	}

	if fmt.Sprintf("%x", hash) != hex.EncodeToString(att.AttestedQuoteInfo.PCRDigest) {
		glog.Fatalf("Unexpected PCR hash Value expected: %s  Got %s", fmt.Sprintf("%x", hash), hex.EncodeToString(att.AttestedQuoteInfo.PCRDigest))
	}

	if string(cc) != string(att.ExtraData) {
		glog.Fatalf("Unexpected secret Value expected: %v  Got %v", string(cc), string(att.ExtraData))
	}
	glog.V(2).Infof("     Attestation Signature Verified ")
	glog.V(2).Infof("     <-- End verifyQuote()")

	glog.V(5).Infof("=============== PushSecret ===============")

	glog.V(5).Infof("     Pushing %s", *importMode)

	hv, err := hex.DecodeString(*expectedPCRValue)
	if err != nil {
		glog.Fatalf("Error parsing uint64->32: %v\n", err)
	}

	pcrMap := map[uint32][]byte{uint32(*pcr): hv}

	vpcrs := &tpmpb.PCRs{Hash: tpmpb.HashAlgo_SHA256, Pcrs: pcrMap}

	var preq *verifier.PushSecretRequest
	if *importMode == "AES" {
		importBlob, err := server.CreateImportBlob(ep, []byte(*aes256Key), vpcrs)
		if err != nil {
			glog.Fatalf("Unable to CreateImportBlob : %v", err)
		}
		sealedOutput, err := proto.Marshal(importBlob)
		if err != nil {
			glog.Fatalf("Unable to marshall ImportBlob: ", err)
		}

		hasher := sha256.New()
		hasher.Write([]byte(*aes256Key))
		glog.V(10).Infof("     Hash of AES Key:  %s", base64.RawStdEncoding.EncodeToString(hasher.Sum(nil)))

		preq = &verifier.PushSecretRequest{
			SecretType: verifier.SecretType_AES,
			ImportBlob: sealedOutput,
		}
	} else if *importMode == "RSA" {

		certPEM, err := ioutil.ReadFile(*exportedRSACert)
		if err != nil {
			glog.Fatalf("Could not find public certificate %v", err)
		}
		block, _ := pem.Decode([]byte(certPEM))
		if block == nil {
			glog.Fatalf("failed to parse certificate PEM")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			glog.Fatalf("failed to parse certificate: " + err.Error())
		}
		glog.V(5).Infof("     Loaded x509 %s", cert.Issuer)

		privateKeyPEM, err := ioutil.ReadFile(*exportedRSAKey)
		if err != nil {
			glog.Fatalf("Could not find private Key %v", err)
		}

		block, _ = pem.Decode(privateKeyPEM)
		priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			glog.Fatalf("failed to parse pravate Key: " + err.Error())
		}

		dataToSign := []byte("secret")
		digest := sha256.Sum256(dataToSign)
		signature, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, digest[:])
		if err != nil {
			glog.Fatalf("Error from signing: %s\n", err)
		}

		glog.V(10).Infof("     Test signature data:  %s", base64.StdEncoding.EncodeToString(signature))
		glog.V(2).Infof("     <-- End generateCertificate()")

		importBlob, err := server.CreateSigningKeyImportBlob(ep, priv, vpcrs)
		if err != nil {
			glog.Fatalf("Unable to CreateImportBlob : %v", err)
		}
		sealedOutput, err := proto.Marshal(importBlob)
		if err != nil {
			glog.Fatalf("Unable to marshall ImportBlob: ", err)
		}

		preq = &verifier.PushSecretRequest{
			SecretType: verifier.SecretType_RSA,
			ImportBlob: sealedOutput,
		}
	}

	presp, err := c.PushSecret(ctx, preq)
	if err != nil {
		glog.Fatalf("Error Quote: %v", err)
	}
	glog.V(5).Infof("     Verification %s", base64.StdEncoding.EncodeToString(presp.Verification))

}
