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
	"time"
	pb "verifier"

	"github.com/golang/glog"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"

	"github.com/google/go-tpm-tools/client"

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

	signCertNVIndex       = 0x01c10000
	signKeyNVIndex        = 0x01c10001
	encryptionCertNVIndex = 0x01c00002
)

var (
	rwc    io.ReadWriteCloser
	pcr    = flag.Int("unsealPcr", 23, "pcr value to unseal against")
	caCert = flag.String("cacert", "CA_crt.pem", "CA Certificate to trust")

	clientCert      = flag.String("clientcert", "client_crt.pem", "Client SSL Certificate")
	clientKey       = flag.String("clientkey", "client_key.pem", "Client SSL PrivateKey")
	usemTLS         = flag.Bool("usemTLS", false, "Validate original client request with mTLS")
	readCertsFromNV = flag.Bool("readCertsFromNV", false, "Try to read read certificates from NV")

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
)

func main() {

	address := flag.String("host", "localhost:50051", "host:port of gRPC server")
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
	//conn, err := grpc.Dial(*address, grpc.WithInsecure())
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
	// currently this code is not used since the NV based EK certs are not available on GCE

	var ekcertBytes []byte
	if *readCertsFromNV {

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

		// now reread the EKEncryption directly from NV
		//   the EKCertificate (x509) is saved at encryptionCertNVIndex
		//   the following steps attempts to read that value in directly from NV
		//   This is currently not supported but i'm adding in code anyway

		ekcertBytes, err = tpm2.NVReadEx(rwc, encryptionCertNVIndex, tpm2.HandleOwner, "", 0)
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
		glog.V(10).Infof("     Encryption Issuer x509 %s", encCert.Issuer.CommonName)

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

		// now reread the EKSigningCert directly from NV
		//   the EKCertificate (x509) is saved at signCertNVIndex
		//   the following steps attempts to read that value in directly from NV
		//   This is currently not supported but i'm adding in code anyway.  it will eventually work on GCE
		//   instances only

		// kcertBytes, err := tpm2.NVReadEx(rwc, signCertNVIndex, tpm2.HandleOwner, emptyPassword, 0)
		// if err != nil {
		// 	glog.Errorf("ERROR:  could not get Signing NVReadEx: %v", err)
		// 	return
		// }

		// ct, err := x509.ParseCertificate(kcertBytes)
		// if err != nil {
		// 	glog.Errorf("ERROR:   ParseCertificate: %v", err)
		// 	return
		// }
		// spubKey := ct.PublicKey.(*rsa.PublicKey)

		// skBytes, err := x509.MarshalPKIXPublicKey(spubKey)
		// if err != nil {
		// 	glog.Errorf("ERROR:  could  MarshalPKIXPublicKey (signing): %v", err)
		// 	return
		// }
		// skPubPEM := pem.EncodeToMemory(
		// 	&pem.Block{
		// 		Type:  "PUBLIC KEY",
		// 		Bytes: skBytes,
		// 	},
		// )
		// glog.V(10).Infof("    Signing PEM Public \n%s", string(skPubPEM))
	}
	c := pb.NewVerifierClient(conn)

	glog.V(5).Infof("=============== MakeCredential ===============")
	akName, ekPub, akPub, err := createKeys()
	if err != nil {
		glog.Fatalf("Unable to generate EK/AK: %v", err)
	}
	req := &pb.MakeCredentialRequest{
		Uid:    *u,
		AkName: akName,
		EkPub:  ekPub,
		EkCert: ekcertBytes,
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

	attestation, signature, err := quote(int(r.Pcr), secret)
	if err != nil {
		glog.Fatalf("Unable to generate quote: %v", err)
	}
	areq := &pb.ActivateCredentialRequest{
		Uid:         *u,
		Secret:      secret,
		Attestation: attestation,
		Signature:   signature,
	}

	ar, err := c.ActivateCredential(ctx, areq)
	if err != nil {
		glog.Fatalf("could not call ActivateCredential: %v", err)
	}
	glog.V(5).Infof("    Activate Credential Status %t", ar.Verified)

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
	att, sig, err := quote(int(qr.Pcr), qr.Nonce)
	if err != nil {
		glog.Fatalf("could not create Quote: %v", err)
	}
	glog.V(5).Infof("=============== Providing Quote ===============")
	pqr := &pb.ProvideQuoteRequest{
		Uid:         *u,
		Attestation: att,
		Signature:   sig,
	}
	pqesp, err := c.ProvideQuote(ctx, pqr)
	if err != nil {
		glog.Fatalf("could not provideQuote: %v", err)
	}
	glog.V(5).Infof("     Provided Quote verified: %t", pqesp.Verified)

	glog.V(5).Infof("=============== OfferImport ===============")

	oir := &pb.OfferImportRequest{
		Uid: *u,
	}
	oirresp, err := c.OfferImport(ctx, oir)
	if err != nil {
		glog.Fatalf("could not OfferImport: %v", err)
	}
	glog.V(5).Infof("=============== OfferImportResponse =============== ")
	if oirresp.SecretType == pb.SecretType_RSA {
		glog.V(5).Infof("===============  Importing sealed RSA Key ===============")
		err = importRSAKey(*oirresp)
		if err != nil {
			glog.Fatalf("Unable to Import RSA Key: %v", err)
		}
	} else if oirresp.SecretType == pb.SecretType_AES {
		glog.V(5).Infof("===============  Importing sealed AES Key ===============")
		secret, err := importKey(*oirresp)
		if err != nil {
			glog.Fatalf("Unable to Import AES Key: %v", err)
		}
		glog.V(5).Infof("     Unsealed Secret %s", secret)
	} else {
		glog.Fatalln("importMode must be either RSA or AES")
	}
}

func importKey(ar pb.OfferImportResponse) (secret string, err error) {
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

func importRSAKey(ar pb.OfferImportResponse) (err error) {

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

func quote(reqPCR int, secret string) (attestation []byte, signature []byte, retErr error) {

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
		return []byte(""), []byte(""), fmt.Errorf("ContextLoad failed for ekh: %v", err)
	}
	ekh, err := tpm2.ContextLoad(rwc, ekhBytes)
	if err != nil {
		return []byte(""), []byte(""), fmt.Errorf("ContextLoad failed for ekh: %v", err)
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
		return []byte(""), []byte(""), fmt.Errorf("Unable to create StartAuthSession : %v", err)
	}
	defer tpm2.FlushContext(rwc, loadCreateHandle)

	if _, err := tpm2.PolicySecret(rwc, tpm2.HandleEndorsement, tpm2.AuthCommand{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession}, loadCreateHandle, nil, nil, nil, 0); err != nil {
		return []byte(""), []byte(""), fmt.Errorf("Unable to create PolicySecret: %v", err)
	}

	authCommandLoad := tpm2.AuthCommand{Session: loadCreateHandle, Attributes: tpm2.AttrContinueSession}

	glog.V(10).Infof("     Read (akPub) ========")
	akPub, err := ioutil.ReadFile(akPubFile)
	if err != nil {
		return []byte(""), []byte(""), fmt.Errorf("Read failed for akPub: %v", err)
	}
	glog.V(10).Infof("     Read (akPriv) ========")
	akPriv, err := ioutil.ReadFile(akPrivFile)
	if err != nil {
		return []byte(""), []byte(""), fmt.Errorf("Read failed for akPriv: %v", err)
	}

	keyHandle, keyName, err := tpm2.LoadUsingAuth(rwc, ekh, authCommandLoad, akPub, akPriv)
	if err != nil {
		return []byte(""), []byte(""), fmt.Errorf("Load failed: %s", err)
	}
	defer tpm2.FlushContext(rwc, keyHandle)
	kn := hex.EncodeToString(keyName)
	glog.V(10).Infof("     AK keyName %s", kn)

	attestation, sig, err := tpm2.Quote(rwc, keyHandle, emptyPassword, emptyPassword, []byte(secret), pcrSelection23, tpm2.AlgNull)
	if err != nil {
		return []byte(""), []byte(""), fmt.Errorf("Failed to quote: %s", err)
	}
	glog.V(10).Infof("     Quote Hex %v", hex.EncodeToString(attestation))
	glog.V(10).Infof("     Quote Sig %v", hex.EncodeToString(sig.RSA.Signature))
	glog.V(5).Infof("     <-- End Quote")
	return attestation, sig.RSA.Signature, nil
}

func createKeys() (n string, ekPub []byte, akPub []byte, retErr error) {

	glog.V(5).Infof("     --> CreateKeys()")

	pcrList := []int{*pcr}
	pcrval, err := tpm2.ReadPCR(rwc, *pcr, tpm2.AlgSHA256)
	if err != nil {
		return "", []byte(""), []byte(""), fmt.Errorf("Unable to  ReadPCR : %v", err)
	}
	glog.V(10).Infof("    Current PCR %v Value %d ", *pcr, hex.EncodeToString(pcrval))

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

	keyHandle, keyName, err := tpm2.LoadUsingAuth(rwc, ekh, authCommandLoad, akPub, akPriv)
	if err != nil {
		return "", []byte(""), []byte(""), fmt.Errorf("Load failed: %s", err)
	}
	defer tpm2.FlushContext(rwc, keyHandle)
	kn := hex.EncodeToString(keyName)
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
