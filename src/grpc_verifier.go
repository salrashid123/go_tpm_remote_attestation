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
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	mrnd "math/rand"
	"time"
	"verifier"

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
	expectedPCRValue = flag.String("expectedPCRValue", "24af52a4f429b71a3184a6d64cddad17e54ea030e2aa6576bf3a5a3d8bd3328f", "expectedPCRValue to use")
	expectedPCRSHA1  = flag.String("expectedPCRSHA1", "0f2d3a2a1adaa479aeeca8f5df76aadc41b862ea", "PCR0 value for the eventlog on GCE VMs, debian10 with secure boot")
	pcr              = flag.Int("pcr", 0, "PCR Value to use")
	u                = flag.String("uid", uuid.New().String(), "uid of client")

	caCertTLS       = flag.String("caCertTLS", "certs/CA_crt.pem", "CA Certificate to Trust for TLS")
	caCertIssuer    = flag.String("caCertIssuer", "certs/CA_crt.pem", "CA Certificate to issue X509 Certificates")
	caKeyIssuer     = flag.String("caKeyIssuer", "certs/CA_key.pem", "CA Key to sign x509")
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
	ca_pem, err := ioutil.ReadFile(*caCertTLS)
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

	c := verifier.NewVerifierClient(conn)

	glog.V(5).Infof("=============== GetPlatformCert ===============")
	req := &verifier.GetPlatformCertRequest{
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

	ekReq := &verifier.GetEKCertRequest{
		Uid: *u,
	}
	ekCertResponse, err := c.GetEKCert(ctx, ekReq)
	if err != nil {
		glog.Infof("GetEKCert Failed, skipping loading Certificate from remote NV;  Original Error is: %v", err)
	} else if len(ekCertResponse.EkCert) > 0 {
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
	akReq := &verifier.GetAKRequest{
		Uid: *u,
	}
	akResponse, err := c.GetAK(ctx, akReq)
	if err != nil {
		glog.Fatalf("Error GetEKCert: %v", err)
	}

	glog.V(20).Infof("     akPub: %v,", hex.EncodeToString(akResponse.AkPub))
	glog.V(20).Infof("     akName: %v,", hex.EncodeToString(akResponse.AkName))

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

	if tPub.MatchesTemplate(client.AKTemplateRSA()) {
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
	glog.V(10).Infof("     Sending Nonce: %s", nonce)
	credBlob, encryptedSecret0, err := tpm2.MakeCredential(rwc, ekh, []byte(nonce), keyName)
	if err != nil {
		glog.Fatalf("MakeCredential failed: %v", err)
	}
	glog.V(20).Infof("     credBlob %s", hex.EncodeToString(credBlob))
	glog.V(20).Infof("     encryptedSecret0 %s", hex.EncodeToString(encryptedSecret0))
	glog.V(2).Infof("     <-- End makeCredential()")

	glog.V(20).Infof("     EncryptedSecret: %s,", hex.EncodeToString(encryptedSecret0))
	glog.V(20).Infof("     CredentialBlob: %v,", hex.EncodeToString(credBlob))

	glog.V(5).Infof("=============== ActivateCredential ===============")
	acReq := &verifier.ActivateCredentialRequest{
		Uid:             *u,
		CredBlob:        credBlob,
		EncryptedSecret: encryptedSecret0,
	}
	acResponse, err := c.ActivateCredential(ctx, acReq)
	if err != nil {
		glog.Fatalf("Error ActivateCredential: %v", err)
	}

	glog.V(10).Infof("     Returned Secret: %s", string(acResponse.Secret))

	if string(acResponse.Secret) != nonce {
		glog.Fatalf(fmt.Sprintf("Error Expected Nonce [%s]does not match provided secret: [%s]", nonce, string(acResponse.Secret)), err)
	}
	glog.V(5).Infof("     Attestation Complete")

	glog.V(5).Infof("=============== Quote/Verify ===============")
	cc := make([]rune, 32)
	for i := range b {
		cc[i] = letterRunes[mrnd.Intn(len(letterRunes))]
	}
	glog.V(10).Infof("     Sending Quote with Nonce: %s", string(cc))
	qReq := &verifier.QuoteRequest{
		Uid:    *u,
		Pcr:    int32(*pcr),
		Secret: string(cc),
	}
	qResponse, err := c.Quote(ctx, qReq)
	if err != nil {
		glog.Fatalf("Error Quote: %v", err)
	}

	glog.V(20).Infof("     Attestation: %s", hex.EncodeToString(qResponse.Attestation))
	glog.V(20).Infof("     Signature: %s", hex.EncodeToString(qResponse.Signature))

	attestation := qResponse.Attestation
	signature := qResponse.Signature

	att, err := tpm2.DecodeAttestationData(attestation)
	if err != nil {
		glog.Fatalf("DecodeAttestationData(%v) failed: %v", attestation, err)
	}

	glog.V(10).Infof("     Attestation ExtraData (nonce): %s ", string(att.ExtraData))
	glog.V(10).Infof("     Attestation PCR#: %v ", att.AttestedQuoteInfo.PCRSelection.PCRs)
	glog.V(10).Infof("     Attestation Hash: %v ", hex.EncodeToString(att.AttestedQuoteInfo.PCRDigest))

	if string(cc) != string(att.ExtraData) {
		glog.Fatalf("Nonce Value mismatch Got: (%s) Expected: (%v)", string(att.ExtraData), string(cc))
	}

	sigL := tpm2.SignatureRSA{
		HashAlg:   tpm2.AlgSHA256,
		Signature: signature,
	}
	hexPCRValue, err := hex.DecodeString(*expectedPCRValue)
	if err != nil {
		glog.Fatalf("Decode failed for provided PCRValue (%v) failed: %v", attestation, err)
	}
	pcrHash := sha256.Sum256(hexPCRValue)

	glog.V(5).Infof("     Expected PCR Value:           --> %s", *expectedPCRValue)
	glog.V(5).Infof("     sha256 of Expected PCR Value: --> %x", pcrHash)

	if fmt.Sprintf("%x", pcrHash) != hex.EncodeToString(att.AttestedQuoteInfo.PCRDigest) {
		glog.Fatalf("Unexpected PCR hash Value expected: %s  Got %s", fmt.Sprintf("%x", pcrHash), hex.EncodeToString(att.AttestedQuoteInfo.PCRDigest))
	}

	glog.V(2).Infof("     Decoding PublicKey for AK ========")

	// use the AK from the original attestation to verify the signature of the Attestation
	// rsaPub := rsa.PublicKey{E: int(tPub.RSAParameters.Exponent()), N: tPub.RSAParameters.Modulus()}
	hsh := crypto.SHA256.New()
	hsh.Write(attestation)
	if err := rsa.VerifyPKCS1v15(ap.(*rsa.PublicKey), crypto.SHA256, hsh.Sum(nil), sigL.Signature); err != nil {
		glog.Fatalf("VerifyPKCS1v15 failed: %v", err)
	}

	// Now compare the nonce that is embedded within the attestation.  This should match the one we sent in earlier.
	if string(cc) != string(att.ExtraData) {
		glog.Fatalf("Unexpected secret Value expected: %v  Got %v", string(cc), string(att.ExtraData))
	}
	glog.V(2).Infof("     Attestation Signature Verified ")

	glog.V(2).Infof("     Reading EventLog")
	bt, err := hex.DecodeString(*expectedPCRSHA1)
	if err != nil {
		glog.Fatalf("Error decoding pcr %v", err)
	}
	evtLogPcrMap := map[uint32][]byte{uint32(*pcr): bt}

	pcrs := &tpmpb.PCRs{Hash: tpmpb.HashAlgo_SHA1, Pcrs: evtLogPcrMap}

	events, err := server.ParseAndVerifyEventLog(qResponse.Eventlog, pcrs)
	if err != nil {
		glog.Fatalf("Failed to parse EventLog: %v", err)
	}

	for _, event := range events {
		glog.V(2).Infof("     Event Type %v\n", event.Type)
		glog.V(2).Infof("     PCR Index %d\n", event.Index)
		glog.V(2).Infof("     Event Data %s\n", hex.EncodeToString(event.Data))
		glog.V(2).Infof("     Event Digest %s\n", hex.EncodeToString(event.Digest))
	}
	glog.V(2).Infof("     EventLog Verified ")

	// Now issue a x509 cert thats associated with the AK.
	//  this next step is just for demonstration and uses a CA authority the Verifier has access to.
	//  Normally, this x509 is sent back to the attestor so that it'd have an x509 for the attested
	//  key.
	glog.V(2).Infof("     Generate Test Certificate for AK ")

	var notBefore time.Time
	notBefore = time.Now()

	notAfter := notBefore.Add(time.Hour * 24)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(2), 20)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		glog.Fatalf("Failed to generate serial number: %v", err)
	}
	glog.V(10).Infof("     Issuing certificate with serialNumber %d", serialNumber)

	cn := "verify.esodemoapp2.com"

	ca_pem, err = ioutil.ReadFile(*caCertIssuer)
	if err != nil {
		glog.Fatalf("failed to load root CA certificates  error=%v", err)
	}
	block, _ := pem.Decode(ca_pem)
	if block == nil {
		glog.Fatalf("Unable to decode %s %v", *caCertIssuer, err)
	}
	ca, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		glog.Fatalf("Unable to parse %s %v", *caCertIssuer, err)
	}

	keyPEMBytes, err := ioutil.ReadFile(*caKeyIssuer)
	if err != nil {
		glog.Fatalf("Unable to read %s  %v", *caKeyIssuer, err)
	}
	privPem, _ := pem.Decode(keyPEMBytes)
	parsedKey, err := x509.ParsePKCS1PrivateKey(privPem.Bytes)
	if err != nil {
		glog.Fatalf("Unable to parse %s %v", *caKeyIssuer, err)
	}

	ct := &x509.Certificate{
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
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	cert_b, err := x509.CreateCertificate(rand.Reader, ct, ca, ap, parsedKey)
	if err != nil {
		glog.Fatalf("Failed to createCertificate: %v", err)
	}

	akCertPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert_b,
		},
	)

	glog.V(10).Infof("     X509 issued by Verifier for Ak: \n%v", string(akCertPEM))

	glog.V(2).Infof("     <-- End verifyQuote()")

	glog.V(5).Infof("=============== PushSecret ===============")

	glog.V(5).Infof("     Pushing %s", *importMode)

	// Note: we are binding the import to the the PCR's value.
	// for AES:
	//   A non-nil pcrs parameter adds a requirement that the TPM must have specific PCR values for Import() to succeed.
	// for RSA:
	//   A non-nil pcrs parameter adds a requirement that the TPM must have specific PCR values to use the signing key.
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

		// Print out the hash of the AES key.
		//  If the attestor was able to extract this key, the PushSecret.Verification
		//  value will be the same hash (eg, both the verifier and attestor has the same key)
		hasher := sha256.New()
		hasher.Write([]byte(*aes256Key))
		glog.V(10).Infof("     Hash of AES Key:  %s", base64.RawStdEncoding.EncodeToString(hasher.Sum(nil)))

		preq = &verifier.PushSecretRequest{
			Uid:        *u,
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
			glog.Fatalf("failed to parse private Key: " + err.Error())
		}

		// Generate a test signature using this RSA key.
		//  If the attestor was able to import this RSA key, the PushSecret.Verification
		//  value will include the same signature (eg, both the verifier and attestor has the same key)
		glog.V(10).Infof("     Data to sign: %s", *u)
		dataToSign := []byte(*u)
		digest := sha256.Sum256(dataToSign)
		signature, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, digest[:])
		if err != nil {
			glog.Fatalf("Error from signing: %s\n", err)
		}

		glog.V(10).Infof("     Test signature data:  %s", base64.RawStdEncoding.EncodeToString(signature))
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
			Uid:        *u,
			SecretType: verifier.SecretType_RSA,
			ImportBlob: sealedOutput,
		}
	}

	presp, err := c.PushSecret(ctx, preq)
	if err != nil {
		glog.Fatalf("Error Pushing Secret: %v", err)
	}
	glog.V(5).Infof("     Verification %s", base64.RawStdEncoding.EncodeToString(presp.Verification))

	// Ask the remote system to generate an unrestricted RSA Key, certify it and return
	//  its public portion.  Once attested, any signature generated by the remote system
	//  can be verified locally.
	glog.V(5).Infof("=============== PullRSAKey ===============")

	psReq := &verifier.PullRSAKeyRequest{
		Uid: *u,
		Pcr: int32(*pcr),
	}
	psResponse, err := c.PullRSAKey(ctx, psReq)
	if err != nil {
		glog.Fatalf("Error PullRSAKey: %v", err)
	}

	glog.V(20).Infof("     SigningKey Attestation %s\n", base64.StdEncoding.EncodeToString(psResponse.Attestation))
	glog.V(20).Infof("     SigningKey Attestation Signature %s\n", base64.StdEncoding.EncodeToString(psResponse.AttestationSignature))

	glog.V(20).Infof("     Read and Decode (attestion)")
	att, err = tpm2.DecodeAttestationData(psResponse.Attestation)
	if err != nil {
		glog.Fatalf("DecodeAttestationData failed: %v", err)
	}
	glog.V(20).Infof("     Attestation AttestedCertifyInfo.Name.Digest.Value: %s", hex.EncodeToString(att.AttestedCertifyInfo.Name.Digest.Value))

	// Verify signature of Attestation by using the PEM Public key for AK
	rsaPub := *ap.(*rsa.PublicKey)
	//rsaPub := rsa.PublicKey{E: int(tPub.RSAParameters.Exponent()), N: tPub.RSAParameters.Modulus()}
	ahsh := crypto.SHA256.New()
	ahsh.Write(psResponse.Attestation)

	if err := rsa.VerifyPKCS1v15(&rsaPub, crypto.SHA256, ahsh.Sum(nil), psResponse.AttestationSignature); err != nil {
		glog.Fatalf("VerifyPKCS1v15 failed: %v", err)
	}
	glog.V(10).Infof("     Attestation of Unrestricted Signing Key Verified")

	// now verify that the public key provided is the same as the one that was attested
	// also verify that the key template matches what we expect for an unrestricted key
	uPub, err := tpm2.DecodePublic(psResponse.TpmPublicKey)
	if err != nil {
		glog.Fatalf("Error Decode Unrestricted key Public %v", err)
	}

	up, err := uPub.Key()
	if err != nil {
		glog.Fatalf("ukPub.Key() failed: %s", err)
	}
	fkey, ok := up.(*rsa.PublicKey)
	if !ok {
		glog.Fatalf("Unable to extract public key from CSR %v", err)
	}
	if uPub.MatchesTemplate(unrestrictedKeyParams) {
		glog.V(10).Infof("     Unrestricted key parameter matches template")
	} else {
		glog.Fatalf("uK does not have correct template parameters")
	}

	ukBytes, err := x509.MarshalPKIXPublicKey(up)
	if err != nil {
		glog.Fatalf("Unable to convert ukPub: %v", err)
	}

	ukPubPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: ukBytes,
		},
	)

	glog.V(10).Infof("     uakPub PEM \n%s", string(ukPubPEM))

	// verify the test signature for the unrestricted key.  For convenience, the
	// test signature's raw data that the attestor signed is the UID sent

	glog.V(10).Infof("     SigningKey Test Signature %s\n", base64.StdEncoding.EncodeToString(psResponse.TestSignature))
	glog.V(10).Infof("     Data to verify signature with: %s", *u)
	uhsh := crypto.SHA256.New()
	uhsh.Write([]byte(*u))

	if err := rsa.VerifyPKCS1v15(fkey, crypto.SHA256, uhsh.Sum(nil), psResponse.TestSignature); err != nil {
		glog.Fatalf("VerifyPKCS1v15 failed: %v", err)
	}
	glog.V(10).Infof("     Test Signature Verified")

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
			ModulusRaw: fkey.N.Bytes(),
		},
	}
	ok, err = att.AttestedCertifyInfo.Name.MatchesPublic(params)
	if err != nil {
		glog.Fatalf("     AttestedCertifyInfo.MatchesPublic(%v) failed: %v", att, err)
	}
	glog.V(10).Infof("     Unrestricted RSA Public key parameters matches AttestedCertifyInfo  %v", ok)

	// Same as with AK.  Now that we have an unrestricted Key on the remote TPM, issue an x509 for it
	//  for use later on (eg, send this pack in another gRPC call back to the attestor).  The attestor
	//  can use this x509 to setup mTLS (if so, set ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},)

	notBefore = time.Now()

	notAfter = notBefore.Add(time.Hour * 24)

	serialNumberLimit = new(big.Int).Lsh(big.NewInt(2), 20)
	serialNumber, err = rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		glog.Fatalf("Failed to generate serial number: %v", err)
	}
	glog.V(10).Infof("     Issuing certificate with serialNumber %d", serialNumber)

	cn = "mtls,server.anotherdomain.com"

	ct = &x509.Certificate{
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
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	cert_b, err = x509.CreateCertificate(rand.Reader, ct, ca, up, parsedKey)
	if err != nil {
		glog.Fatalf("Failed to createCertificate: %v", err)
	}

	ukCertPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert_b,
		},
	)

	glog.V(10).Infof("     X509 issued by Verifier for unrestricted Key: \n%v", string(ukCertPEM))

	glog.V(5).Infof("     Pulled Signing Key  complete %v", psResponse.Uid)
}
