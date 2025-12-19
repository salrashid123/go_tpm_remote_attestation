package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"slices"

	"flag"
	"fmt"
	"net"
	"os"

	"github.com/golang/glog"
	"github.com/google/go-attestation/attest"
	"github.com/google/go-tpm/tpmutil"
	"github.com/google/uuid"
	"github.com/salrashid123/go_tpm_registrar/verifier"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

const ()

var (
	address          = flag.String("host", "localhost:50051", "host:port of gRPC server")
	grpcServerName   = flag.String("grpcservername", "verify.domain.com", "SNI for grpc server")
	tlsCert          = flag.String("tlsCert", "certs/root-ca.crt", "tls Certificate")
	eventLogPath     = flag.String("eventLogPath", "/sys/kernel/security/tpm0/binary_bios_measurements", "Path to the eventlog")
	tpmDevice        = flag.String("tpmDevice", "/dev/tpmrm0", "TPMPath")
	platformCertFile = flag.String("platformCertFile", "certs/platform_cert.der", "Platform Certificate File")

	tpm               *attest.TPM
	ek                *attest.EK
	ekpubBytes        []byte
	ekCert            *x509.Certificate
	akbytes           []byte
	nkBytes           []byte
	issuedKeyderBytes []byte
)

const ()

var TPMDEVICES = []string{"/dev/tpm0", "/dev/tpmrm0"}

func openTPM(path string) (io.ReadWriteCloser, error) {
	if slices.Contains(TPMDEVICES, path) {
		return tpmutil.OpenTPM(path)
	} else {
		return net.Dial("tcp", path)
	}
}

func main() {
	flag.Set("logtostderr", "true")
	flag.Set("stderrthreshold", "INFO")
	flag.Parse()

	if *address == "" {
		fmt.Fprintln(os.Stderr, "missing -address flag (localhost:50051)")
		flag.Usage()
		os.Exit(2)
	}

	grpcRootCAs := x509.NewCertPool()
	ca_pem, err := os.ReadFile(*tlsCert)
	if err != nil {
		glog.Errorf("failed to load root CA certificates  error=%v", err)
		os.Exit(1)
	}
	if !grpcRootCAs.AppendCertsFromPEM(ca_pem) {
		glog.Errorf("no root CA certs parsed from file ")
		os.Exit(1)
	}
	tlsCfg := tls.Config{
		RootCAs:    grpcRootCAs,
		ServerName: *grpcServerName,
	}

	ce := credentials.NewTLS(&tlsCfg)
	ctx := context.Background()

	conn, err := grpc.NewClient(*address, grpc.WithTransportCredentials(ce))
	if err != nil {
		glog.Errorf("did not connect: %v", err)
		os.Exit(1)
	}
	defer conn.Close()

	uid := uuid.New().String()

	c := verifier.NewVerifierClient(conn)
	glog.V(5).Infof("=============== OfferPlatformCert ===============")

	platformCert, err := os.ReadFile(*platformCertFile)
	if err != nil {
		glog.Errorf("ERROR: Unable to load parse platform certificate %v", err)
		os.Exit(1)
	}

	_, err = c.OfferPlatformCert(ctx, &verifier.OfferPlatformCertRequest{
		Uid:          uid,
		PlatformCert: platformCert,
	})
	if err != nil {
		glog.Errorf("error sending platformcert: %v", err)
		os.Exit(1)
	}
	glog.V(5).Infof("Verified Platform Cert\n")

	glog.V(5).Infof("=============== OfferEK ===============")

	config := &attest.OpenConfig{
		TPMVersion: attest.TPMVersion20,
	}
	tpm, err = attest.OpenTPM(config)
	if err != nil {
		glog.Errorf("error opening TPM %v", err)
		os.Exit(1)
	}
	defer tpm.Close()

	eks, err := tpm.EKs()
	if err != nil {
		glog.Errorf("error getting EK %v", err)
		os.Exit(1)
	}

	for _, e := range eks {
		if e.Certificate != nil {
			glog.Infof("ECCert with available Issuer: %s", e.Certificate.Issuer)
		}
	}

	if len(eks) == 0 {
		glog.Error("error no EK found")
		os.Exit(1)
	}

	// use the  ek at 0 for now...
	ek = &eks[0]

	if ek.Public == nil {
		glog.Error("error no Public not found")
		os.Exit(1)
	}

	ekpubBytes, err = x509.MarshalPKIXPublicKey(ek.Public)
	if err != nil {
		glog.Errorf("ERROR:  could  marshall public key %v", err)
		os.Exit(1)
	}

	if ek.Certificate != nil {
		ekCert = ek.Certificate
	}

	_, err = c.OfferEK(ctx, &verifier.OfferEKRequest{
		Uid:    uid,
		EkCert: ek.Certificate.Raw,
	})
	if err != nil {
		glog.Errorf("error sending ekcert: %v", err)
		os.Exit(1)
	}
	glog.V(5).Infof("Verified EK Cert\n")

	glog.V(5).Infof("=============== OfferAK ===============")
	// generate the attestation key
	// TODO: see how to get the GCE signed attestation key:
	// https://github.com/salrashid123/gcp-vtpm-ek-ak
	akConfig := &attest.AKConfig{
		Parent: &attest.ParentKeyConfig{
			Algorithm: attest.RSA,
			Handle:    0x81000001, // SRK, pg 29 https://trustedcomputinggroup.org/wp-content/uploads/TCG-TPM-v2.0-Provisioning-Guidance-Published-v1r1.pdf
		},
	}
	//akConfig := &attest.AKConfig{}
	ak, err := tpm.NewAK(akConfig)
	if err != nil {
		glog.Errorf("ERROR:  could not get AK %v", err)
		os.Exit(1)
	}

	akbytes, err = ak.Marshal()
	if err != nil {
		glog.Errorf("ERROR:  could marshall AK %v", err)
		os.Exit(1)
	}

	attestParams := ak.AttestationParameters()
	attestParametersBytes := new(bytes.Buffer)
	err = json.NewEncoder(attestParametersBytes).Encode(attestParams)
	if err != nil {
		glog.Errorf("ERROR:  encode attestation parameters AK %v", err)
		os.Exit(1)
	}

	_, err = c.OfferAK(ctx, &verifier.OfferAKRequest{
		Uid:                   uid,
		AttestationParameters: attestParametersBytes.Bytes(),
	})
	if err != nil {
		glog.Errorf("error sending attestation parameters: %v", err)
		os.Exit(1)
	}
	glog.V(5).Infof("Verified AK \n")

	glog.V(5).Infof("=============== GetMakeCredential ===============")

	mk, err := c.GetMakeCredential(ctx, &verifier.GetMakeCredentialRequest{
		Uid: uid,
	})
	if err != nil {
		glog.Errorf("error sending getMakeCredentials: %v", err)
		os.Exit(1)
	}
	glog.V(60).Infof("EncryptedCredentials %s", base64.StdEncoding.EncodeToString(mk.EncryptedCredentials))

	// akf, err := tpm.LoadAK(akbytes)
	// if err != nil {
	// 	glog.Errorf("ERROR:  error loading ak AK %v", err)
	// 	os.Exit(1)
	// }
	// defer ak.Close(tpm)

	var encryptedCredentials attest.EncryptedCredential
	err = json.Unmarshal(mk.EncryptedCredentials, &encryptedCredentials)
	if err != nil {
		glog.Errorf("ERROR:  error decoding encryptedCredentials %v", err)
		os.Exit(1)
	}

	secret, err := ak.ActivateCredential(tpm, encryptedCredentials)
	//secret, err := ak.ActivateCredentialWithEK(tpm, encryptedCredentials, *ek)
	if err != nil {
		glog.Errorf("ERROR:  error activating Credential  AK %v", err)
		os.Exit(1)
	}
	glog.V(5).Infof("EncryptedCredentials Secret %s", hex.EncodeToString(secret))

	glog.V(5).Infof("=============== SetActivateCredential ===============")

	_, err = c.SetActivateCredential(ctx, &verifier.SetActivateCredentialRequest{
		Uid:    uid,
		Secret: secret,
	})
	if err != nil {
		glog.Errorf("error sending getMakeCredentials: %v", err)
		os.Exit(1)
	}
	glog.V(5).Infof("SetActivateCredential complete \n")

	glog.V(5).Infof("=============== OfferQuote ===============")

	oq, err := c.OfferQuote(ctx, &verifier.OfferQuoteRequest{
		Uid: uid,
	})
	if err != nil {
		glog.Errorf("error sending OfferQuote: %v", err)
		os.Exit(1)
	}
	glog.V(5).Infof("OfferQuote complete \n")

	glog.V(5).Infof("=============== SetQuote ===============")

	evtLog, err := os.ReadFile(*eventLogPath)
	if err != nil {
		glog.Errorf("     Error reading eventLog %v", err)
		os.Exit(1)
	}

	platformAttestation, err := tpm.AttestPlatform(ak, oq.Nonce, &attest.PlatformAttestConfig{
		EventLog: evtLog,
	})
	if err != nil {
		glog.Errorf("ERROR: creating Attestation %v", err)
		os.Exit(1)
	}

	platformAttestationBytes := new(bytes.Buffer)
	err = json.NewEncoder(platformAttestationBytes).Encode(platformAttestation)
	if err != nil {
		glog.Errorf("ERROR: encoding platformAttestationBytes %v", err)
		os.Exit(1)
	}

	_, err = c.SetQuote(ctx, &verifier.SetQuoteRequest{
		Uid:                 uid,
		PlatformAttestation: platformAttestationBytes.Bytes(),
	})
	if err != nil {
		glog.Errorf("error sending SetQuote: %v", err)
		os.Exit(1)
	}
	glog.V(5).Infof("SetQuote complete \n")

	glog.V(5).Infof("=============== SetAttestedKey ===============")
	// now crate the TLS EC key on the TPM
	// https://github.com/google/go-attestation/blob/master/attest/tpm.go#L147
	//   tpm2.FlagSignerDefault ^ tpm2.FlagRestricted
	// where
	// FlagSignerDefault = FlagSign | FlagRestricted | FlagFixedTPM | FlagFixedParent | FlagSensitiveDataOrigin | FlagUserWithAuth
	kConfig := &attest.KeyConfig{
		Algorithm: attest.ECDSA,
		Size:      256,
		// Parent: &attest.ParentKeyConfig{
		// 	Algorithm: attest.RSA,
		// 	Handle:    0x81000001, // default RSA SRK
		// },
	}
	nk, err := tpm.NewKey(ak, kConfig)
	if err != nil {
		glog.Errorf("ERROR:  error creating key  %v", err)
		os.Exit(1)
	}
	defer nk.Close()

	err = ak.Close(tpm)
	if err != nil {
		glog.Errorf("ERROR:  error closing ak  %v", err)
		os.Exit(1)
	}

	nkBytes, err = nk.Marshal()
	if err != nil {
		glog.Errorf("ERROR:  could not marshall newkey %v", err)
		os.Exit(1)
	}

	pubKey, ok := nk.Public().(*ecdsa.PublicKey)
	if !ok {
		glog.Errorf("Could not assert the public key to ec public key")
		os.Exit(1)
	}

	issuedKeyderBytes, err = x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		glog.Errorf("Could not MarshalPKIXPublicKey ec public key")
		os.Exit(1)
	}
	pubkeyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: issuedKeyderBytes,
		},
	)

	glog.V(2).Infof("Generated ECC Public \n%s", string(pubkeyPem))

	keyCertificationBytes := new(bytes.Buffer)
	err = json.NewEncoder(keyCertificationBytes).Encode(nk.CertificationParameters())
	if err != nil {
		glog.Errorf("ERROR: encoding keyCertificationBytes %v", err)
		os.Exit(1)
	}

	_, err = c.SetAttestedKey(ctx, &verifier.SetAttestedKeyRequest{
		Uid:              uid,
		Key:              issuedKeyderBytes,
		KeyCertification: keyCertificationBytes.Bytes(),
	})
	if err != nil {
		glog.Errorf("error sending SetQuote: %v", err)
		os.Exit(1)
	}
	glog.V(5).Infof("SetAttestedKey complete \n")

	glog.V(5).Infof("=============== GetCertificate ===============")

	glog.V(5).Infof("Creating CSR")

	var csrtemplate = x509.CertificateRequest{
		Subject: pkix.Name{
			Organization:       []string{"Acme Co"},
			OrganizationalUnit: []string{"Enterprise"},
			Locality:           []string{"Mountain View"},
			Province:           []string{"California"},
			Country:            []string{"US"},
			CommonName:         "mytpm",
		},
		DNSNames: []string{"mytpm"},
		//SignatureAlgorithm: x509.SHA256WithRSAPSS,
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}

	nkp, err := nk.Private(nk.Public())
	if err != nil {
		glog.Errorf("Failed to get private crypto.signer: %s", err)
		os.Exit(1)
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &csrtemplate, nkp)
	if err != nil {
		glog.Errorf("Failed to create CSR: %s", err)
		os.Exit(1)
	}
	pemcsr := pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE REQUEST",
			Bytes: csrBytes,
		},
	)
	glog.V(5).Infof("CSR \n%s\n", string(pemcsr))

	ccr, err := c.GetCertificate(ctx, &verifier.GetCertificateRequest{
		Uid: uid,
		Csr: csrBytes,
	})
	if err != nil {
		glog.Errorf("error sending GetCertificate: %v", err)
		os.Exit(1)
	}

	issuedcrtPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ccr.Certificate})

	glog.V(5).Infof("Isued Certificate: \n%s\n", string(issuedcrtPEM))

	glog.V(5).Infof("GetCertificate complete \n")

}
