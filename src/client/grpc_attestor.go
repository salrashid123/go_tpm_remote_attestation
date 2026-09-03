package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"slices"
	"time"

	"flag"
	"fmt"
	"os"

	"github.com/golang/glog"
	"github.com/google/go-attestation/attest"
	"github.com/google/go-attestation/attributecert"
	"github.com/google/go-tpm/tpmutil"
	"github.com/salrashid123/go_tpm_registrar/verifier"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/peer"
)

const ()

var (
	address        = flag.String("host", "localhost:50051", "host:port of gRPC server")
	grpcServerName = flag.String("grpcservername", "verify.domain.com", "SNI for grpc server")
	tlsCert        = flag.String("tlsCert", "certs/root-ca.crt", "tls Certificate")
	eventLogPath   = flag.String("eventLogPath", "/sys/kernel/security/tpm0/binary_bios_measurements", "Path to the eventlog")
	tpmPath        = flag.String("tpm-path", "127.0.0.1:2321", "Path to the TPM device (character device or a Unix socket).")

	platformCACert = flag.String("platformCACert", "certs/platform-ca.crt", "tls Certificate")
	platformCAKey  = flag.String("platformCAKey", "certs/platform-ca.key", "tls Key")

	ekmLabel          = flag.String("ekmLabel", "EXPORTER-my_label", "label to use for the EKM (default: EXPORTER-my_label)")
	ekmContext        = flag.String("ekmContext", "mycontext", "context to use for the EKM (default: mycontext)")
	tpm               *attest.TPM
	ek                *attest.EK
	ekpubBytes        []byte
	ekCert            *x509.Certificate
	akbytes           []byte
	nkBytes           []byte
	issuedKeyderBytes []byte
)

var TPMDEVICES = []string{"/dev/tpm0", "/dev/tpmrm0"}

func OpenTPM(path string) (io.ReadWriteCloser, error) {
	if slices.Contains(TPMDEVICES, path) {
		return tpmutil.OpenTPM(path)
	} else {
		return net.Dial("tcp", path)
	}
}

type linuxCmdChannel struct {
	io.ReadWriteCloser
}

// MeasurementLog implements CommandChannelTPM20.
func (cc *linuxCmdChannel) MeasurementLog() ([]byte, error) {
	return os.ReadFile(*eventLogPath)
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

	glog.V(5).Infof("=============== HealthCheck ===============")

	pr := new(peer.Peer)

	hctx, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()
	resp, err := healthpb.NewHealthClient(conn).Check(hctx, &healthpb.HealthCheckRequest{Service: verifier.Verifier_ServiceDesc.ServiceName}, grpc.Peer(pr))
	if err != nil {
		glog.Errorf("HealthCheck failed %+v", err)
		os.Exit(1)
	}

	if resp.GetStatus() != healthpb.HealthCheckResponse_SERVING {
		glog.Errorf("service not in serving state: ", resp.GetStatus().String())
		os.Exit(1)
	}
	glog.V(5).Infof("RPC HealthChekStatus: %v\n", resp.GetStatus())

	switch info := pr.AuthInfo.(type) {
	case credentials.TLSInfo:
		authType := info.AuthType()
		sn := info.State.ServerName
		glog.V(60).Infof("AuthType, ServerName %s, %s\n", authType, sn)
		tlsInfo, ok := pr.AuthInfo.(credentials.TLSInfo)
		if !ok {
			glog.Errorf("ERROR:  Could get remote TLS")
			os.Exit(1)
		}
		ekm, err := tlsInfo.State.ExportKeyingMaterial(*ekmLabel, []byte(*ekmContext), 32)
		if err != nil {
			glog.Errorf("ERROR:  Could getting EKM %v", err)
			os.Exit(1)
		}
		glog.V(10).Infof("EKM: %s\n", hex.EncodeToString(ekm))

	default:
		glog.Errorf("Unknown AuthInfo type")
		os.Exit(1)
	}

	// first get the ek so we can stuff it into the platform cert

	var config *attest.OpenConfig
	if !slices.Contains(TPMDEVICES, *tpmPath) {
		glog.Info("Opening swtpm socket")
		rwc, err := OpenTPM(*tpmPath)
		if err != nil {
			glog.Errorf("can't open TPM %q: %v", *tpmPath, err)
			os.Exit(1)
		}
		defer func() {
			rwc.Close()
		}()

		//rwr := transport.FromReadWriter(rwc)
		config = &attest.OpenConfig{
			CommandChannel: &linuxCmdChannel{rwc},
		}
	}

	tpm, err = attest.OpenTPM(config)
	if err != nil {
		glog.Errorf("error opening TPM %v", err)
		os.Exit(1)
	}
	defer tpm.Close()

	r, err := tpm.Info()
	if err != nil {
		glog.Errorf("error getting TPMInfo %v", err)
		os.Exit(1)
	}

	//https://github.com/google/go-attestation/blob/master/attest/tpm.go#L232C1-L233C44

	// $ tpm2_getcap  properties-fixed
	// 	TPM2_PT_FIRMWARE_VERSION_1:
	//   raw: 0x20240125     <<< u16 bigendian: 8228
	// TPM2_PT_FIRMWARE_VERSION_2:
	//   raw: 0x120000

	// Manufacturer: IBM
	// VendorInfo: SW   TPM
	// FirmwareVersionMajor: 8228
	// FirmwareVersionMinor: 293

	glog.V(10).Infof("Manufacturer: %s\n", r.Manufacturer)
	glog.V(10).Infof("VendorInfo: %s\n", r.VendorInfo)
	glog.V(10).Infof("FirmwareVersionMajor: %d\n", r.FirmwareVersionMajor)
	glog.V(10).Infof("FirmwareVersionMinor: %d\n", r.FirmwareVersionMinor)

	eks, err := tpm.EKs()
	if err != nil {
		glog.Errorf("error getting EK %v", err)
		os.Exit(1)
	}

	for _, e := range eks {
		if e.Certificate != nil {
			glog.Infof("EKCert Issuer: %s", e.Certificate.Issuer)
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
	glog.V(10).Infof("EKCert SerialNumber: %d\n", ek.Certificate.SerialNumber)

	c := verifier.NewVerifierClient(conn)
	glog.V(5).Infof("=============== OfferPlatformCert ===============")

	// Now get the platformcert
	//  this step should be done by the platform issuer and their CA prior to any remote attestation protocol
	//   there are two options here:  1) either use a static platform cert, or issue one dynamically just as a demo

	// STATIC
	// // I just statically generated the platform cert on another sheildedVM with a different EKCert/TPM
	// //  i did that since i don't know how to generate and issue a platformcert in golang
	// //  but i do know how to issue one win JAVA
	// //  so, what i did created a new attribute cert on a different vm but used the same trusted CA to sign it.
	// //  the verifer will check the signature but will pretend the EKCert the attestor has has the same static serial number
	// // https://github.com/salrashid123/attribute_certificate
	// // https://en.wikipedia.org/wiki/Authorization_certificate
	// // https://github.com/openssl/openssl/issues/14648
	// // 2.1.5 Assertions Made by a Platform Certificate >  https://trustedcomputinggroup.org/wp-content/uploads/IWG_Platform_Certificate_Profile_v1p1_r19_pub_fixed.pdf

	// // for now just accept it w/o verifying its claims and move on

	// platformCert, err := os.ReadFile(*platformCertFile)
	// if err != nil {
	// 	glog.Errorf("ERROR: Unable to load parse platform certificate %v", err)
	// 	os.Exit(1)
	// }

	// Dynamic
	// //  the following generates the platform CA and injects the EK's issuer and serial number into it
	// //   this step should be done before any of the remote attestation protocol begins and should not be part
	// //   of this protocol.  The only reason i'm doing it here is to make it an end-to-end example.

	platformCACertBytes, err := os.ReadFile(*platformCACert)
	if err != nil {
		glog.Errorf("ERROR: Unable to load paltform CA %v", err)
		os.Exit(1)
	}
	platformCAKeyBytes, err := os.ReadFile(*platformCAKey)
	if err != nil {
		glog.Errorf("ERROR: Unable to load paltform CA Key %v", err)
		os.Exit(1)
	}

	pubBlock, _ := pem.Decode(platformCACertBytes)
	ccacrt, err := x509.ParseCertificate(pubBlock.Bytes)
	if err != nil {
		glog.Errorf("error parsing client ca certificate %v", err)
		os.Exit(1)
	}

	privBlock, _ := pem.Decode(platformCAKeyBytes)
	ccakey, err := x509.ParsePKCS8PrivateKey(privBlock.Bytes)
	if err != nil {
		glog.Errorf("error decoding client ca certificate ca key:  %v", err)
		os.Exit(1)
	}
	var notBefore time.Time
	notBefore = time.Now()
	notAfter := notBefore.Add(time.Hour * 24 * 365)

	// h := &attributecert.Certholder{
	// 	Issuer: ek.Certificate.Issuer,
	// 	Serial: ek.Certificate.SerialNumber,
	// }

	rdns := ek.Certificate.Issuer.ToRDNSequence()
	derBytes, err := asn1.Marshal(rdns)
	if err != nil {
		glog.Errorf("ERROR:Failed to marshal RDNSequence to DER: %v", err)
		os.Exit(1)
	}

	platformCert, err := attributecert.CreateAttributeCertificate(derBytes, ek.Certificate.SerialNumber, notBefore, notAfter, ccacrt, ccakey)
	if err != nil {
		glog.Errorf("ERROR:Failed to marshal RDNSequence to DER: %v", err)
		os.Exit(1)
	}

	_, err = c.OfferPlatformCert(ctx, &verifier.OfferPlatformCertRequest{
		PlatformCert: platformCert,
	})
	if err != nil {
		glog.Errorf("error sending platformcert: %v", err)
		os.Exit(1)
	}
	glog.V(5).Infof("Verified Platform Cert\n")

	glog.V(5).Infof("=============== OfferEK ===============")

	_, err = c.OfferEK(ctx, &verifier.OfferEKRequest{
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

	glog.V(5).Infof("Creating AK CSR")

	var akcsrtemplate = x509.CertificateRequest{
		Subject: pkix.Name{
			Organization:       []string{"Acme Co"},
			OrganizationalUnit: []string{"Enterprise"},
			Locality:           []string{"Mountain View"},
			Province:           []string{"California"},
			Country:            []string{"US"},
			CommonName:         "attestor.domain.com",
		},
		DNSNames:           []string{"attestor.domain.com"},
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	aks, err := NewTPMCrypto(&TPM{
		TPM: tpm,
		AK:  ak,
	})
	if err != nil {
		glog.Errorf("Failed to create CSR: %s", err)
		os.Exit(1)
	}

	akcsrBytes, err := x509.CreateCertificateRequest(rand.Reader, &akcsrtemplate, aks)
	if err != nil {
		glog.Errorf("Failed to create CSR: %s", err)
		os.Exit(1)
	}
	akpemcsr := pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE REQUEST",
			Bytes: akcsrBytes,
		},
	)
	glog.V(5).Infof("AK CSR \n%s\n", string(akpemcsr))
	defer ak.Close(tpm)

	_, err = c.OfferAK(ctx, &verifier.OfferAKRequest{
		AttestationParameters: attestParametersBytes.Bytes(),
		AkCsr:                 akcsrBytes,
	})
	if err != nil {
		glog.Errorf("error sending attestation parameters: %v", err)
		os.Exit(1)
	}
	glog.V(5).Infof("Verified AK \n")

	glog.V(5).Infof("=============== GetMakeCredential ===============")

	mk, err := c.GetMakeCredential(ctx, &verifier.GetMakeCredentialRequest{})
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
	glog.V(5).Infof("EncryptedCredentials Secret %s", base64.StdEncoding.EncodeToString(secret))

	glog.V(5).Infof("=============== SetActivateCredential ===============")

	_, err = c.SetActivateCredential(ctx, &verifier.SetActivateCredentialRequest{
		Secret: secret,
	})
	if err != nil {
		glog.Errorf("error sending getMakeCredentials: %v", err)
		os.Exit(1)
	}
	glog.V(5).Infof("SetActivateCredential complete \n")

	glog.V(5).Infof("=============== OfferQuote ===============")

	oq, err := c.OfferQuote(ctx, &verifier.OfferQuoteRequest{})
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

	sq, err := c.SetQuote(ctx, &verifier.SetQuoteRequest{
		PlatformAttestation: platformAttestationBytes.Bytes(),
	})
	if err != nil {
		glog.Errorf("error sending SetQuote: %v", err)
		os.Exit(1)
	}

	issuedakcrtPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: sq.AkCertificate})

	glog.V(5).Infof("Issued AK Certificate: \n%s\n", string(issuedakcrtPEM))
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
		Csr: csrBytes,
	})
	if err != nil {
		glog.Errorf("error sending GetCertificate: %v", err)
		os.Exit(1)
	}

	issuedcrtPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ccr.Certificate})

	glog.V(5).Infof("Issued Certificate: \n%s\n", string(issuedcrtPEM))

	glog.V(5).Infof("GetCertificate complete \n")

}

type TPM struct {
	_ crypto.Signer
	//_ crypto.MessageSigner // introduced in https://tip.golang.org/doc/go1.25#cryptopkgcrypto
	_   crypto.MessageSigner
	TPM *attest.TPM
	AK  *attest.AK
}

func NewTPMCrypto(conf *TPM) (TPM, error) {

	if conf.TPM == nil {
		return TPM{}, fmt.Errorf("AK TPM cannot be null")
	}

	if conf.AK == nil {
		return TPM{}, fmt.Errorf("AK cannot be null")
	}

	return *conf, nil
}

func (t TPM) Public() crypto.PublicKey {
	return t.AK.Public()
}

func (t TPM) Sign(rr io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return t.AK.SignMsg(t.TPM, digest, opts)
}

func (t TPM) SignMessage(rand io.Reader, msg []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	return t.AK.SignMsg(t.TPM, msg, opts)
}
