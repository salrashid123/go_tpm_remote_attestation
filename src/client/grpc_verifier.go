package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"hash"
	"os"
	"strconv"
	"strings"

	"github.com/golang/glog"
	"github.com/google/go-attestation/attest"
	"github.com/google/go-attestation/attributecert"
	x509ext "github.com/google/go-attestation/x509"

	"github.com/google/uuid"

	"github.com/google/go-tpm-tools/proto/tpm"
	"github.com/google/go-tpm-tools/server"

	oid "github.com/google/go-attestation/oid"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/salrashid123/go_tpm_registrar/verifier"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

const ()

var (
	address              = flag.String("host", "localhost:50051", "host:port of gRPC server")
	grpcServerName       = flag.String("grpcservername", "attestor.domain.com", "SNI for grpc server")
	tlsCert              = flag.String("tlsCert", "certs/root-ca.crt", "tls Certificate")
	platformCA           = flag.String("platformCA", "certs/IntelSigningKey_20April2017.cer", "Platform CA")
	platformCACert       = flag.String("platformCACert", "certs/platform-ca.crt", "tls Certificate")
	expectedPCRMapSHA256 = flag.String("expectedPCRMapSHA256", "0:d0c70a9310cd0b55767084333022ce53f42befbb69c059ee6c0a32766f160783", "Sealing and Quote PCRMap (as comma separated key:value).  pcr#:sha256,pcr#sha256.  Default value uses pcr0:sha256")
	ekRootCA             = flag.String("ekrootCA", "certs/ek_root.pem", "EK rootsCA")
	ekIntermediateCA     = flag.String("ekintermediateCA", "certs/ek_intermediate.pem", "EK intermediate CA")
)

func main() {
	flag.Set("logtostderr", "true")
	flag.Set("stderrthreshold", "INFO")
	flag.Parse()
	var err error

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

	// first connect to the GRPC service using default TLS certs
	//conn, err := grpc.NewClient(*address, grpc.WithTransportCredentials(insecure.NewCredentials()))
	conn, err := grpc.NewClient(*address, grpc.WithTransportCredentials(ce))
	if err != nil {
		glog.Errorf("did not connect: %v", err)
		os.Exit(1)
	}
	defer conn.Close()

	c := verifier.NewVerifierClient(conn)
	glog.V(5).Infof("=============== GetPlatformCert ===============")
	req := &verifier.GetPlatformCertRequest{}
	platformCertResponse, err := c.GetPlatformCert(ctx, req)
	if err != nil {
		glog.Errorf("Error GetPlatformCert: %v", err)
	}
	if len(platformCertResponse.PlatformCert) > 0 {
		glog.V(5).Infof("=============== GetPlatformCert Returned from remote ===============")

		// load the DER certificate, this is for validation of the static platform cert
		// rootDER, err := os.ReadFile(*platformCA)
		// if err != nil {
		// 	glog.Errorf(fmt.Sprintf("Error Reading Root platform cert %v", err))
		// 	os.Exit(1)
		// }
		// platformRoot, err := x509.ParseCertificate(rootDER)
		// if err != nil {
		// 	glog.Errorf(fmt.Sprintf("Error failed to parse certificate %v", err))
		// 	os.Exit(1)
		// }

		// for the dynamic platform cert
		rootPEM, err := os.ReadFile(*platformCACert)
		if err != nil {
			glog.Errorf(fmt.Sprintf("Error Reading Root platform cert %v", err))
			os.Exit(1)
		}
		pubBlock, _ := pem.Decode(rootPEM)
		platformRoot, err := x509.ParseCertificate(pubBlock.Bytes)
		if err != nil {
			glog.Errorf(fmt.Sprintf("Error failed to parse certificate %v", err))
			os.Exit(1)
		}

		ac, err := attributecert.ParseAttributeCertificate(platformCertResponse.PlatformCert)
		if err != nil {
			glog.Errorf(fmt.Sprintf("Error  failed to parse  attribute certificate  %v", err))
			os.Exit(1)
		}

		glog.V(20).Infof("     PlatformCertificate Issuer: %s\n", ac.Issuer)
		glog.V(20).Infof("     PlatformCertificate Version: %d\n", ac.Version)

		glog.V(20).Infof("     PlatformCertificate CredentialSpecification: %s\n", ac.CredentialSpecification)
		glog.V(20).Infof("     PlatformCertificate PlatformManufacturer: %s\n", ac.PlatformManufacturer)
		glog.V(20).Infof("     PlatformCertificate PlatformModel: %s\n", ac.PlatformModel)
		glog.V(20).Infof("     PlatformCertificate PlatformVersion: %s\n", ac.PlatformVersion)
		glog.V(20).Infof("     PlatformCertificate PropertiesURI: %s\n", ac.PropertiesURI)

		for j, c := range ac.Components {
			glog.V(20).Infof("        PlatformCertificate Components[%d].Manufacturer: %s\n", j, c.Manufacturer)
			glog.V(20).Infof("        PlatformCertificate Components[%d].ManufacturerID: %d\n", j, c.ManufacturerID)
			glog.V(20).Infof("        PlatformCertificate Components[%d].Model: %s\n", j, c.Model)
			glog.V(20).Infof("        PlatformCertificate Components[%d].Revision: %s\n", j, c.Revision)
			glog.V(20).Infof("        PlatformCertificate Components[%d].Serial: %s\n", j, c.Serial)
			for i, a := range c.Addresses {
				glog.V(20).Infof("        PlatformCertificate Components[%d].Addresses[%d].AddressType: %s\n", j, i, a.AddressType)
				glog.V(20).Infof("        PlatformCertificate Components[%d].Addresses[%d].AddressValue: %s\n", j, i, a.AddressValue)
			}
			glog.V(20).Infof("        PlatformCertificate Components[%d].FieldReplaceable: %t\n", j, c.FieldReplaceable)
		}

		glog.V(20).Infof("     PlatformCertificate Holder.Issuer: %s\n", ac.Holder.Issuer)
		glog.V(20).Infof("     PlatformCertificate Holder.Serial: %d\n", ac.Holder.Serial)
		glog.V(20).Infof("     PlatformCertificate Holder.Issuer.CommonName: %s\n", ac.Holder.Issuer.CommonName)

		for i, p := range ac.Properties {
			glog.V(20).Infof("        PlatformCertificate Properties[%d]. Name [%s] Value [%s]\n", i, p.PropertyName, p.PropertyValue)
		}
		glog.V(20).Infof("     PlatformCertificate TBBSecurityAssertions.Iso9000URI: %s\n", ac.TBBSecurityAssertions.Iso9000URI)
		glog.V(20).Infof("     PlatformCertificate TBBSecurityAssertions.CcInfo.ProfileOid: %s\n", ac.TBBSecurityAssertions.CcInfo.ProfileOid)
		glog.V(20).Infof("     PlatformCertificate TBBSecurityAssertions.CcInfo.ProfileURI: %s\n", ac.TBBSecurityAssertions.CcInfo.ProfileURI)
		glog.V(20).Infof("     PlatformCertificate TBBSecurityAssertions.CcInfo.TargetOid: %s\n", ac.TBBSecurityAssertions.CcInfo.TargetOid)
		glog.V(20).Infof("     PlatformCertificate TBBSecurityAssertions.CcInfo.TargetURI: %s\n", ac.TBBSecurityAssertions.CcInfo.TargetURI)
		glog.V(20).Infof("     PlatformCertificate TBBSecurityAssertions.CcInfo.Version: %s\n", ac.TBBSecurityAssertions.CcInfo.Version)

		glog.V(20).Infof("     PlatformCertificate TCGPlatformSpecification.Version: %d\n", ac.TCGPlatformSpecification.Version)
		glog.V(20).Infof("     PlatformCertificate TCGPlatformSpecification.Version.MajorVersion: %d\n", ac.TCGPlatformSpecification.Version.MajorVersion)
		glog.V(20).Infof("     PlatformCertificate TCGPlatformSpecification.Version.MinorVersion: %d\n", ac.TCGPlatformSpecification.Version.MinorVersion)
		glog.V(20).Infof("     PlatformCertificate TCGPlatformSpecification.Version.Revision: %d\n", ac.TCGPlatformSpecification.Version.Revision)

		glog.V(20).Infof("     PlatformCertificate UserNotice.UserNotice.ExplicitText: %s\n", ac.UserNotice.ExplicitText)
		glog.V(20).Infof("     PlatformCertificate UserNotice.UserNotice.Organization: %s\n", ac.UserNotice.NoticeRef.Organization)
		glog.V(20).Infof("     PlatformCertificate UserNotice.UserNotice.NoticeNumbers: %d\n", ac.UserNotice.NoticeRef.NoticeNumbers)

		err = ac.CheckSignatureFrom(platformRoot)
		if err != nil {
			glog.Errorf(fmt.Sprintf("Error failed to verify  attribute certificate  %v", err))
			os.Exit(1)
		}
		glog.V(20).Infof(" Verified Platform cert signed by privacyCA")

		// todo, save the serial number here...we need to compare the serail number seen here againt the EKCert (which we don't have at the point; thats done in
		// the next step
		glog.V(20).Infof(" Platform Cert's Holder SerialNumber %s\n", fmt.Sprintf("%x", ac.Holder.Serial))

		// if _, err := cert.Verify(opts); err != nil {
		// 	if err.Error() != "x509: unhandled critical extension" {
		// 		return &verifier.OfferPlatformCertResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("failed to verify platform certificate: "+err.Error()))
		// 	}
		// }
	}

	// get the EKCert;  you can also 'just read' it from certs/ekcert.epm
	//  if you downloaded it earlier and trust it; its verified later against roots.
	glog.V(5).Infof("=============== start GetEK ===============")
	ekReq := &verifier.GetEKRequest{}

	pr := new(peer.Peer)
	ekResponse, err := c.GetEK(ctx, ekReq, grpc.Peer(pr))
	if err != nil {
		glog.Errorf("GetEK Failed,   Original Error is: %v", err)
		os.Exit(1)
	}

	switch info := pr.AuthInfo.(type) {
	case credentials.TLSInfo:
		authType := info.AuthType()
		sn := info.State.ServerName
		glog.V(20).Infof("        AuthType, ServerName %s, %s\n", authType, sn)
		tlsInfo, ok := pr.AuthInfo.(credentials.TLSInfo)
		if !ok {
			glog.Errorf("ERROR:  Could get remote TLS")
			os.Exit(1)
		}
		ekm, err := tlsInfo.State.ExportKeyingMaterial("my_nonce", nil, 32)
		if err != nil {
			glog.Errorf("ERROR:  Could getting EKM %v", err)
			os.Exit(1)
		}
		glog.V(20).Infof("        EKM my_nonce: %s\n", hex.EncodeToString(ekm))
	default:
		glog.Errorf("Unknown AuthInfo type")
		os.Exit(1)
	}

	// first try to verify the ekcert
	// Note: GCE confidential vm's have ekCerts https://github.com/salrashid123/gcp-vtpm-ek-ak which you can get via API
	// the following root and intermediates are for GCE confidential VMs
	// $ gcloud compute instances get-shielded-identity attestor --format=json | jq -r '.encryptionKey.ekCert' > certs/ekcert.pem
	// $ gcloud compute instances get-shielded-identity attestor --format=json | jq -r '.signingKey.ekCert' > certs/akcert.pem
	// $ curl -s $(openssl x509 -in certs/ekcert.pem -noout -text | grep -Po "((?<=CA Issuers - URI:)http://.*)$") | openssl x509 -inform DER -outform PEM -out certs/ek_intermediate.pem
	// $ curl -s $(openssl x509 -in certs/ek_intermediate.pem -noout -text | grep -Po "((?<=CA Issuers - URI:)http://.*)$") | openssl x509 -inform DER -outform PEM -out certs/ek_root.pem
	//
	// for other TPMs,  you can get the EK on the TPM itself and verify against the manufacturers CA
	//  see https://github.com/salrashid123/tls_ak?tab=readme-ov-file#local-testing
	//
	var ekPubPEM []byte

	ekcert, err := x509.ParseCertificate(ekResponse.EkCert)
	if err != nil {
		glog.Errorf("ERROR:   ParseCertificate: %v", err)
		os.Exit(1)
	}

	// TODO compare the platform cert's holder serial# to the ekcert's serial number
	glog.V(20).Infof("     EKCert serial number should match platform Platform Cert's Holder SerialNumber %s\n", fmt.Sprintf("%x", ekcert.SerialNumber))

	// optionally parse SAN.DirName, eg:
	// pg 24,26: https://trustedcomputinggroup.org/wp-content/uploads/TCG_IWG_Credential_Profile_EK_V2.1_R13.pdf
	// X509v3 Subject Alternative Name: critical
	//   DirName:/2.23.133.2.1=id:53544D20/2.23.133.2.2=ST33HTPHAHD8/2.23.133.2.3=id:00010102
	// 2.23.133.2.1 tcg-at-tpmManufacturer TPM Manufacturer Name for EK Credential Profile for TPM 2.0
	//     id:53544D20 = hex("STM")
	// 2.23.133.2.2 tcg-at-tpmModel TPM Model Number defined in EK Credential Profile for TPM 2.0
	// 2.23.133.2.3 tcg-at-tpmVersion TPM Version defined in EK Credential Profile for TPM 2.0

	var oidExtensionSubjectAltName = []int{2, 5, 29, 17}
	var oidExtensionSubjectDirectoryAttributes = []int{2, 5, 29, 9}
	type tpmSpecification struct {
		Family   string
		Level    int
		Revision int
	}
	type attribute struct {
		Type   asn1.ObjectIdentifier
		Values []asn1.RawValue `asn1:"set"`
	}
	for _, ex := range ekcert.Extensions {
		if ex.Id.Equal(oidExtensionSubjectAltName) {
			s, err := x509ext.ParseSubjectAltName(ex)
			if err != nil {
				glog.Errorf("failed to unmarshal EK SAN " + err.Error())
				os.Exit(1)
			}
			for _, na := range s.DirectoryNames {
				for _, attr := range na.Names {
					if attr.Type.Equal(oid.TPMManufacturer) {
						glog.V(20).Infof("     TPM Manufacturer %s", attr.Value)
					}
					if attr.Type.Equal(oid.TPMModel) {
						glog.V(20).Infof("     TPM Model %s", attr.Value)
					}
					if attr.Type.Equal(oid.TPMVersion) {
						// todo: parse the major/minor version properly
						glog.V(20).Infof("     TPM Version %s", attr.Value)
					}
				}

			}
		}

		if ex.Id.Equal(oidExtensionSubjectDirectoryAttributes) {

			var attrs []attribute
			_, err := asn1.Unmarshal(ex.Value, &attrs)
			if err != nil {
				glog.Errorf("failed to parse EK SubjectDirectoryAttributes" + err.Error())
				os.Exit(1)
			}

			for _, attr := range attrs {
				if attr.Type.Equal(oid.TPMSpecification) {
					if len(attr.Values) != 1 {
						glog.Errorf("failed to parse EK SubjectDirectoryAttributes ", errors.New("expected SET size of 1"))
						os.Exit(1)
					}
					value := attr.Values[0]
					var spec tpmSpecification
					rest, err := asn1.Unmarshal(value.FullBytes, &spec)
					if err != nil {
						glog.Errorf("failed to parse EK SubjectDirectoryAttributes ", err)
						os.Exit(1)
					}
					if len(rest) != 0 {
						glog.Errorf("failed to parse EK SubjectDirectoryAttributes ", err)
						os.Exit(1)
					}
					glog.V(20).Infof("     TPM Family %s", spec.Family)
					glog.V(20).Infof("     TPM Level %d", spec.Level)
					glog.V(20).Infof("     TPM Revision %d", spec.Revision)
				}
			}
		}
	}

	// if the service is on GCP, the ekcert has some special details encoded inside it
	gceInfo, err := server.GetGCEInstanceInfo(ekcert)
	if err == nil && gceInfo != nil {
		glog.V(10).Infof("     EKCert  GCE InstanceID %d", gceInfo.InstanceId)
		glog.V(10).Infof("     EKCert  GCE InstanceName %s", gceInfo.InstanceName)
		glog.V(10).Infof("     EKCert  GCE ProjectId %s", gceInfo.ProjectId)
	}

	ekcrtPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ekResponse.EkCert})
	glog.V(2).Infof("        EKCertificate ========\n%s\n", ekcrtPEM)

	spubKey := ekcert.PublicKey.(*rsa.PublicKey)

	skBytes, err := x509.MarshalPKIXPublicKey(spubKey)
	if err != nil {
		glog.Errorf("ERROR:  could  MarshalPKIXPublicKey: %v", err)
		os.Exit(1)
	}
	ekPubPEM = pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: skBytes,
		},
	)

	glog.V(10).Infof("     EKCert  Issuer %v", ekcert.Issuer)
	glog.V(10).Infof("     EKCert  IssuingCertificateURL %v", fmt.Sprint(ekcert.IssuingCertificateURL))
	glog.V(10).Infof("     EKCert  SerialNumber %v", fmt.Sprint(ekcert.SerialNumber))

	glog.V(40).Infof("    EkCert Public Key \n%s\n", ekPubPEM)

	// now try to verify the EKCert is legit using the CA's you expect woud've signed it
	glog.V(10).Info("    Verifying EKCert")
	ekRootPEM, err := os.ReadFile(*ekRootCA)
	if err != nil {
		glog.Errorf("failed to reading roots: ", err.Error())
		os.Exit(1)
	}

	ekRoots := x509.NewCertPool()
	ok := ekRoots.AppendCertsFromPEM([]byte(ekRootPEM))
	if !ok {
		glog.Errorf("failed append to roots ")
		os.Exit(1)
	}

	var exts []asn1.ObjectIdentifier
	for _, ext := range ekcert.UnhandledCriticalExtensions {
		if ext.Equal(oidExtensionSubjectAltName) {
			continue
		}
		exts = append(exts, ext)
	}
	ekcert.UnhandledCriticalExtensions = exts

	//oid 2.23.133.8.1 tcg-kp-EKCertificate Identifies the certificate as an Endorsement Credential.
	// try to see if the ekcert includes the recommended oid as the extension value
	var tcgkpEKCertificate asn1.ObjectIdentifier = []int{2, 23, 133, 8, 1}
	for _, ku := range ekcert.UnknownExtKeyUsage {
		if ku.Equal(tcgkpEKCertificate) {
			glog.V(10).Infof("     EKCert Includes tcg-kp-EKCertificate ExtendedKeyUsage %s", ku.String())
		}
	}

	intermediatePEM, err := os.ReadFile(*ekIntermediateCA)
	if err != nil {
		glog.Errorf("failed to read intermediate CA: " + err.Error())
		os.Exit(1)
	}

	intermediates := x509.NewCertPool()
	ok = intermediates.AppendCertsFromPEM([]byte(intermediatePEM))
	if !ok {
		glog.Errorf("failed to append intermediates: ")
		os.Exit(1)
	}

	opts := x509.VerifyOptions{
		Roots:         ekRoots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsage(x509.ExtKeyUsageAny)},
	}
	if _, err := ekcert.Verify(opts); err != nil {
		glog.Errorf("failed to verify certificate: " + err.Error())
		os.Exit(1)
	}

	glog.V(10).Info("    EKCert Verified")

	glog.V(5).Infof("     EKPub: \n%s\n", ekPubPEM)

	spkiBlock, _ := pem.Decode(ekPubPEM)

	ekPubKey, err := x509.ParsePKIXPublicKey(spkiBlock.Bytes)
	if err != nil {
		glog.Errorf("ERROR:  could  parsing ek public key %v", err)
		os.Exit(1)
	}

	bblock, _ := pem.Decode(ekPubPEM)
	if bblock == nil {
		glog.Errorf("GetEK Failed,   Original Error is: %v", err)
		os.Exit(1)
	}

	glog.V(5).Infof("=============== end GetEKCert ===============")

	// now get the attestation key
	glog.V(5).Infof("=============== start GetAK ===============")
	akResponse, err := c.GetAK(ctx, &verifier.GetAKRequest{})
	if err != nil {
		glog.Errorf("GetAK Failed,  Original Error is: %v", err)
		os.Exit(1)
	}

	serverAttestationParameter := &attest.AttestationParameters{}
	reader := bytes.NewReader(akResponse.AttestationParameters)
	err = json.NewDecoder(reader).Decode(serverAttestationParameter)
	if err != nil {
		glog.Errorf("Error encoding serverAttestationParamer %v", err)
		os.Exit(1)
	}

	akp, err := attest.ParseAKPublic(serverAttestationParameter.Public)
	if err != nil {
		glog.Errorf("Error Parsing AK %v", err)
		os.Exit(1)
	}

	akpPub, err := x509.MarshalPKIXPublicKey(akp.Public)
	if err != nil {
		glog.Errorf("Error MarshalPKIXPublicKey ak %v", err)
		os.Exit(1)
	}
	akPubPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: akpPub,
		},
	)

	glog.V(5).Infof("      ak public \n%s\n", akPubPEM)
	glog.V(5).Infof("=============== end GetAK ===============")

	// do remote attestation usign the ek and ak
	glog.V(5).Infof("=============== start Attest ===============")

	params := attest.ActivationParameters{
		EK: ekPubKey,
		AK: *serverAttestationParameter,
	}

	secret, encryptedCredentials, err := params.Generate()
	if err != nil {
		glog.Errorf("Error generating make credential parameters %v", err)
		os.Exit(1)
	}
	glog.Infof("      Outbound Secret: %s\n", base64.StdEncoding.EncodeToString(secret))

	encryptedCredentialsBytes := new(bytes.Buffer)
	err = json.NewEncoder(encryptedCredentialsBytes).Encode(encryptedCredentials)
	if err != nil {
		glog.Errorf("Error encoding encryptedCredentials %v", err)
		os.Exit(1)
	}

	mcResponse, err := c.Attest(ctx, &verifier.AttestRequest{
		EncryptedCredentials: encryptedCredentialsBytes.Bytes(),
	})
	if err != nil {
		glog.Errorf("GetAK Failed,  Original Error is: %v", err)
		os.Exit(1)
	}
	glog.V(5).Infof("      Inbound Secret: %s\n", base64.StdEncoding.EncodeToString(mcResponse.Secret))

	if base64.StdEncoding.EncodeToString(mcResponse.Secret) == base64.StdEncoding.EncodeToString(secret) {
		glog.V(5).Infof("      inbound/outbound Secrets Match; accepting AK")
	} else {
		glog.Error("attestation secrets do not match; exiting")
		os.Exit(1)
	}
	glog.V(5).Infof("=============== end Attest ===============")

	// run a quote-verify operation
	glog.V(5).Infof("=============== start Quote/Verify ===============")

	nonce := []byte(uuid.New().String())
	quoteResponse, err := c.Quote(ctx, &verifier.QuoteRequest{
		Nonce: nonce,
	})
	if err != nil {
		glog.Errorf("Quote Failed,  Original Error is: %v", err)
		os.Exit(1)
	}

	// create pcr map for go-tpm-tools
	pcrMap, _, err := getPCRMap(tpm.HashAlgo_SHA256)
	if err != nil {
		glog.Errorf("  Could not get PCRMap: %s", err)
		os.Exit(1)
	}
	//vpcrs := &tpmpb.PCRs{Hash: tpmpb.HashAlgo_SHA256, Pcrs: pcrMap}

	serverPlatformAttestationParameter := &attest.PlatformParameters{}
	err = json.NewDecoder(bytes.NewReader(quoteResponse.PlatformAttestation)).Decode(serverPlatformAttestationParameter)
	if err != nil {
		glog.Errorf("Quote Failed: json decoding quote response: %v", err)
		os.Exit(1)
	}

	pub, err := attest.ParseAKPublic(serverAttestationParameter.Public)
	if err != nil {
		glog.Errorf("Quote Failed ParseAKPublic: %v", err)
		os.Exit(1)
	}

	// compare the ak provided earlier during attestation with the one bound to the quote; they must be the same
	qakBytes, err := x509.MarshalPKIXPublicKey(pub.Public)
	if err != nil {
		glog.Errorf("Error %v", err)
		os.Exit(1)
	}
	qakPubPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: qakBytes,
		},
	)

	glog.V(5).Infof("      quote-attested public \n%s\n", qakPubPEM)

	if base64.StdEncoding.EncodeToString(qakPubPEM) != base64.StdEncoding.EncodeToString(akPubPEM) {
		glog.Errorf("Attested key does not match value in quote")
		os.Exit(1)
	}

	for _, quote := range serverPlatformAttestationParameter.Quotes {
		if err := pub.Verify(quote, serverPlatformAttestationParameter.PCRs, nonce); err != nil {
			glog.Errorf("Quote Failed Verify: %v", err)
			os.Exit(1)
		}
	}

	for _, p := range serverPlatformAttestationParameter.PCRs {
		glog.V(20).Infof("     PCR: %d, verified: %t value: %s", p.Index, p.QuoteVerified(), hex.EncodeToString((p.Digest)))
		if p.DigestAlg == crypto.SHA256 {
			v, ok := pcrMap[uint32(p.Index)]
			if ok {
				if hex.EncodeToString(v) != hex.EncodeToString(p.Digest) {
					glog.Errorf("Quote Failed Verify for index: %d", p.Index)
					os.Exit(1)
				}
			}
		}
	}

	glog.V(5).Infof("     quotes verified")
	el, err := attest.ParseEventLog(serverPlatformAttestationParameter.EventLog)
	if err != nil {
		glog.Errorf("Quote Parsing EventLog Failed: %v", err)
		os.Exit(1)
	}

	for _, e := range el.Events(attest.HashSHA256) {
		glog.V(60).Infof("Event Index: %d", e.Index)
		glog.V(60).Infof("   Event Type: %s", e.Type)
		glog.V(60).Infof("   Event: %s", string(e.Data))
		// determine if SEV is enabled on GCE:
		//  see https://gist.github.com/salrashid123/0c7a4a6f7465cff19d05ac50d238cd57
		// if e.Index == 0 && e.Type.String() == "EV_NONHOST_INFO" {
		// 	sevStatus, err := server.ParseGCENonHostInfo(e.Data)
		// 	if err != nil {
		// 		glog.Errorf("Error parsing SEV Status: %v", err)
		// 		os.Exit(1)
		// 	}
		// 	glog.V(60).Infof("     EV SevStatus: %s\n", sevStatus.String())
		// }
	}

	sb, err := attest.ParseSecurebootState(el.Events(attest.HashSHA256))
	if err != nil {
		glog.Errorf("Quote Parsing ParseSecurebootState Failed: %v", err)
		os.Exit(1)
	}

	glog.V(5).Infof("     secureBoot State enabled: [%t]", sb.Enabled)

	if _, err := el.Verify(serverPlatformAttestationParameter.PCRs); err != nil {
		glog.Errorf("Quote Verify Failed: %v", err)
		os.Exit(1)
	}
	glog.V(5).Infof("=============== end Quote/Verify ===============")

	// now ask the server for the EC TLS key
	glog.V(5).Infof("=============== start NewKey ===============")

	kid := uuid.New().String()
	newKeyResponse, err := c.GetKey(ctx, &verifier.GetAttestedKeyRequest{
		Kid: kid,
	})
	if err != nil {
		glog.Errorf("newKey Failed,  Original Error is: %v", err)
		os.Exit(1)
	}

	cr := pem.EncodeToMemory(&pem.Block{Type: "Public Key", Bytes: newKeyResponse.Key})
	glog.V(2).Infof("        PublicKey ========\n%s\n", cr)

	// verify the tls key is certified by the AK
	keyCertificationParameter := &attest.CertificationParameters{}
	err = json.NewDecoder(bytes.NewReader(newKeyResponse.KeyCertification)).Decode(keyCertificationParameter)
	if err != nil {
		glog.Errorf("Key Certification  %v", err)
		os.Exit(1)
	}

	err = keyCertificationParameter.Verify(attest.VerifyOpts{
		Public: akp.Public,
		Hash:   crypto.SHA256,
	})
	if err != nil {
		glog.Errorf("Key Verification error %v", err)
		os.Exit(1)
	}

	decodedTPMNTPublic, err := tpm2.DecodePublic(keyCertificationParameter.Public)
	if err != nil {
		glog.Errorf("error parsing TPM public key structure: %v", err)
		os.Exit(1)
	}

	glog.V(20).Infof("     Key AuthPolicy [%s]", hex.EncodeToString(decodedTPMNTPublic.AuthPolicy))

	// Verify the TPM key Attributes
	// https://github.com/google/go-attestation/blob/master/attest/tpm.go#L147
	//   tpm2.FlagSignerDefault ^ tpm2.FlagRestricted
	// where
	// https://pkg.go.dev/github.com/google/go-tpm/legacy/tpm2#KeyProp
	// FlagSignerDefault = FlagSign | FlagRestricted | FlagFixedTPM | FlagFixedParent | FlagSensitiveDataOrigin | FlagUserWithAuth

	tlsKeyProps := decodedTPMNTPublic.Attributes
	glog.V(20).Infof("     Key TPM Properties mask: %d", tlsKeyProps)

	expectedAttributeMask := tpm2.FlagSign | tpm2.FlagRestricted | tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin | tpm2.FlagUserWithAuth ^ tpm2.FlagRestricted
	glog.V(20).Infof("     Key Expected Properties mask %d", expectedAttributeMask)

	if expectedAttributeMask != tlsKeyProps {
		glog.Errorf("error Key attribute mismatch, expected [%d], got [%d]", expectedAttributeMask, tlsKeyProps)
		os.Exit(1)
	}

	// extract the PEM key
	tlsPubKey, err := decodedTPMNTPublic.Key()
	if err != nil {
		glog.Errorf("error parsing getting public key for TLS Key: %v", err)
		os.Exit(1)
	}
	tlsECCPub, ok := tlsPubKey.(*ecdsa.PublicKey)
	if !ok {
		glog.Errorf("error converting tls public key to ec key: %v", err)
		os.Exit(1)
	}

	certifyPubbytes, err := x509.MarshalPKIXPublicKey(tlsECCPub)
	if err != nil {
		glog.Errorf("ERROR:  Failed to marshall certificate publcikey: %s", err)
		os.Exit(1)
	}
	certifyPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: certifyPubbytes,
		},
	)

	glog.V(5).Infof("     key verified \n%s\n", certifyPEM)
	glog.V(5).Infof("=============== end NewKey ===============")

}

func getPCRMap(algo tpm.HashAlgo) (map[uint32][]byte, []byte, error) {

	pcrMap := make(map[uint32][]byte)
	var hsh hash.Hash
	// https://github.com/tpm2-software/tpm2-tools/blob/83f6f8ac5de5a989d447d8791525eb6b6472e6ac/lib/tpm2_openssl.c#L206
	if algo == tpm.HashAlgo_SHA1 {
		hsh = sha1.New()
	}
	if algo == tpm.HashAlgo_SHA256 {
		hsh = sha256.New()
	}
	if algo == tpm.HashAlgo_SHA1 || algo == tpm.HashAlgo_SHA256 {
		for _, v := range strings.Split(*expectedPCRMapSHA256, ",") {
			entry := strings.Split(v, ":")
			if len(entry) == 2 {
				uv, err := strconv.ParseUint(entry[0], 10, 32)
				if err != nil {
					return nil, nil, fmt.Errorf(" PCR key:value is invalid in parsing %s", v)
				}
				hexEncodedPCR, err := hex.DecodeString(entry[1])
				if err != nil {
					return nil, nil, fmt.Errorf(" PCR key:value is invalid in encoding %s", v)
				}
				pcrMap[uint32(uv)] = hexEncodedPCR
				hsh.Write(hexEncodedPCR)
			} else {
				return nil, nil, fmt.Errorf(" PCR key:value is invalid %s", v)
			}
		}
	} else {
		return nil, nil, fmt.Errorf("Unknown Hash Algorithm for TPM PCRs %v", algo)
	}
	if len(pcrMap) == 0 {
		return nil, nil, fmt.Errorf(" PCRMap is null")
	}
	return pcrMap, hsh.Sum(nil), nil
}
