package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"hash"
	"math/big"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"context"

	"github.com/golang/glog"
	"github.com/google/go-attestation/attest"
	"github.com/google/go-attestation/attributecert"
	"github.com/google/go-attestation/oid"
	x509ext "github.com/google/go-attestation/x509"
	"github.com/google/go-tpm-tools/proto/tpm"
	tpmtoolsserver "github.com/google/go-tpm-tools/server"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/uuid"
	"github.com/salrashid123/go_tpm_registrar/verifier"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

const ()

type db struct {
	PlatformCert          *attributecert.AttributeCertificate
	EKCert                *x509.Certificate
	AKPub                 crypto.PublicKey
	AttestationParameters *attest.AttestationParameters
	Attested              bool
	Secret                []byte
	IssuedKey             *ecdsa.PublicKey
	IssuedCert            *x509.Certificate
	Nonce                 []byte
	AttestedKey           crypto.PublicKey
}

var (
	grpcPort             = flag.String("grpcPort", ":50051", "port of gRPC server")
	rootCert             = flag.String("rootCert", "certs/root-ca.crt", "tls Certificate")
	signingCert          = flag.String("signingCert", "certs/root-ca.crt", "tls Certificate")
	signingKey           = flag.String("signingKey", "certs/root-ca.key", "tls Certificate")
	tlsCert              = flag.String("tlsCert", "certs/verify_crt.pem", "tls Certificate")
	tlsKey               = flag.String("tlsKey", "certs/verify_key.pem", "tls Key")
	expectedPCRMapSHA256 = flag.String("expectedPCRMapSHA256", "0:d0c70a9310cd0b55767084333022ce53f42befbb69c059ee6c0a32766f160783", "Sealing and Quote PCRMap (as comma separated key:value).  pcr#:sha256,pcr#sha256.  Default value uses pcr0:sha256")
	ekRootCA             = flag.String("ekrootCA", "certs/ek_root.pem", "EK rootsCA")
	ekIntermediateCA     = flag.String("ekintermediateCA", "certs/ek_intermediate.pem", "EK intermediate CA")
	platformCA           = flag.String("platformCA", "certs/IntelSigningKey_20April2017.cer", "Platform CA")
	attestationKeys      = make(map[string]db)
)

type server struct {
	mu sync.Mutex
}

type contextKey string

const contextEventKey contextKey = "event"

type event struct {
	PeerCertificates []*x509.Certificate
	EKM              string
	PeerIP           string
}

func authUnaryInterceptor(
	ctx context.Context,
	req interface{},
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (interface{}, error) {
	var newCtx context.Context
	var peerIPPort string
	p, ok := peer.FromContext(ctx)
	if ok {
		var err error
		peerIPPort, _, err = net.SplitHostPort(p.Addr.String())
		if err != nil {
			return nil, status.Errorf(codes.PermissionDenied, "could not get Remote IP")
		}
		glog.V(60).Infof("     Connected from peer %v", peerIPPort)
		newCtx = context.WithValue(ctx, contextKey("peerIP"), peerIPPort)
	} else {
		glog.Errorf("ERROR:  Could not extract peerInfo from TLS")
		return nil, status.Errorf(codes.PermissionDenied, "ERROR:  Could not extract peerInfo from TLS")
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		glog.Errorf("ERROR:  Could get remote TLS")
		return nil, status.Errorf(codes.PermissionDenied, "ERROR: could not get remote TLS")
	}
	ekm, err := tlsInfo.State.ExportKeyingMaterial("my_nonce", nil, 32)
	if err != nil {
		glog.Errorf("ERROR:  Could getting EKM %v", err)
		return nil, status.Errorf(codes.PermissionDenied, "ERROR: error getting EKM")
	}
	glog.V(60).Infof("     EKM my_nonce: %s\n", hex.EncodeToString(ekm))

	event := &event{
		EKM:    hex.EncodeToString(ekm),
		PeerIP: peerIPPort,
	}

	newCtx = context.WithValue(newCtx, contextEventKey, *event)
	return handler(newCtx, req)
}

func (s *server) OfferPlatformCert(ctx context.Context, in *verifier.OfferPlatformCertRequest) (*verifier.OfferPlatformCertResponse, error) {
	glog.V(2).Infof("======= OfferPlatformCert ========")

	if len(in.PlatformCert) > 0 {

		// TODO, read platfromCA from file once instead of every request.
		rootDER, err := os.ReadFile(*platformCA)
		if err != nil {
			return &verifier.OfferPlatformCertResponse{}, status.Errorf(codes.Internal, "Error Reading Root platform cert %v", err)
		}

		platformRoot, err := x509.ParseCertificate(rootDER)
		if err != nil {
			return &verifier.OfferPlatformCertResponse{}, status.Errorf(codes.Internal, "Error failed to parse certificate %v", err)
		}

		ac, err := attributecert.ParseAttributeCertificate(in.PlatformCert)
		if err != nil {
			return &verifier.OfferPlatformCertResponse{}, status.Errorf(codes.Internal, "Error  failed to parse  attribute certificate  %v", err)
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
			return &verifier.OfferPlatformCertResponse{}, status.Errorf(codes.Internal, "Error [%s] failed to verify  attribute certificate  %v", err)
		}
		glog.V(20).Infof(" Verified Platform cert signed by privacyCA")

		s.mu.Lock()
		defer s.mu.Unlock()

		if val, ok := attestationKeys[in.Uid]; ok {
			val.PlatformCert = ac
			attestationKeys[in.Uid] = val
		} else {
			attestationKeys[in.Uid] = db{
				PlatformCert: ac,
			}
		}
	} else {
		return &verifier.OfferPlatformCertResponse{}, status.Errorf(codes.Internal, "ERROR:  error reading platform cert")
	}
	return &verifier.OfferPlatformCertResponse{}, nil
}

func (s *server) OfferEK(ctx context.Context, in *verifier.OfferEKRequest) (*verifier.OfferEKResponse, error) {
	glog.V(2).Infof("======= OfferEK ========")

	ekcert, err := x509.ParseCertificate(in.EkCert)
	if err != nil {
		return &verifier.OfferEKResponse{}, status.Errorf(codes.Internal, "ERROR:   ParseCertificate: %v", err)
	}

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
				return &verifier.OfferEKResponse{}, status.Errorf(codes.Internal, "failed to parse EK SubjectDirectoryAttributes %v", err.Error())
			}

			for _, attr := range attrs {
				if attr.Type.Equal(oid.TPMSpecification) {
					if len(attr.Values) != 1 {
						return &verifier.OfferEKResponse{}, status.Errorf(codes.Internal, "failed to parse EK SubjectDirectoryAttributes %v", errors.New("expected SET size of 1"))
					}
					value := attr.Values[0]
					var spec tpmSpecification
					rest, err := asn1.Unmarshal(value.FullBytes, &spec)
					if err != nil {
						return &verifier.OfferEKResponse{}, status.Errorf(codes.Internal, "failed to parse EK SubjectDirectoryAttributes %v", err)
					}
					if len(rest) != 0 {
						return &verifier.OfferEKResponse{}, status.Errorf(codes.Internal, "failed to parse EK SubjectDirectoryAttributes %v", err)
					}
					glog.V(20).Infof("     TPM Family %s", spec.Family)
					glog.V(20).Infof("     TPM Level %d", spec.Level)
					glog.V(20).Infof("     TPM Revision %d", spec.Revision)
				}
			}
		}
	}

	// if the service is on GCP, the ekcert has some special details encoded inside it
	gceInfo, err := tpmtoolsserver.GetGCEInstanceInfo(ekcert)
	if err == nil && gceInfo != nil {
		glog.V(10).Infof("     EKCert  GCE InstanceID %d", gceInfo.InstanceId)
		glog.V(10).Infof("     EKCert  GCE InstanceName %s", gceInfo.InstanceName)
		glog.V(10).Infof("     EKCert  GCE ProjectId %s", gceInfo.ProjectId)
	}

	ekcrtPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: in.EkCert})
	glog.V(2).Infof("        EKCertificate ========\n%s\n", ekcrtPEM)

	spubKey := ekcert.PublicKey.(*rsa.PublicKey)

	skBytes, err := x509.MarshalPKIXPublicKey(spubKey)
	if err != nil {
		return &verifier.OfferEKResponse{}, status.Errorf(codes.Internal, "ERROR:  could  MarshalPKIXPublicKey: %v", err)
	}
	ekPubPEM := pem.EncodeToMemory(
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
		return &verifier.OfferEKResponse{}, status.Errorf(codes.Internal, "failed to reading roots: %v", err.Error())
	}

	ekRoots := x509.NewCertPool()
	ok := ekRoots.AppendCertsFromPEM([]byte(ekRootPEM))
	if !ok {
		return &verifier.OfferEKResponse{}, status.Errorf(codes.Internal, "failed append to roots ")
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
		return &verifier.OfferEKResponse{}, status.Errorf(codes.Internal, "failed to read intermediate CA: %v", err.Error())
	}

	intermediates := x509.NewCertPool()
	ok = intermediates.AppendCertsFromPEM([]byte(intermediatePEM))
	if !ok {
		return &verifier.OfferEKResponse{}, status.Errorf(codes.Internal, "failed to append intermediates: ")
	}

	opts := x509.VerifyOptions{
		Roots:         ekRoots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsage(x509.ExtKeyUsageAny)},
	}
	if _, err := ekcert.Verify(opts); err != nil {
		return &verifier.OfferEKResponse{}, status.Errorf(codes.Internal, "failed to verify certificate: %v", err.Error())
	}

	glog.V(10).Info("    EKCert Verified")

	s.mu.Lock()
	defer s.mu.Unlock()

	if val, ok := attestationKeys[in.Uid]; ok {
		if val.PlatformCert != nil {
			// do some validation of the platform cert and EK here
		}
		val.EKCert = ekcert
		attestationKeys[in.Uid] = val
	} else {
		attestationKeys[in.Uid] = db{
			EKCert: ekcert,
		}
	}

	glog.V(5).Infof("=============== end OfferEK ===============")
	return &verifier.OfferEKResponse{}, nil
}

func (s *server) OfferAK(ctx context.Context, in *verifier.OfferAKRequest) (*verifier.OfferAKResponse, error) {
	glog.V(2).Infof("======= OfferAK ========")

	s.mu.Lock()
	defer s.mu.Unlock()
	if val, ok := attestationKeys[in.Uid]; ok {
		if val.EKCert == nil {
			return &verifier.OfferAKResponse{}, status.Errorf(codes.Internal, "Error cannot process AK before calling OfferEK")
		}
	} else {
		return &verifier.OfferAKResponse{}, status.Errorf(codes.Internal, "Error cannot process AK before calling OfferEK")
	}

	serverAttestationParameter := &attest.AttestationParameters{}
	reader := bytes.NewReader(in.AttestationParameters)
	err := json.NewDecoder(reader).Decode(serverAttestationParameter)
	if err != nil {
		return &verifier.OfferAKResponse{}, status.Errorf(codes.Internal, "Error encoding serverAttestationParamer %v", err)
	}

	akp, err := attest.ParseAKPublic(attest.TPMVersion20, serverAttestationParameter.Public)
	if err != nil {
		return &verifier.OfferAKResponse{}, status.Errorf(codes.Internal, "Error Parsing AK %v", err)
	}

	akpPub, err := x509.MarshalPKIXPublicKey(akp.Public)
	if err != nil {
		return &verifier.OfferAKResponse{}, status.Errorf(codes.Internal, "Error MarshalPKIXPublicKey ak %v", err)
	}
	akPubPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: akpPub,
		},
	)

	glog.V(5).Infof("      ak public \n%s\n", akPubPEM)

	val := attestationKeys[in.Uid]
	val.AKPub = akp.Public
	val.AttestationParameters = serverAttestationParameter
	attestationKeys[in.Uid] = val

	glog.V(5).Infof("=============== end GetAK ===============")

	return &verifier.OfferAKResponse{}, nil
}

func (s *server) GetMakeCredential(ctx context.Context, in *verifier.GetMakeCredentialRequest) (*verifier.GetMakeCredentialResponse, error) {
	glog.V(2).Infof("======= GetMakeCredential ========")

	s.mu.Lock()
	defer s.mu.Unlock()
	if val, ok := attestationKeys[in.Uid]; ok {
		if val.EKCert == nil || val.AKPub == nil {
			return &verifier.GetMakeCredentialResponse{}, status.Errorf(codes.Internal, "Error MakeCredential requires AK and EK")
		}
	} else {
		return &verifier.GetMakeCredentialResponse{}, status.Errorf(codes.Internal, "Error MakeCredential requires AK and EK")
	}
	glog.V(5).Infof("=============== end GetMakeCredential ===============")

	val := attestationKeys[in.Uid]

	params := attest.ActivationParameters{
		TPMVersion: attest.TPMVersion20,
		EK:         val.EKCert.PublicKey,
		AK:         *val.AttestationParameters,
	}

	secret, encryptedCredentials, err := params.Generate()
	if err != nil {
		return &verifier.GetMakeCredentialResponse{}, status.Errorf(codes.Internal, "Error generating make credential parameters %v", err)
	}
	glog.Infof("      Outbound Secret: %s\n", base64.StdEncoding.EncodeToString(secret))

	encryptedCredentialsBytes := new(bytes.Buffer)
	err = json.NewEncoder(encryptedCredentialsBytes).Encode(encryptedCredentials)
	if err != nil {
		return &verifier.GetMakeCredentialResponse{}, status.Errorf(codes.Internal, "Error encoding encryptedCredentials %v", err)
	}

	val.Secret = secret
	attestationKeys[in.Uid] = val

	return &verifier.GetMakeCredentialResponse{
		EncryptedCredentials: encryptedCredentialsBytes.Bytes(),
	}, nil
}

func (s *server) SetActivateCredential(ctx context.Context, in *verifier.SetActivateCredentialRequest) (*verifier.SetActivateCredentialResponse, error) {
	glog.V(2).Infof("======= SetActivateCredential ========")

	s.mu.Lock()
	defer s.mu.Unlock()
	if val, ok := attestationKeys[in.Uid]; ok {

		if val.EKCert == nil || val.AKPub == nil || val.AttestationParameters == nil {
			return &verifier.SetActivateCredentialResponse{}, status.Errorf(codes.Internal, "Error SetActivateCredential requires AK and EK and AttestationParameters")
		}
	} else {
		return &verifier.SetActivateCredentialResponse{}, status.Errorf(codes.Internal, "Error SetActivateCredential requires AK and EK and AttestationParameters")
	}

	val := attestationKeys[in.Uid]

	if !bytes.Equal(val.Secret, in.Secret) {
		return &verifier.SetActivateCredentialResponse{}, status.Errorf(codes.Internal, "Error SetActivateCredential secrets not equal")
	}

	vv := attestationKeys[in.Uid]
	vv.Attested = true

	attestationKeys[in.Uid] = vv

	glog.V(5).Infof("=============== end SetActivateCredential ===============")
	return &verifier.SetActivateCredentialResponse{}, nil
}

func (s *server) OfferQuote(ctx context.Context, in *verifier.OfferQuoteRequest) (*verifier.OfferQuoteResponse, error) {
	glog.V(2).Infof("======= OfferQuote ========")

	s.mu.Lock()
	defer s.mu.Unlock()
	if val, ok := attestationKeys[in.Uid]; ok {
		if val.EKCert == nil || val.AKPub == nil || val.AttestationParameters == nil || !val.Attested {
			return &verifier.OfferQuoteResponse{}, status.Errorf(codes.Internal, "Error OfferQuote requires AK and EK and AttestationParameters and must be Attested first")
		}
	} else {
		return &verifier.OfferQuoteResponse{}, status.Errorf(codes.Internal, "Error OfferQuote requires AK and EK and AttestationParameters and must be Attested first")
	}

	nonce := []byte(uuid.New().String())

	vv := attestationKeys[in.Uid]
	vv.Nonce = nonce

	attestationKeys[in.Uid] = vv

	glog.V(5).Infof("=============== end OfferQuote ===============")
	return &verifier.OfferQuoteResponse{
		Nonce: nonce,
	}, nil
}

func (s *server) SetQuote(ctx context.Context, in *verifier.SetQuoteRequest) (*verifier.SetQuoteResponse, error) {
	glog.V(2).Infof("======= SetQuote ========")

	s.mu.Lock()
	defer s.mu.Unlock()
	if val, ok := attestationKeys[in.Uid]; ok {
		if val.EKCert == nil || val.AKPub == nil || val.AttestationParameters == nil || !val.Attested || val.Nonce == nil {
			return &verifier.SetQuoteResponse{}, status.Errorf(codes.Internal, "Error OfferQuote requires AK and EK and AttestationParameters, OfferQuote(nonce) and must be Attested first")
		}
	} else {

		return &verifier.SetQuoteResponse{}, status.Errorf(codes.Internal, "Error OfferQuote requires AK and EK and AttestationParameters,OfferQuote(nonce) and must be Attested first")
	}

	vv := attestationKeys[in.Uid]

	// create pcr map for go-tpm-tools
	pcrMap, _, err := getPCRMap(*expectedPCRMapSHA256, tpm.HashAlgo_SHA256)
	if err != nil {
		return &verifier.SetQuoteResponse{}, status.Errorf(codes.Internal, "  Could not get PCRMap: %s", err)
	}
	//vpcrs := &tpmpb.PCRs{Hash: tpmpb.HashAlgo_SHA256, Pcrs: pcrMap}

	serverPlatformAttestationParameter := &attest.PlatformParameters{}
	err = json.NewDecoder(bytes.NewReader(in.PlatformAttestation)).Decode(serverPlatformAttestationParameter)
	if err != nil {
		return &verifier.SetQuoteResponse{}, status.Errorf(codes.Internal, "Quote Failed: json decoding quote response: %v", err)
	}

	pub, err := attest.ParseAKPublic(attest.TPMVersion20, serverPlatformAttestationParameter.Public)
	if err != nil {
		return &verifier.SetQuoteResponse{}, status.Errorf(codes.Internal, "Quote Failed ParseAKPublic: %v", err)
	}

	// compare the ak provided earlier during attestation with the one bound to the quote; they must be the same
	qakBytes, err := x509.MarshalPKIXPublicKey(pub.Public)
	if err != nil {
		return &verifier.SetQuoteResponse{}, status.Errorf(codes.Internal, "Error MarshalPKIPublicKey for Quote %v", err)
	}
	qakPubPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: qakBytes,
		},
	)

	glog.V(5).Infof("      quote-attested public \n%s\n", qakPubPEM)

	akpPub, err := x509.MarshalPKIXPublicKey(vv.AKPub)
	if err != nil {
		return &verifier.SetQuoteResponse{}, status.Errorf(codes.Internal, "Error MarshalPKIXPublicKey ak %v", err)
	}
	akPubPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: akpPub,
		},
	)

	if base64.StdEncoding.EncodeToString(qakPubPEM) != base64.StdEncoding.EncodeToString(akPubPEM) {
		return &verifier.SetQuoteResponse{}, status.Errorf(codes.Internal, "Attested key does not match value in quote")
	}

	for _, quote := range serverPlatformAttestationParameter.Quotes {
		if err := pub.Verify(quote, serverPlatformAttestationParameter.PCRs, vv.Nonce); err != nil {
			return &verifier.SetQuoteResponse{}, status.Errorf(codes.Internal, " Quote Failed Verify: %v", err)
		}
	}

	for _, p := range serverPlatformAttestationParameter.PCRs {
		glog.V(20).Infof("     PCR: %d, verified: %t value: %s", p.Index, p.QuoteVerified(), hex.EncodeToString((p.Digest)))
		if p.DigestAlg == crypto.SHA256 {
			v, ok := pcrMap[uint32(p.Index)]
			if ok {
				if hex.EncodeToString(v) != hex.EncodeToString(p.Digest) {
					return &verifier.SetQuoteResponse{}, status.Errorf(codes.Internal, "Quote Failed Verify for index: %d", p.Index)
				}
			}
		}
	}

	glog.V(5).Infof("     quotes verified")
	el, err := attest.ParseEventLog(serverPlatformAttestationParameter.EventLog)
	if err != nil {
		return &verifier.SetQuoteResponse{}, status.Errorf(codes.Internal, "Quote Parsing EventLog Failed: %v", err)
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
		// 		return &verifier.SetQuoteResponse{}, status.Errorf(codes.Internal, "Error parsing SEV Status: %v", err)
		// 	}
		// 	glog.V(60).Infof("     EV SevStatus: %s\n", sevStatus.String())
		// }
	}

	sb, err := attest.ParseSecurebootState(el.Events(attest.HashSHA256))
	if err != nil {
		return &verifier.SetQuoteResponse{}, status.Errorf(codes.Internal, "Quote Parsing ParseSecurebootState Failed: %v", err)
	}

	glog.V(5).Infof("     secureBoot State enabled: [%t]", sb.Enabled)

	if _, err := el.Verify(serverPlatformAttestationParameter.PCRs); err != nil {
		return &verifier.SetQuoteResponse{}, status.Errorf(codes.Internal, "Quote Verify Failed: %v", err)
	}

	glog.V(5).Infof("=============== end SetQuote ===============")
	return &verifier.SetQuoteResponse{}, nil
}

func (s *server) SetAttestedKey(ctx context.Context, in *verifier.SetAttestedKeyRequest) (*verifier.SetAttestedKeyResponse, error) {
	glog.V(2).Infof("======= SetAttestedKey ========")

	s.mu.Lock()
	defer s.mu.Unlock()
	if val, ok := attestationKeys[in.Uid]; ok {
		if val.EKCert == nil || val.AKPub == nil || val.AttestationParameters == nil || !val.Attested || val.Nonce == nil {
			return &verifier.SetAttestedKeyResponse{}, status.Errorf(codes.Internal, "Error SetAttestedKey requires AK and EK and AttestationParameters, OfferQuote(nonce) and must be Attested first")
		}
	} else {
		return &verifier.SetAttestedKeyResponse{}, status.Errorf(codes.Internal, "Error SetAttestedKey requires AK and EK and AttestationParameters,OfferQuote(nonce) and must be Attested first")
	}

	vv := attestationKeys[in.Uid]

	//cr := pem.EncodeToMemory(&pem.Block{Type: "Public Key", Bytes: in.Key})
	glog.V(2).Infof("        New PublicKey ========")

	// verify the tls key is certified by the AK
	keyCertificationParameter := &attest.CertificationParameters{}
	err := json.NewDecoder(bytes.NewReader(in.KeyCertification)).Decode(keyCertificationParameter)
	if err != nil {
		return &verifier.SetAttestedKeyResponse{}, status.Errorf(codes.Internal, "Key Certification  %v", err)
	}

	err = keyCertificationParameter.Verify(attest.VerifyOpts{
		Public: vv.AKPub,
		Hash:   crypto.SHA256,
	})
	if err != nil {
		return &verifier.SetAttestedKeyResponse{}, status.Errorf(codes.Internal, "Key Verification error %v", err)
	}

	decodedTPMNTPublic, err := tpm2.DecodePublic(keyCertificationParameter.Public)
	if err != nil {
		return &verifier.SetAttestedKeyResponse{}, status.Errorf(codes.Internal, "error parsing TPM public key structure: %v", err)
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
		return &verifier.SetAttestedKeyResponse{}, status.Errorf(codes.Internal, "error Key attribute mismatch, expected [%d], got [%d]", expectedAttributeMask, tlsKeyProps)
	}

	// extract the PEM key
	tlsPubKey, err := decodedTPMNTPublic.Key()
	if err != nil {
		glog.Errorf("error parsing getting public key for TLS Key: %v", err)
		os.Exit(1)
	}
	tlsECCPub, ok := tlsPubKey.(*ecdsa.PublicKey)
	if !ok {
		return &verifier.SetAttestedKeyResponse{}, status.Errorf(codes.Internal, "error converting tls public key to ec key: %v", err)
	}

	certifyPubbytes, err := x509.MarshalPKIXPublicKey(tlsECCPub)
	if err != nil {
		return &verifier.SetAttestedKeyResponse{}, status.Errorf(codes.Internal, "ERROR:  Failed to marshall certificate publcikey: %s", err)
	}
	certifyPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: certifyPubbytes,
		},
	)

	vv.IssuedKey = tlsECCPub
	attestationKeys[in.Uid] = vv
	glog.V(5).Infof("     key verified \n%s\n", certifyPEM)

	glog.V(5).Infof("=============== end SetAttestedKey ===============")
	return &verifier.SetAttestedKeyResponse{}, nil
}

func (s *server) GetCertificate(ctx context.Context, in *verifier.GetCertificateRequest) (*verifier.GetCertificateResponse, error) {
	glog.V(2).Infof("======= GetCertificate ========")

	s.mu.Lock()
	defer s.mu.Unlock()
	if val, ok := attestationKeys[in.Uid]; ok {
		if val.EKCert == nil || val.AKPub == nil || val.AttestationParameters == nil || !val.Attested || val.Nonce == nil || val.IssuedKey == nil {
			return &verifier.GetCertificateResponse{}, status.Errorf(codes.Internal, "Error GetCertificate requires AK and EK and AttestationParameters, OfferQuote(nonce), SetAttestedKey and must be Attested first")
		}
	} else {
		return &verifier.GetCertificateResponse{}, status.Errorf(codes.Internal, "Error GetCertificate requires AK and EK and AttestationParameters,OfferQuote(nonce),SetAttestedKey and must be Attested first")
	}
	csr, err := x509.ParseCertificateRequest(in.Csr)
	if err != nil {
		return &verifier.GetCertificateResponse{}, status.Errorf(codes.Internal, "Failed to create CSR: %s", err)
	}

	val := attestationKeys[in.Uid]
	if !val.IssuedKey.Equal(csr.PublicKey.(*ecdsa.PublicKey)) {
		return &verifier.GetCertificateResponse{}, status.Errorf(codes.Internal, "Public Key provided does not match attested public newkey")
	}

	glog.V(5).Infof("Creating public x509")

	// todo, read the signing key on startup instead of each rpc

	// read the root cert and key that will sign the client cert
	clientCAcrtBytes, err := os.ReadFile(*signingCert)
	if err != nil {
		return &verifier.GetCertificateResponse{}, status.Errorf(codes.Internal, "did not load clientCA certificate: %v", err)
	}

	block, _ := pem.Decode(clientCAcrtBytes)
	if block == nil {
		return &verifier.GetCertificateResponse{}, status.Errorf(codes.Internal, "error reading client ca certificate file %v", err)
	}
	ccacrt, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return &verifier.GetCertificateResponse{}, status.Errorf(codes.Internal, "error parsing client ca certificate  %v", err)
	}

	clientCAKeyBytes, err := os.ReadFile(*signingKey)
	if err != nil {
		return &verifier.GetCertificateResponse{}, status.Errorf(codes.Internal, "error reading client ca certificate private key: %v", err)
	}
	caPrivPem, _ := pem.Decode(clientCAKeyBytes)
	ccakey, err := x509.ParsePKCS8PrivateKey(caPrivPem.Bytes)
	if err != nil {
		return &verifier.GetCertificateResponse{}, status.Errorf(codes.Internal, "error decoding client ca certificate ca key %v", err)
	}

	var notBefore time.Time
	notBefore = time.Now()

	notAfter := notBefore.Add(time.Hour * 24 * 365)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return &verifier.GetCertificateResponse{}, status.Errorf(codes.Internal, "Failed to generate serial number: %s", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization:       []string{"Acme Co"},
			OrganizationalUnit: []string{"Enterprise"},
			Locality:           []string{"Mountain View"},
			Province:           []string{"California"},
			Country:            []string{"US"},
			CommonName:         csr.Subject.CommonName,
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		DNSNames:              csr.DNSNames,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, ccacrt, csr.PublicKey, ccakey)
	if err != nil {
		return &verifier.GetCertificateResponse{}, status.Errorf(codes.Internal, "Failed to create certificate: %s", err)
	}

	glog.V(5).Infof("=============== end GetCertificate ===============")
	return &verifier.GetCertificateResponse{
		Certificate: derBytes,
	}, nil
}

func main() {
	flag.Set("logtostderr", "true")
	flag.Set("stderrthreshold", "INFO")
	flag.Parse()
	var err error

	defaultCerts, err := tls.LoadX509KeyPair(*tlsCert, *tlsKey)
	if err != nil {
		glog.Errorf("failed to create default certs: %v", err)
		os.Exit(1)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{defaultCerts},
	}
	ce := credentials.NewTLS(tlsConfig)
	lis, err := net.Listen("tcp", *grpcPort)
	if err != nil {
		glog.Errorf("failed to listen: %v", err)
		os.Exit(1)
	}

	sopts := []grpc.ServerOption{grpc.MaxConcurrentStreams(10)}

	sopts = append(sopts, grpc.Creds(ce), grpc.UnaryInterceptor(authUnaryInterceptor))
	s := grpc.NewServer(sopts...)

	verifier.RegisterVerifierServer(s, &server{})

	glog.V(2).Infof("Starting gRPC server on port %v", *grpcPort)
	s.Serve(lis)
}

func getPCRMap(expectedPCRMapSHA256 string, algo tpm.HashAlgo) (map[uint32][]byte, []byte, error) {

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
		for _, v := range strings.Split(expectedPCRMapSHA256, ",") {
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
