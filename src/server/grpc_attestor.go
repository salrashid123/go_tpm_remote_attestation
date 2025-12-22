package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"slices"

	"flag"
	"fmt"
	"net"
	"os"
	"sync"

	"github.com/golang/glog"

	"github.com/salrashid123/go_tpm_registrar/verifier"
	"golang.org/x/net/context"
	"google.golang.org/grpc"

	"github.com/google/go-attestation/attest"
	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpmutil"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

const ()

var (
	grpcport         = flag.String("grpcport", "", "grpcport")
	tlsCert          = flag.String("tlsCert", "certs/attestor.crt", "tls Certificate")
	tlsKey           = flag.String("tlsKey", "certs/attestor.key", "tls Key")
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
	} else if path == "simulator" {
		return simulator.GetWithFixedSeedInsecure(1073741825)
	} else {
		return net.Dial("tcp", path)
	}
}

type server struct {
	mu      sync.Mutex
	running bool
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

func (s *server) GetPlatformCert(ctx context.Context, in *verifier.GetPlatformCertRequest) (*verifier.GetPlatformCertResponse, error) {
	glog.V(2).Infof("======= GetPlatformCert ========")

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
	platformCert, err := os.ReadFile(*platformCertFile)
	if err != nil {
		glog.Errorf("ERROR: Unable to load parse platform certificate %v", err)
		return &verifier.GetPlatformCertResponse{}, status.Errorf(codes.FailedPrecondition, fmt.Sprintf("Failed to read platformcert %v", err))
	}
	glog.V(2).Infof("     Returning GetPlatformCert ========")
	return &verifier.GetPlatformCertResponse{
		PlatformCert: platformCert,
	}, nil
}

func (s *server) GetEK(ctx context.Context, in *verifier.GetEKRequest) (*verifier.GetEKResponse, error) {
	glog.V(2).Infof("======= GetEK ========")

	return &verifier.GetEKResponse{
		EkPub:  ekpubBytes,
		EkCert: ekCert.Raw,
	}, nil

}

func (s *server) GetAK(ctx context.Context, in *verifier.GetAKRequest) (*verifier.GetAKResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	glog.V(2).Infof("======= GetAK ========")

	ak, err := tpm.LoadAK(akbytes)
	if err != nil {
		glog.Errorf("error loading ak %v", err)
		return &verifier.GetAKResponse{}, status.Errorf(codes.Internal, "ERROR:  error loading ak")
	}
	defer ak.Close(tpm)
	attestParams := ak.AttestationParameters()
	attestParametersBytes := new(bytes.Buffer)
	err = json.NewEncoder(attestParametersBytes).Encode(attestParams)
	if err != nil {
		glog.Errorf("ERROR:  encode attestation parameters AK %v", err)
		return &verifier.GetAKResponse{}, status.Errorf(codes.Internal, "ERROR:  could generate attestationParameters")
	}
	return &verifier.GetAKResponse{
		AttestationParameters: attestParametersBytes.Bytes(),
	}, nil
}

func (s *server) Attest(ctx context.Context, in *verifier.AttestRequest) (*verifier.AttestResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	glog.V(2).Infof("======= Attest ========")

	val := ctx.Value(contextKey("event")).(event)
	glog.V(60).Infof("     Inbound gRPC request from: %s", val.PeerIP)
	glog.V(60).Infof("     Inbound EKM: %s", val.EKM)

	ak, err := tpm.LoadAK(akbytes)
	if err != nil {
		glog.Errorf("ERROR:  error loading ak AK %v", err)
		return &verifier.AttestResponse{}, status.Errorf(codes.Internal, "ERROR:  error loading ak")
	}
	defer ak.Close(tpm)
	var encryptedCredentials attest.EncryptedCredential
	err = json.Unmarshal(in.EncryptedCredentials, &encryptedCredentials)
	if err != nil {
		glog.Errorf("ERROR:  error decoding encryptedCredentials %v", err)
		return &verifier.AttestResponse{}, status.Errorf(codes.Internal, "ERROR:  error decoding encryptedCredentials")
	}

	secret, err := ak.ActivateCredential(tpm, encryptedCredentials)
	//secret, err := ak.ActivateCredentialWithEK(tpm, encryptedCredentials, *ek)
	if err != nil {
		glog.Errorf("ERROR:  error activating Credential  AK %v", err)
		return &verifier.AttestResponse{}, status.Errorf(codes.Internal, "ERROR:  error activating Credentials")
	}

	return &verifier.AttestResponse{
		Secret: secret,
	}, nil
}

func (s *server) Quote(ctx context.Context, in *verifier.QuoteRequest) (*verifier.QuoteResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	glog.V(2).Infof("======= Quote ========")

	ak, err := tpm.LoadAK(akbytes)
	if err != nil {
		glog.Errorf("ERROR:  error loading ak AK %v", err)
		return &verifier.QuoteResponse{}, status.Errorf(codes.Internal, "ERROR:  error loading ak")
	}
	defer ak.Close(tpm)
	evtLog, err := os.ReadFile(*eventLogPath)
	if err != nil {
		glog.Errorf("     Error reading eventLog %v", err)
		return &verifier.QuoteResponse{}, status.Errorf(codes.FailedPrecondition, fmt.Sprintf("Error reading eventLog: %v", err))
	}

	platformAttestation, err := tpm.AttestPlatform(ak, in.Nonce, &attest.PlatformAttestConfig{
		EventLog: evtLog,
	})
	if err != nil {
		glog.Errorf("ERROR: creating Attestation %v", err)
		return &verifier.QuoteResponse{}, status.Errorf(codes.Internal, "ERROR:  creating Attestation ")
	}

	platformAttestationBytes := new(bytes.Buffer)
	err = json.NewEncoder(platformAttestationBytes).Encode(platformAttestation)
	if err != nil {
		glog.Errorf("ERROR: encoding platformAttestationBytes %v", err)
		return &verifier.QuoteResponse{}, status.Errorf(codes.Internal, "ERROR:  encoding platformAttestationBytes ")
	}

	return &verifier.QuoteResponse{
		PlatformAttestation: platformAttestationBytes.Bytes(),
	}, nil
}

func (s *server) GetKey(ctx context.Context, in *verifier.GetAttestedKeyRequest) (*verifier.GetAttestedKeyResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	glog.V(2).Infof("======= GetTLSKey ========")

	nk, err := tpm.LoadKey(nkBytes)
	if err != nil {
		glog.Errorf("ERROR:  could not load tls key%v", err)
		return &verifier.GetAttestedKeyResponse{}, status.Errorf(codes.Internal, fmt.Sprintf("ERROR:  error tls key"))
	}
	defer nk.Close()

	keyCertificationBytes := new(bytes.Buffer)
	err = json.NewEncoder(keyCertificationBytes).Encode(nk.CertificationParameters())
	if err != nil {
		glog.Errorf("ERROR: encoding keyCertificationBytes %v", err)
		return &verifier.GetAttestedKeyResponse{}, status.Errorf(codes.Internal, fmt.Sprintf("ERROR:  encoding keyCertificationBytes "))
	}

	return &verifier.GetAttestedKeyResponse{
		Key:              issuedKeyderBytes,
		KeyCertification: keyCertificationBytes.Bytes(),
	}, nil
}

func main() {
	flag.Set("logtostderr", "true")
	flag.Set("stderrthreshold", "INFO")
	flag.Parse()

	if *grpcport == "" {
		fmt.Fprintln(os.Stderr, "missing -grpcport flag (:50051)")
		flag.Usage()
		os.Exit(2)
	}

	var err error
	glog.V(2).Info("Getting EKCert")

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

	defaultCerts, err := tls.LoadX509KeyPair(*tlsCert, *tlsKey)
	if err != nil {
		glog.Errorf("failed to create default certs: %v", err)
		os.Exit(1)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{defaultCerts},
	}
	ce := credentials.NewTLS(tlsConfig)
	lis, err := net.Listen("tcp", *grpcport)
	if err != nil {
		glog.Errorf("failed to listen: %v", err)
		os.Exit(1)
	}

	sopts := []grpc.ServerOption{grpc.MaxConcurrentStreams(10)}

	sopts = append(sopts, grpc.Creds(ce), grpc.UnaryInterceptor(authUnaryInterceptor))
	s := grpc.NewServer(sopts...)

	verifier.RegisterVerifierServer(s, &server{})

	glog.V(2).Infof("Starting gRPC server on port %v", *grpcport)
	s.Serve(lis)
}
