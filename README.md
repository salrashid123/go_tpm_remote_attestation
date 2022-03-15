# TPM Remote Attestation protocol using go-tpm and gRPC (pull)

This repo contains a sample `gRPC` client server application that uses a Trusted Platform Module for:

* TPM [Remote Attestation](https://tpm2-software.github.io/tpm2-tss/getting-started/2019/12/18/Remote-Attestation.html)
* TPM [Quote-Verify](https://github.com/salrashid123/tpm2/tree/master/quote_verify)
* Sealed and PCR bound Transfer of RSA or AES keys.
* Parse TPM EventLog


Note: there are two branches to this repository:  `push` and `pull`

The main difference between them is which side initiates communication to attest a TPM.

* In the `push` model, the `verifier` is a remote server which *makes* an outbound API call _to_ the TPM device (`attestor`).  The TPM device now performs remote attestation but is driven by the the API calls from the remote server.

* In the `pull` model, the `verifier` is a remote server which *receives* an outbound API call _from_ the TPM device (`attestor`).  The TPM device is in control of when to initiate and perform remote attestation.


This gRPC specification in the `pull` model has several methods included in the flow here

```protobuf
service Verifier {

  Attestor acquires the Platform Certificate (if available)
    and sends that to the verifier
  rpc OfferPlatformCert (OfferPlatformCertRequest) returns (OfferPlatformCertResponse) { }  

  Attestor creates AK, EK and sends that to the Verifier
  Verifier check EK Certificate issuer, generates secret nonce using EK,AK
     and return that to Attestor  
  rpc MakeCredential (MakeCredentialRequest) returns (MakeCredentialResponse) { }

  Attestor uses TPM to decrypt nonce and sends that to Verifier
  Verifier checks nonce values are same; associates AK with EK
  rpc ActivateCredential (ActivateCredentialRequest) returns (ActivateCredentialResponse) { }

  Attestor offers to provide a FULL attestation over all PCRs
  Verifier generates a nonce and returns that to the Attestor
  rpc OfferAttestation (OfferAttestationRequest) returns (OfferAttestationResponse) { }

  Attestor uses TPM to generate a full Attestation object that includes all PCRs and EventLog
  Attestor returns attestation blob to Verifier
  Verifier checks the signature of the attestation blob matches AK, verifies EventLog and Nonce, PCR values
  rpc ProvideAttestation (ProvideAttestationRequest) returns (ProvideAttestationResponse) { }

  Attestor offers to provide a quote
  Verifier selects PCR value to use and a nonce and returns that to Attestor
  rpc OfferQuote (OfferQuoteRequest) returns (OfferQuoteResponse) { }

  Attestor uses TPM to generate Quote using PCR and seals the nonce into the attestation
  Attestor return attestation and Signature
  Verifier confirms attestation signature using AK
  rpc ProvideQuote (ProvideQuoteRequest) returns (ProvideQuoteResponse) { }

  Attestor requests remote arbitrary RSA or AES secret from Verifier
  Verifier uses EK to encrypt the RSA or AES key and return to Attestor
  Attestor decrypts AES key using TPM.
  Attestor embeds RSA key into TPM.
  rpc GetSecret (GetSecretRequest) returns (GetSecretResponse) { }  

  Attestor generates an RSA key on TPM
  Attestor Certifies the RSA key using AK and receives attestation blob
  Attestor uses RSA key to generate a CSR
  Attestor sends TPM wire format for the generated RSA Public, CSR, attestation blob to Verifier
  Verifier confirms AK signed the attestation blog
  Verifier extracts the RSA public key from CSR and confirms it matches the key encoded into the attestation blob
  Verifier checks that the TPM wire format for the public key has the correct TPM template
  Verifier extracts the RSA Public key from the TPM Wire format and cross checks with the CSR's RSA Public key   
  Verifier uses CA to sign the CSR
  Verifier returns x509 to Attestor
  rpc OfferCSR (OfferCSRRequest) returns (OfferCSRResponse) { }  
}
```

![images/flow.png](images/flow.png)


>>> **NOTE** the code and procedure outlined here is **NOT** supported by google.


You can use this standalone to setup a gRPC client/server for remote attestation.

There are two parts:

* `attestor`:  a `gRPC` client which makes outbound from a grpcServer (`verifier`), which inturn performs attestation, quote/verify and then then securely receives a sealed key from a verifier to the attestor.  The key is distributed such that it can _only_ get loaded or decoded on the attestor that has the TPM

* `verifier`: a `gRPC` server which accepts connections from attestor and then performs remote attestation, quote/verify, sealed transfer of keys as viewed from a server's end

---

As you can see, the whole protocol is rather complicated but hinges on being able to trust the initial Endorsement Key.   As mentioned, this is normally done by validating that the EndorsementPublic certificate is infact real and signed by a 3rd party (eg, the manufacturer of the TPM).   This protocol also "validates" the PlatformCA which itself includes a reference (serial# reference) to the EndorsementKey.  I suppose it can contain the hash of the EKcert as another attribute...

---

also see

 - [go-attestation](https://github.com/google/go-attestation)

## Setup

We will use a GCP Shielded VM for these tests

First create several VMs

```bash
# Attestor
## debian 10
gcloud compute instances create attestor \
  --zone=us-central1-a --machine-type=e2-medium --no-service-account --no-scopes \
  --image=debian-11-bullseye-v20211105 --image-project=debian-cloud  \
  --shielded-secure-boot --shielded-vtpm --shielded-integrity-monitoring

# Verifier
gcloud compute instances create verifier \
  --zone=us-central1-a --machine-type=e2-medium --no-service-account --no-scopes \
  --image=debian-11-bullseye-v20211105 --image-project=debian-cloud  \
  --shielded-secure-boot --shielded-vtpm --shielded-integrity-monitoring
```

On each, install `go 1.16+` and setup `libtspi-dev`, `gcc` (`apt-get update && apt-get install gcc libtspi-dev`) only on the `Verifier`

```bash
apt-get update
apt-get install libtspi-dev wget gcc -y

wget https://golang.org/dl/go1.17.linux-amd64.tar.gz
rm -rf /usr/local/go && tar -C /usr/local -xzf go1.17.linux-amd64.tar.gz
```

the client  VM, edit `/etc/hosts`

and set the value of `verify.esodemoapp2.com` to the IP of the server (in my case, its `10.128.0.58`)

```
10.128.0.58 verify.esodemoapp2.com
```

ofcourse you can use any hostname here but the certificated provided in this repo matches the SAN values for TLS.

Note, if you use `--importMode=AES` on server, use `--importMode=AES` on the client

## PCR values

First note the PCR values the shielded VM uses.

For `Debian 11 with SecureBoot`, the values are:

```bash
# uname -a
  5.10.0-9-cloud-amd64 #1 SMP Debian 5.10.70-1 (2021-09-30) x86_64 GNU/Linux

$ tpm2_pcrread  sha1:0,7+sha256:0,7
  sha1:
    0 : 0x0F2D3A2A1ADAA479AEECA8F5DF76AADC41B862EA
    7 : 0xACFD7EACCC8F855AA27B2C05B8B1C7C982BFBBFA
  sha256:
    0 : 0x24AF52A4F429B71A3184A6D64CDDAD17E54EA030E2AA6576BF3A5A3D8BD3328F
    7 : 0x3D91599581F7A3A3A1BB7C7A55A7B8A50967BE6506A5F47A9E89FEF756FAB07A
```
You can derive the PCR values using  `tpm2_tools` ([installation instructions](https://github.com/salrashid123/tpm2#installing-tpm2_tools-golang)
) or the go sample [here](https://gist.github.com/salrashid123/5b6b5c93fc305c7f751ced81650542d3)

We will use the PCR values to validate remote state (quote/verify) and for sealed transfer of either an AES or RSA key

### AES
```bash
## Verifier
go run src/verifier.go \
  --grpcport :50051  -aes256Key "G-KaPdSgUkXp2s5v8y/B?E(H+MbQeThW" \
  --expectedPCRMapSHA256 0:24af52a4f429b71a3184a6d64cddad17e54ea030e2aa6576bf3a5a3d8bd3328f,7:3d91599581f7a3a3a1bb7c7a55a7b8a50967be6506a5f47a9e89fef756fab07a \
   -expectedPCRMapSHA1 0:0f2d3a2a1adaa479aeeca8f5df76aadc41b862ea \
   --importMode=AES \
   --cacert  certs/CA_crt.pem \
   --platformCA certs/CA_crt.pem \
   --servercert certs/server_crt.pem \
   --serverkey certs/server_key.pem \
   --usemTLS \
   --readEventLog \
   --v=10 -alsologtostderr

## Attestor
go run src/attestor.go  \
   --uid 369c327d-ad1f-401c-aa91-d9b0e69bft67  \
   --unsealPcrs=0,7  \
   --host verify.esodemoapp2.com:50051 \
   --cacert certs/CA_crt.pem  \
   --clientcert certs/client_crt.pem \
   --clientkey certs/client_key.pem \
   --platformCertFile certs/platform_cert.der \
   --usemTLS  \
   --readEventLog \
   --useFullAttestation \
   --v=10 -alsologtostderr
```

### RSA

```bash
## Verifier
go run src/verifier.go \
   --grpcport :50051 \
   --expectedPCRMapSHA256 0:24af52a4f429b71a3184a6d64cddad17e54ea030e2aa6576bf3a5a3d8bd3328f,7:3d91599581f7a3a3a1bb7c7a55a7b8a50967be6506a5f47a9e89fef756fab07a \
   -expectedPCRMapSHA1 0:0f2d3a2a1adaa479aeeca8f5df76aadc41b862ea \
   -importMode=RSA \
   --cacert  certs/CA_crt.pem  \
   --servercert certs/server_crt.pem \
   --serverkey certs/server_key.pem \
   --platformCA certs/CA_crt.pem \
   --usemTLS \
   --readEventLog \
   --v=10 -alsologtostderr

## Attestor
go run src/attestor.go  \
   --uid 369c327d-ad1f-401c-aa91-d9b0e69bft67  \
   --unsealPcrs=0,7  \
   --host verify.esodemoapp2.com:50051 \
   --cacert certs/CA_crt.pem  \
   --clientcert certs/client_crt.pem \
   --clientkey certs/client_key.pem \
   --platformCertFile certs/platform_cert.der \
   --usemTLS \
   --readEventLog \
   --useFullAttestation \
   --v=10 -alsologtostderr
```


You can find a sample event log for the AES example under the `example/` folder

---

### Platform Certificate

The platform certificate used in this protocol is just a sample, static one tied to a ShieldedVM's EKCert serial number.

I did this because i do not know how to generate a platform cert in go.  Instead i used  NSA's [Platform Attribute Certificate Creator (paccor)](https://github.com/nsacyber/paccor) in java to create the cert separately.

What this means is we just make believe/pretend that the platform cert is valid by statically comparing the serialnumbers. In reality the verifier should check the certificate serial number and that a valid privacy ca signed the cert..

[Attribute Certificate](https://github.com/salrashid123/attribute_certificate).


Note a sample serial number that is in the EKCert

```bash
tpm2_nvread -o ekcert.der 0x01c00002
openssl x509 -in ekcert.der -inform DER -outform PEM -out ekcert.pem

# openssl x509 -in ekcert.der -inform DER -outform PEM -out ekcert.pem
openssl x509 -in ekcert.pem -text
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            01:43:f2:f9:3e:d0:12:42:d6:86:88:fb:48:ba:7c:b9:9e:dd:50
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C = US, ST = California, L = Mountain View, O = Google LLC, OU = Cloud, CN = "tpm_ek_v1_cloud_host-signer-0-2021-10-12T04:22:11-07:00 K:1, 3:nbvaGZFLcuc:0:18"
```

and the encoded reference of the same in the `platform_cert.der`

```bash
$ openssl asn1parse -inform DER -in certs/platform_cert.der
    0:d=0  hl=4 l=1268 cons: SEQUENCE          
    4:d=1  hl=4 l= 988 cons: SEQUENCE          
    8:d=2  hl=2 l=   1 prim: INTEGER           :01
   11:d=2  hl=3 l= 218 cons: SEQUENCE          
...
.
  121:d=7  hl=2 l=  88 cons: SET               
  123:d=8  hl=2 l=  86 cons: SEQUENCE          
  125:d=9  hl=2 l=   3 prim: OBJECT            :commonName
  130:d=9  hl=2 l=  79 prim: UTF8STRING        :tpm_ek_v1_cloud_host-signer-0-2021-10-12T04:22:11-07:00 K:1, 3:nbvaGZFLcuc:0:18
  211:d=4  hl=2 l=  19 prim: INTEGER           :0143F2F93ED01242D68688FB48BA7CB99EDD50
  232:d=2  hl=2 l=  93 cons: cont [ 0 ]        
```

You can verify the Platform cert was signed by a given CA by using [go-attestation.attributecert.AttributeCertificate.CheckSignatureFrom](https://pkg.go.dev/github.com/google/go-attestation@v0.3.2/attributecert#AttributeCertificate.CheckSignatureFrom)

This links the platform cert with that specific EKCert


- [`2.1.5 Assertions Made by a Platform Certificate`](https://trustedcomputinggroup.org/wp-content/uploads/IWG_Platform_Certificate_Profile_v1p1_r19_pub_fixed.pdf)

```
3.2 Platform Certificate
This section contains the format for a Platform Certificate conforming to version 1.0 of this specification.
The Platform Certificate makes the assertions listed in section 2.1.6. This certificate format
adheres to RFC 5755 [11] and all requirements and limitations from that specification apply unless otherwise noted.
```

- [Host Integrity at Runtime and Start-up (HIRS)](https://github.com/nsacyber/HIRS/tree/master)

  
### Ubuntu with AMD-SEV (--confidential-compute)

If you use a GCP Confidential Compute VM for the attestor, use the pcr values it currently holds

```bash
gcloud compute instances create attestor-cc --zone=us-central1-a --machine-type=n2d-standard-2 \
  --confidential-compute --maintenance-policy=TERMINATE \
  --image=ubuntu-2004-focal-v20210927 --image-project=confidential-vm-images \
  --no-service-account --no-scopes \
  --shielded-secure-boot --shielded-vtpm --shielded-integrity-monitoring

tpm2_pcrread  sha1:0,7+sha256:0,7
  sha1:
    0 : 0xC032C3B51DBB6F96B047421512FD4B4DFDE496F3
    7 : 0x45B6A836BDC555783626C9E4E6234AC692F76B0B
  sha256:
    0 : 0x0F35C214608D93C7A6E68AE7359B4A8BE5A0E99EEA9107ECE427C4DEA4E439CF
    7 : 0xDD0276B3BF0E30531A575A1CB5A02171EA0AD0F164D51E81F4CD0AB0BD5BAADD
```

To use a conf-compute vm as the "attestor"

```bash
go run src/verifier.go \
   --grpcport :50051 \
   --expectedPCRMapSHA256 0:0f35c214608d93c7a6e68ae7359b4a8be5a0e99eea9107ece427c4dea4e439cf,7:dd0276b3bf0e30531a575a1cb5a02171ea0ad0f164d51e81f4cd0ab0bd5baadd \
   -expectedPCRMapSHA1 0:c032c3b51dbb6f96b047421512fd4b4dfde496f3 \
   --cacert  certs/CA_crt.pem  \
   --servercert certs/server_crt.pem \
   --serverkey certs/server_key.pem \
   --usemTLS \
   --readEventLog \
   --v=10 -alsologtostderr
```