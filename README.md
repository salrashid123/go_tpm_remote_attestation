# TPM Remote Attestation protocol using go-tpm and gRPC


This repo contains a sample `gRPC` client server application that uses a Trusted Platform Module for:

* TPM [Remote Attestation](https://tpm2-software.github.io/tpm2-tss/getting-started/2019/12/18/Remote-Attestation.html)
* TPM [Quote-Verify](https://github.com/salrashid123/tpm2/tree/master/quote_verify)
* Sealed and PCR bound Transfer of RSA or AES keys.
* Parse TPM EventLog


Note: there are two branches to this repository:  `push` and `pull`

The main difference between them is which side initiates communication to attest a TPM.

* In the `push` model, the `verifier` is a remote server which *makes* an outbound API call _to_ the TPM device (`attestor`).  The TPM device now performs remote attestation but is driven by the the API calls from the remote server.

* In the `pull` model, the `verifier` is a remote server which *receives* an outbound API call _from_ the TPM device (`attestor`).  The TPM device is in control of when to initiate and perform remote attestation.


Attestation:

( Images taken from [Remote Attestation](https://tpm2-software.github.io/tpm2-tss/getting-started/2019/12/18/Remote-Attestation.html) )


![images/diag1.png](images/diag1.png)

Quote/Verify:

![images/diag2.png](images/diag2.png)

EventLog

![images/diag3.png](images/diag3.png)

>>> **NOTE** the code and procedure outlined here is **NOT** supported by google.


You can use this standalone to setup a gRPC client/server for remote attestation.

There are two parts:

* `attestor`:  a `gRPC` server which accepts connections from a verifier, performs remote attestation, quote/verify and then then securely receives a sealed key from a verifier.  The key is distributed such that it can _only_ get loaded or decoded on the attestor that has the TPM

* `verifier`: a `gRPC` client which connects to the corresponding attestor, proves it owns a specific TPM and then sends a sealed Key that can only be decoded by that client.

---

As you can see, the whole protocol is rather complicated but hinges on being able to trust the initial Endorsement Key.   As mentioned, this is normally done by validating that the EndorsementPublic certificate is infact real and signed by a 3rd party (eg, the manufacturer of the TPM).  In the case of google's shielded vTPM, it is signed by google's subordinate CA and includes information about the VM's instance_id value.  This protocol also "validates" the PlatformCA which itself includes a reference (serial# reference) to the EndorsementKey.  I suppose it can contain the hash of the EKcert as another attribute...

---

also see

 - [go-attestation](https://github.com/google/go-attestation)


## Setup

We will use a GCP Shielded VM for these tests 

First create two VMs

```bash
gcloud compute instances create attestor \
  --zone=us-central1-a --machine-type=e2-medium --no-service-account --no-scopes \
  --image=debian-11-bullseye-v20211105 --image-project=debian-cloud  \
  --shielded-secure-boot --shielded-vtpm --shielded-integrity-monitoring

gcloud compute instances create verifier \
  --zone=us-central1-a --machine-type=e2-medium --no-service-account --no-scopes \
  --image=debian-11-bullseye-v20211105 --image-project=debian-cloud  \
  --shielded-secure-boot --shielded-vtpm --shielded-integrity-monitoring
```

On each, install `go 1.16+` and setup `libtspi-dev`, `gcc` (`apt-get update && apt-get install gcc libtspi-dev`)

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


## Tests

Now test the client-server by transmitting both an RSA and AES key.


On startup, the verifier will:

1. Verifier contacts the Attestor
2. Attestor returns EKCert (EK)
3. Verifier checks Issuer of EKCert
  
Begin Remote Attestation

4. Verifier Requests Attestation Key (AK). Attestor return AK
5. Verifier uses (EK,AK) to begin Remote Attestation (MakeCredential) which involves using AK,EK to encrypt a value that it sends to Attestor
6. Attestor decodes the secret sent by Verifier (ActivateCredential) and returns the decrypted value to Verifier
7. Verifier confirms the secret sent matches.  Verifier associates AK with EK

End Remote Attestation

Begin Quote/Verify

8. Verifier Requests Quote over PCR values 
9. Attestor generates Quote over PCR value and uses AK to sign
10. Attestor generates EventLog 
11. Attestor returns Quote and EventLog to Verifier 
12. Verifier checks signature of the Attestation is by the AK and the PCR values from the Quote.  Verifier replays the eventLog to confirm derived PCR value.
13. Verifier uses CA private key to sign an x509 certificate tied to the AK.  The verifier _could_ return this x509 back to the attestor over a new (unimplemented) gRPC API call.

End Quote/Verify

Begin Sealed Transfer (PushSecret)

14. Verifier uses EK to encrypt either a local RSA or AES Key 
15. Verifier transmits encrypted Key to Attestor 
16. Attestor either decrypts the AES key or imports the External RSA key into its TPM
17. Attestor generates a test signature using the RSA key or calculates the Hash value of AES key.
18. Attestor returns the signature or hash to Verifier. 
19. Verifier confirms the signature value or hash (thereby confirming the Attestor decoded the RSA or AES key)

End Sealed Transfer

Begin Unrestricted SigningKey Transfer (PullSecret)

20. Verifier Requests Unrestricted Signing Key
21. Attestor generates RSA Key on TPM as a child of EK
22. Attestor uses AK to [Certify](https://github.com/tpm2-software/tpm2-tools/blob/master/man/tpm2_certify.1.md) the new key
23. Attestor transmits the TPM Wire firmat of the RSA key and test signature over some preshared data.
24. Verifier uses AK to confirm the authenticity of the Certification and RSA Public key is attested.
25. Verifier uses RSA Public key to verify the signature provided over preshared data
26. Verifier extracts the public key from the TPM Wireformat and compares it with the Key embedded in the attestation
27. Verifier uses the TPM Wire format Public key to verify the specifications for the unrestricted key (e,g matches template)
28. Verifier uses CA private key to sign an x509certificate tied to the SigningKey.  The verifier _could_ return this x509 back to the attestor over a new (unimplemented) gRPC API call.
    The attestor could use this x509 and private key on its TPM to create an mTLS connection.  See [crypto.Signer for TPM](https://github.com/salrashid123/signer#usage-tls) and [mTLS with TPM bound private key](https://github.com/salrashid123/go_tpm_https_embed) 

End Unrestricted SigningKey Transfer

### AES

#### Attestor AES

```log
go run src/grpc_attestor.go --grpcport :50051 \
 --unsealPcrs=0,7 \
 --caCertTLS certs/CA_crt.pem \
 --servercert certs/server_crt.pem \
 --serverkey certs/server_key.pem \
  -useFullAttestation --readEventLog \
  --platformCertFile certs/platform_cert.der \
  --v=10 -alsologtostderr
```

#### Verifier AES

```log
go run src/grpc_verifier.go --importMode=AES  --uid 369c327d-ad1f-401c-aa91-d9b0e69bft67 --readEventLog \
   -aes256Key "G-KaPdSgUkXp2s5v8y/B?E(H+MbQeThW" \
   --host verify.esodemoapp2.com:50051 \
   --expectedPCRMapSHA256 0:24af52a4f429b71a3184a6d64cddad17e54ea030e2aa6576bf3a5a3d8bd3328f,7:3d91599581f7a3a3a1bb7c7a55a7b8a50967be6506a5f47a9e89fef756fab07a \
   --expectedPCRMapSHA1 0:0f2d3a2a1adaa479aeeca8f5df76aadc41b862ea \
   --caCertTLS certs/CA_crt.pem --caCertIssuer certs/CA_crt.pem --caKeyIssuer certs/CA_key.pem --platformCA certs/CA_crt.pem \
   --readEventLog \
   --useFullAttestation \
   --v=10 -alsologtostderr 
```

### RSA

#### Attestor RSA

```log
go run src/grpc_attestor.go --grpcport :50051 \
  --unsealPcrs=0,7 \
  --caCertTLS certs/CA_crt.pem \
  --servercert certs/server_crt.pem -useFullAttestation  --readEventLog \
  --serverkey certs/server_key.pem --platformCertFile certs/platform_cert.der  \
  --v=10 -alsologtostderr
```

#### Verifier RSA

```log
go run src/grpc_verifier.go --importMode=RSA  --uid 369c327d-ad1f-401c-aa91-d9b0e69bft67 \
  --expectedPCRMapSHA256 0:24af52a4f429b71a3184a6d64cddad17e54ea030e2aa6576bf3a5a3d8bd3328f,7:3d91599581f7a3a3a1bb7c7a55a7b8a50967be6506a5f47a9e89fef756fab07a \
  --expectedPCRMapSHA1 0:0f2d3a2a1adaa479aeeca8f5df76aadc41b862ea \
  --rsaCert=certs/tpm_client.crt \
  --readEventLog --useFullAttestation \
  --caCertTLS certs/CA_crt.pem --caCertIssuer certs/CA_crt.pem --caKeyIssuer certs/CA_key.pem    --platformCA certs/CA_crt.pem \
  --rsaKey=certs/tpm_client.key  --host verify.esodemoapp2.com:50051   \
  --v=10 -alsologtostderr 
```


#### EventLog

Please see the following for background on the eventlog and how to use it 

- [TPMJS Event Log](https://google.github.io/tpm-js/#pg_attestation)

>> Note, on [GCP Shielded VM](https://cloud.google.com/compute/docs/instances/integrity-monitoring), the default `PCR0` value is:

```bash
# tpm2_pcrread sha1:0+sha256:0
  sha1:
    0 : 0x0F2D3A2A1ADAA479AEECA8F5DF76AADC41B862EA
  sha256:
    0 : 0x24AF52A4F429B71A3184A6D64CDDAD17E54EA030E2AA6576BF3A5A3D8BD3328F
```

You can find a full end-to-end trace for the AES example under the `example/` folder

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

This links the platform cert with that specific EKCert

You can verify the Platform cert was signed by a given CA by using [go-attestation.attributecert.AttributeCertificate.CheckSignatureFrom](https://pkg.go.dev/github.com/google/go-attestation@v0.3.2/attributecer
t#AttributeCertificate.CheckSignatureFrom)


- [`2.1.5 Assertions Made by a Platform Certificate`](https://trustedcomputinggroup.org/wp-content/uploads/IWG_Platform_Certificate_Profile_v1p1_r19_pub_fixed.pdf)

```
3.2 Platform Certificate
This section contains the format for a Platform Certificate conforming to version 1.0 of this specification.
The Platform Certificate makes the assertions listed in section 2.1.6. This certificate format
adheres to RFC 5755 [11] and all requirements and limitations from that specification apply unless otherwise noted.
```

- [Host Integrity at Runtime and Start-up (HIRS)](https://github.com/nsacyber/HIRS/tree/master)


### Applications

This is just an academic exercise (so do not use the code as is).   However, some applications of this


- [TPM based Google Service Account Credentials](https://github.com/salrashid123/oauth2#usage-tpmtokensource)
- [TPM based mTLS](https://github.com/salrashid123/signer#usage-tls)
- [Trusted Platform Module (TPM) recipes with tpm2_tools and go-tpm](https://github.com/salrashid123/tpm2)


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


go run src/grpc_verifier.go --importMode=RSA  --uid 369c327d-ad1f-401c-aa91-d9b0e69bft67 \
  --expectedPCRMapSHA256 0:0f35c214608d93c7a6e68ae7359b4a8be5a0e99eea9107ece427c4dea4e439cf,7:dd0276b3bf0e30531a575a1cb5a02171ea0ad0f164d51e81f4cd0ab0bd5baadd \
  --expectedPCRMapSHA1 0:c032c3b51dbb6f96b047421512fd4b4dfde496f3 \
  --rsaCert=certs/tpm_client.crt \
  --readEventLog --useFullAttestation \
  --caCertTLS certs/CA_crt.pem --caCertIssuer certs/CA_crt.pem --caKeyIssuer certs/CA_key.pem \
  --rsaKey=certs/tpm_client.key  --host verify.esodemoapp2.com:50051   \
  --v=10 -alsologtostderr 
```
