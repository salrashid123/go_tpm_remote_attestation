# TPM Remote Attestation protocol using go-tpm and gRPC

This repo contains a sample `gRPC` client server application that uses a Trusted Platform Module for:

* TPM [Remote Attestation](https://tpm2-software.github.io/tpm2-tss/getting-started/2019/12/18/Remote-Attestation.html)
* TPM [Quote-Verify](https://github.com/salrashid123/tpm2/tree/master/quote_verify)
* Sealed and PCR bound Transfer of RSA or AES keys.
* Parse TPM EventLog

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

* `attestor`:  a `gRPC` server which accepts connections from a verifier, performs remote attestation, quote/verify and then transmits an ECC public key back to the verifier which is certified to exist on that TPM

* `verifier`: a `gRPC` client which connects to the corresponding attestor, and the attestor proves it owns a specific TPM.

---

On startup, the verifier will:

1. Verifier contacts the Attestor
2. Attestor returns a demo Platform Certificate
3. Verifier checks the platform certificate specifications and verifies it with a demo platform CA
4. Attestor returns EKCert (EK)
5. Verifier checks Issuer and Signature of EKCert
  
Begin Remote Attestation

6. Verifier Requests Attestation Key (AK). Attestor return AK
7. Verifier uses (EK,AK) to begin Remote Attestation (`MakeCredential`) which involves using AK,EK to encrypt a value that it sends to Attestor
8. Attestor decodes the secret sent by Verifier (`ActivateCredential`) and returns the decrypted value to Verifier
9. Verifier confirms the secret sent matches.  Verifier associates AK with EK

End Remote Attestation

Begin Quote/Verify

10. Verifier Requests Quote over PCR values 
11. Attestor generates Quote over PCR value and uses AK to sign
12. Attestor generates EventLog 
13. Attestor returns Quote and EventLog to Verifier 
14. Verifier checks signature of the Attestation is by the AK and the PCR values from the Quote.  Verifier replays the eventLog to confirm derived PCR value.

15. (optional) Attestor creates an ECC key on the TPM and certifies it using the AK
16. (optional) Verifier requests certified ECC key from Verifier
17. (optional) Verifier confirms ECC key was certified by AK 

---

also see

 - [TPM based TLS using Attested Keys](https://github.com/salrashid123/tls_ak)
 - [Sign, Verify and decode using Google Cloud vTPM Attestation Key and Certificate](https://github.com/salrashid123/gcp-vtpm-ek-ak)
 - [go-attestation](https://github.com/google/go-attestation)


## Setup on GCE

We will use a GCP Shielded VM for these tests 

First create a VM

```bash
gcloud compute instances create attestor --zone=us-central1-a \
    --machine-type=n2d-standard-2  --min-cpu-platform="AMD Milan" \
    --shielded-secure-boot --no-service-account --no-scopes \
    --shielded-vtpm --confidential-compute-type=SEV \
    --shielded-integrity-monitoring 

gcloud compute firewall-rules create allow-tpm-verifier \
   --action allow --direction INGRESS   --source-ranges 0.0.0.0/0    --rules tcp:50051
```

### Attestor VM

Install `go 1.20+` and setup `libtspi-dev`, `gcc` (`apt-get update && apt-get install gcc libtspi-dev tpm2-tools`)

```bash
apt-get update
apt-get install libtspi-dev wget gcc git tpm2-tools -y

wget https://go.dev/dl/go1.22.3.linux-amd64.tar.gz
rm -rf /usr/local/go && tar -C /usr/local -xzf go1.22.3.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin/
```

Get the external IP

```bash
$ gcloud compute instances list --filter=name=attestor
NAME      ZONE           MACHINE_TYPE    PREEMPTIBLE  INTERNAL_IP    EXTERNAL_IP    STATUS
attestor  us-central1-a  n2d-standard-2               10.128.15.208  34.121.64.117  RUNNING
```

For GCP Confidential VM's, PCR 0 and 7 are used for attestation and those have default values on the `attestor` vm of:

```bash
$ tpm2_pcrread -o pcrs sha1:0+sha256:0,7
  sha1:
    0 : 0x2AAB58E23EA5120D70A3EBCE56BD0E6D5E3035B7
  sha256:
    0 : 0xA0B5FF3383A1116BD7DC6DF177C0C2D433B9EE1813EA958FA5D166A202CB2A85
    7 : 0x41154B2091D52958CF4B5028BD91BA4354C176050602F6D0DFBABFFA3F951186
```

```log
$ go run src/grpc_attestor.go --grpcport :50051  --v=10 -alsologtostderr

I0119 03:15:14.571472    4626 grpc_attestor.go:293] Getting EKCert
I0119 03:15:14.587224    4626 grpc_attestor.go:313] ECCert with available Issuer: CN=EK/AK CA Intermediate,OU=Google Cloud,O=Google LLC,L=Mountain View,ST=California,C=US
I0119 03:15:14.857007    4626 grpc_attestor.go:409] Generated ECC Public 
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE9yKgPRWKB9Chjnkjy46ivtPOQG5R
p7THPIQ3lRox15lHpS/FUqthJKHUrCVOYYxBYJF0+Ebogb2GJrYJ+HTHKQ==
-----END PUBLIC KEY-----
I0119 03:15:14.857698    4626 grpc_attestor.go:434] Starting gRPC server on port :50051



I0119 03:15:25.390763    4626 grpc_attestor.go:126] ======= GetPlatformCert ========
I0119 03:15:25.390795    4626 grpc_attestor.go:127]      client provided uid: 
I0119 03:15:25.390856    4626 grpc_attestor.go:145]      Returning GetPlatformCert ========
I0119 03:15:25.430128    4626 grpc_attestor.go:153] ======= GetEK ========
I0119 03:15:25.469365    4626 grpc_attestor.go:165] ======= GetAK ========
I0119 03:15:25.567951    4626 grpc_attestor.go:188] ======= Attest ========
I0119 03:15:25.853384    4626 grpc_attestor.go:222] ======= Quote ========
I0119 03:15:26.227629    4626 grpc_attestor.go:259] ======= GetTLSKey ========
```

### Verifier

First get the Attestor EK Signing certificates.

```bash
### EK 
## get the EK

gcloud compute instances get-shielded-identity attestor \
   --format=json --zone=us-central1-a | jq -r '.encryptionKey.ekCert' > certs/ekcert.pem

openssl x509 -inform pem -text -in certs/ekcert.pem
### gives a 
            # Authority Information Access: 
            #     CA Issuers - URI:http://privateca-content-65d1688e-0000-2203-850e-30fd381456f8.storage.googleapis.com/810af313406ad3e2079b/ca.crt

## get the intermediate from the ek
# Issuer: C=US, ST=California, L=Mountain View, O=Google LLC, OU=Google Cloud, CN=EK/AK CA Intermediate

curl -s $(openssl x509 -in certs/ekcert.pem -noout -text | grep -Po "((?<=CA Issuers - URI:)http://.*)$") | openssl x509 -inform DER -outform PEM \
   -out certs/ek_intermediate.pem

## get the root from the intermediate
curl -s $(openssl x509 -in certs/ek_intermediate.pem -noout -text | grep -Po "((?<=CA Issuers - URI:)http://.*)$") | openssl x509 \
    -inform DER -outform PEM -out certs/ek_root.pem
```

Now run the verifier:

```log
export ATTESTOR_ADDRESS=34.121.64.117 

go run src/grpc_verifier.go --host=$ATTESTOR_ADDRESS:50051 \
       --ekintermediateCA=certs/ek_intermediate.pem  --ekrootCA=certs/ek_root.pem  --expectedPCRMapSHA256=0:a0b5ff3383a1116bd7dc6df177c0c2d433b9ee1813ea958fa5d166a202cb2a85 \
        --v=10 -alsologtostderr


I0118 22:15:24.548210  621636 grpc_verifier.go:90] =============== GetPlatformCert ===============
I0118 22:15:24.698309  621636 grpc_verifier.go:97] =============== GetPlatformCert Returned from remote ===============
I0118 22:15:24.698360  621636 grpc_verifier.go:98]      client provided uid: 
I0118 22:15:24.698974  621636 grpc_verifier.go:129]      PlatformCertificate Issuer: Not Specified
I0118 22:15:24.699137  621636 grpc_verifier.go:136]  Verified Platform cert signed by privacyCA
I0118 22:15:24.699170  621636 grpc_verifier.go:141]  Platform Cert's Holder SerialNumber 1b001fe40bf96774751a72e9f5de5333d6b62
I0118 22:15:24.699195  621636 grpc_verifier.go:152] =============== start GetEK ===============
I0118 22:15:24.740614  621636 grpc_verifier.go:283]      EKCert  GCE InstanceID 2003763118985041850
I0118 22:15:24.740684  621636 grpc_verifier.go:284]      EKCert  GCE InstanceName attestor
I0118 22:15:24.740724  621636 grpc_verifier.go:285]      EKCert  GCE ProjectId core-eso
I0118 22:15:24.740796  621636 grpc_verifier.go:289]         EKCertificate ========
-----BEGIN CERTIFICATE-----
MIIF3DCCA8SgAwIBAgITDZ/7tOQJpK9gHOfYMSe0c/w9qTANBgkqhkiG9w0BAQsF
ADCBhjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExFjAUBgNVBAcT
DU1vdW50YWluIFZpZXcxEzARBgNVBAoTCkdvb2dsZSBMTEMxFTATBgNVBAsTDEdv
b2dsZSBDbG91ZDEeMBwGA1UEAxMVRUsvQUsgQ0EgSW50ZXJtZWRpYXRlMCAXDTI1
MDExOTAyNTQyNloYDzIwNTUwMTEyMDI1NDI1WjBpMRYwFAYDVQQHEw11cy1jZW50
cmFsMS1hMR4wHAYDVQQKExVHb29nbGUgQ29tcHV0ZSBFbmdpbmUxETAPBgNVBAsT
CGNvcmUtZXNvMRwwGgYDVQQDExMyMDAzNzYzMTE4OTg1MDQxODUwMIIBIjANBgkq
hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApl1i3sLXqyjOjxNo+pqpgzkEDVzVm2Td
Nfz2fYUjqENVJ630csOjBJ9Jn/XEYqjR7STAP9TouxYEWqFoPaQTD1iXLRU7eBGA
i6QCXyhZcPlNymOJAtcUcsBl882T8DXtpPDfJjspGWQDgjmAPK/79UQMZGssN27W
OKDujxZZsgAmqNFQt5IUffP0QF1JTW7BP4SSwdggwH9FW3KfkJ7Wl8ON06CjFMFn
OjlfIb8VnaEBYjGZyB5CSvBU+jvWJhLgqXzaEQep6azOeYRMsDGwVuBdM2Ulkyo8
PGaap0LvA9t4j3wtFWeZtb1Kmi+2P/svONX09+l07sWyXqTGzNzevwIDAQABo4IB
WzCCAVcwDgYDVR0PAQH/BAQDAgUgMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFK89
SclI0RZ4b6W6a6fSejIN9g1iMB8GA1UdIwQYMBaAFA8hnVbhqcCJxWzaI8DE8TKw
Sol6MIGNBggrBgEFBQcBAQSBgDB+MHwGCCsGAQUFBzAChnBodHRwOi8vcHJpdmF0
ZWNhLWNvbnRlbnQtNjVkMTY4OGUtMDAwMC0yMjAzLTg1MGUtMzBmZDM4MTQ1NmY4
LnN0b3JhZ2UuZ29vZ2xlYXBpcy5jb20vODEwYWYzMTM0MDZhZDNlMjA3OWIvY2Eu
Y3J0MGcGCisGAQQB1nkCARUEWTBXDA11cy1jZW50cmFsMS1hAgYA569zXpwMCGNv
cmUtZXNvAggbzsvwuSHXugwIYXR0ZXN0b3KgIDAeoAMCAQChAwEB/6IDAQH/owMB
AQCkAwEBAKUDAQEAMA0GCSqGSIb3DQEBCwUAA4ICAQCetb98rvc0MrC4MbdF7UUb
o5OAo/nXQnHwXvzTXzIgV4g8aMcdw0MyaoLApKJf37Q0nku9qNcP/fMAPLYJWnqO
2bhPfVHXG4dYvIg+zluFvECWkZJrgvgTNZgmNPJYGWtPYd8fcucJUFfMo5DV22IR
W7NmfzRPXjp9GjJeXQjKyx0xJtWb3Fbvvjh84ANFX8CoqU5BRzfwz+9CYVWdiNXM
ITuf9v4Y2/vb+WAP2yXEuYjgj1a2yNezrKRy+qDksm4i+0AnRRvnQS72CBVWRnAU
5RcX2lHPOjp0M6VeWL4iNZXyRJOL9ycvIl7FVhBl7Bv2oUg7IQxFT2tw68oF2shl
06UN4U27ZCf1PWNZX+qTLBVmPxqla8+Rq8n0qqsraOgnjD9F7OU98ghquIPfP3zh
JtyeE1TFlm0g+fTO6fopWXFdYXrQFagpYvPy0PtXg2vYhtoRndBflp2giGPb1evS
1pcjJUr76kXovng9TMzgH/3MyNHgUphvI+gTFje3Tng2K9aFip7vqPvhaXDB3Dkz
1VgjdXyV+DSOyb3sKxOhItozktU1Z5o1lezjUeY9dAFV3Bonme/a8X4Q718yNP5Q
kM4M6NKWJOpvgm17VDyNUAniCU/Xqrk8njkYk6C7n8D1BbzTanwAry4vKFxUy0vQ
Ld6Gu3BJL7eEhWkWIGf8GQ==
-----END CERTIFICATE-----

I0118 22:15:24.740901  621636 grpc_verifier.go:305]      EKCert  Issuer CN=EK/AK CA Intermediate,OU=Google Cloud,O=Google LLC,L=Mountain View,ST=California,C=US
I0118 22:15:24.741000  621636 grpc_verifier.go:306]      EKCert  IssuingCertificateURL [http://privateca-content-65d1688e-0000-2203-850e-30fd381456f8.storage.googleapis.com/810af313406ad3e2079b/ca.crt]
I0118 22:15:24.741044  621636 grpc_verifier.go:311]     Verifying EKCert
I0118 22:15:24.743577  621636 grpc_verifier.go:366]     EKCert Verified
I0118 22:15:24.743630  621636 grpc_verifier.go:368]      EKPub: 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApl1i3sLXqyjOjxNo+pqp
gzkEDVzVm2TdNfz2fYUjqENVJ630csOjBJ9Jn/XEYqjR7STAP9TouxYEWqFoPaQT
D1iXLRU7eBGAi6QCXyhZcPlNymOJAtcUcsBl882T8DXtpPDfJjspGWQDgjmAPK/7
9UQMZGssN27WOKDujxZZsgAmqNFQt5IUffP0QF1JTW7BP4SSwdggwH9FW3KfkJ7W
l8ON06CjFMFnOjlfIb8VnaEBYjGZyB5CSvBU+jvWJhLgqXzaEQep6azOeYRMsDGw
VuBdM2Ulkyo8PGaap0LvA9t4j3wtFWeZtb1Kmi+2P/svONX09+l07sWyXqTGzNze
vwIDAQAB
-----END PUBLIC KEY-----

I0118 22:15:24.743713  621636 grpc_verifier.go:384] =============== end GetEKCert ===============
I0118 22:15:24.743761  621636 grpc_verifier.go:387] =============== start GetAK ===============
I0118 22:15:24.840372  621636 grpc_verifier.go:420]       ak public 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAstrZU393Zuewk8wsYbw1
H8k00A2WBkn6VUMHghIPQyn+EN/ts/f5fKk0ZNkGJQb2POhRieSMKUUG+HmKFpBL
k1udZs3oESx5oIVbeXlFnp5+POa0S4eCgPTuRoJohrBmgDOK9P8COIYLTRzv8bdy
Jr2iDIG+ZQbMqNsci4ItDnJRnPdJenN85ahghn0B6nTKJpwH1RuNBqXeu1Y03TuD
9LECjzL0mWnNJ0othJd8JjuW9nr1CU1roD5hmLxqJth7KKJAj1ZO/+3uYJZds4cS
Dop48Pblb3MCgaS3BMTxnbTi+4ts05s0APu9+nYwzrie8QISFerZ9rNFJdbFjPjo
owIDAQAB
-----END PUBLIC KEY-----

I0118 22:15:24.840462  621636 grpc_verifier.go:421] =============== end GetAK ===============
I0118 22:15:24.840528  621636 grpc_verifier.go:424] =============== start Attest ===============
I0118 22:15:24.840908  621636 grpc_verifier.go:437]       Outbound Secret: MpcYIFtsz7nDz4nYvmJTbyaEoEsUN/ecYrVSoMFMC44=
I0118 22:15:25.129612  621636 grpc_verifier.go:453]       Inbound Secret: MpcYIFtsz7nDz4nYvmJTbyaEoEsUN/ecYrVSoMFMC44=
I0118 22:15:25.129699  621636 grpc_verifier.go:456]       inbound/outbound Secrets Match; accepting AK
I0118 22:15:25.129753  621636 grpc_verifier.go:461] =============== end Attest ===============
I0118 22:15:25.129808  621636 grpc_verifier.go:464] =============== start Quote/Verify ===============
I0118 22:15:25.495091  621636 grpc_verifier.go:509]       quote-attested public 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAstrZU393Zuewk8wsYbw1
H8k00A2WBkn6VUMHghIPQyn+EN/ts/f5fKk0ZNkGJQb2POhRieSMKUUG+HmKFpBL
k1udZs3oESx5oIVbeXlFnp5+POa0S4eCgPTuRoJohrBmgDOK9P8COIYLTRzv8bdy
Jr2iDIG+ZQbMqNsci4ItDnJRnPdJenN85ahghn0B6nTKJpwH1RuNBqXeu1Y03TuD
9LECjzL0mWnNJ0othJd8JjuW9nr1CU1roD5hmLxqJth7KKJAj1ZO/+3uYJZds4cS
Dop48Pblb3MCgaS3BMTxnbTi+4ts05s0APu9+nYwzrie8QISFerZ9rNFJdbFjPjo
owIDAQAB
-----END PUBLIC KEY-----

I0118 22:15:25.495271  621636 grpc_verifier.go:536]      quotes verified
I0118 22:15:25.495715  621636 grpc_verifier.go:565]      secureBoot State enabled: [true]
I0118 22:15:25.495910  621636 grpc_verifier.go:571] =============== end Quote/Verify ===============
I0118 22:15:25.495945  621636 grpc_verifier.go:574] =============== start NewKey ===============
I0118 22:15:25.592241  621636 grpc_verifier.go:586]         PublicKey ========
-----BEGIN Public Key-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE9yKgPRWKB9Chjnkjy46ivtPOQG5R
p7THPIQ3lRox15lHpS/FUqthJKHUrCVOYYxBYJF0+Ebogb2GJrYJ+HTHKQ==
-----END Public Key-----

I0118 22:15:25.592449  621636 grpc_verifier.go:655]      key verified 
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE9yKgPRWKB9Chjnkjy46ivtPOQG5R
p7THPIQ3lRox15lHpS/FUqthJKHUrCVOYYxBYJF0+Ebogb2GJrYJ+HTHKQ==
-----END PUBLIC KEY-----

I0118 22:15:25.592494  621636 grpc_verifier.go:656] =============== end NewKey ===============        
```


#### Local TPM

If you want to test locally, you need to acquire your TPM's issuer and intermediate root certificates.

For my laptop, the PCR value and issuers was `certs/ECCert.pem` 


EKCert:

```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            24:eb:bd:b3:08:6f:8a:ab:e5:d6:91:d5:55:f9:d0:14:e7:5f:29:bb
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C=CH, O=STMicroelectronics NV, CN=STM TPM EK Intermediate CA 06
        X509v3 extensions:
            X509v3 Authority Key Identifier: 
                FB:17:D7:0D:73:48:70:E9:19:C4:E8:E6:03:97:5E:66:4E:0E:43:DE
            X509v3 Subject Alternative Name: critical
                DirName:/2.23.133.2.1=id:53544D20/2.23.133.2.2=ST33HTPHAHD8/2.23.133.2.3=id:00010102
```

With PCRs:

```bash
$ sudo tpm2_pcrread -o pcrs sha1:0+sha256:0,7
[sudo] password for srashid: 
  sha1:
    0 : 0x5FAB55B431F59B753BBD0C3885C85201099BF5DD
  sha256:
    0 : 0x3C5B53C48B7A21E554FBB14678C67DAFD792151CD3BDC6017E35F1B4A41FF412
    7 : 0xAE2CE658A648D02A7F587BF36BFBAEE41DF3E3F241DAD2385C411D9B38D3904A


## run attestor
go run src/grpc_attestor.go --grpcport :50051  --v=10 -alsologtostderr


## run verifier
export ATTESTOR_ADDRESS=127.0.0.1
go run src/grpc_verifier.go --host=$ATTESTOR_ADDRESS:50051 \
       --ekintermediateCA=certs/stmtpmek_combined.pem  --ekrootCA=certs/gstpmroot.pem  --expectedPCRMapSHA256=0:3c5b53c48b7a21e554fbb14678c67dafd792151cd3bdc6017e35f1b4a41ff412     --v=10 -alsologtostderr
```

---

### Platform Certificate

The platform certificate used in this protocol is just a sample, static one I downloaded from the [go-attestation testdata](https://github.com/google/go-attestation/tree/master/attributecert/testdata).

Specifically, [Intel_pc1.cer](https://github.com/google/go-attestation/blob/master/attributecert/testdata/Intel_pc1.cer) which is verified against [IntelSigningKey_20April2017.cer](https://github.com/google/go-attestation/blob/master/attributecert/testdata/IntelSigningKey_20April2017.cer)

Ideally, the Platform Certificate contains a reference back to the TPM's EKCertificate [`pg 12: Assertions Made by a Platform Certificate`](https://trustedcomputinggroup.org/wp-content/uploads/IWG_Platform_Certificate_Profile_v1p1_r19_pub_fixed.pdf)


```
2.1.5.2 EK Certificates
126 This assertion is used by the Privacy-CA to verify that the platform contains a unique TPM
127 referenced by this Platform Certificate.
128 This SHALL be an unambiguous indication of the EK Certificates of the TPM incorporated
129 into the platform. The Platform Certificate SHALL contain references to all TCG required
130 Endorsement Key (EK) Certificates. The “TCG Infrastructure Working Group Reference
131 Architecture for Interoperability (Part I)” [2] requires the TPM Manufacturer to issue an EK
132 Certificate for each TPM Endorsement Key. The Platform Certificate MAY also contain
133 references to optional EK Certificates, such as those issued by the Platform OEM or Platform
134 Owner. 
```

However, the test platform certs here don't include this.

instead, i just used the serial number in the EKCert 

For example, if the EKCert is:

```bash
## ekpublic
$ tpm2_createek -c ek.ctx -G rsa -u ek.pub 
$ tpm2_readpublic -c ek.ctx -o ek.pem -f PEM -Q

## ekcert
$ tpm2_getekcertificate -X -o ECcert.bin
$ openssl x509 -in ECcert.bin -inform DER -noout -text

$  openssl x509 -inform pem -text -in ECCert.pem
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            24:eb:bd:b3:08:6f:8a:ab:e5:d6:91:d5:55:f9:d0:14:e7:5f:29:bb
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C=CH, O=STMicroelectronics NV, CN=STM TPM EK Intermediate CA 06
        Validity
            Not Before: Sep 25 00:00:00 2020 GMT
            Not After : Dec 31 00:00:00 2049 GMT
        Subject: 
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Modulus:
                    00:f9:2b:c1:d6:d6:66:74:df:10:e2:7f:ff:ea:73:
                    8f:0e:e0:4d:92:49:ed:4c:45:13:3b:c6:09:b5:a8:
                    72:a6:00:3a:2e:08:9a:5c:ad:16:ee:c6:11:05:1d:
                    76:d9:56:f4:43:6a:38:da:3c:bd:ef:c2:49:b8:c4:
                    85:d3:fa:de:9c:1d:82:aa:82:22:56:99:bf:65:dc:
                    8a:07:7d:c3:d6:0b:91:01:cf:05:09:8c:07:e1:b8:
                    ef:fe:da:f4:5a:eb:ea:ad:84:26:1a:26:93:db:f0:
                    0a:fd:b4:ba:9d:55:34:f5:fe:6a:0b:16:0d:77:0a:
                    46:8f:8c:38:e7:57:34:4c:53:91:95:07:f9:d5:6e:
                    95:9e:96:87:87:25:0d:c0:bf:a0:0d:72:0d:1e:85:
                    b5:af:99:24:54:a0:13:d4:29:b9:22:78:db:31:57:
                    49:ac:96:4a:3f:e5:d1:2b:65:ab:50:eb:2e:17:d8:
                    43:a5:f5:19:c7:9c:65:69:ae:b4:ae:44:dc:bc:42:
                    85:c6:e6:b2:c1:90:09:74:64:2f:0a:63:8a:64:99:
                    21:1d:7c:b9:84:7d:8c:5b:d4:71:ed:c0:af:2b:64:
                    fa:49:d1:20:53:ed:5f:8d:85:84:03:ce:d3:57:81:
                    c9:38:67:95:24:0a:0d:e9:b1:b3:f4:31:71:08:fa:
                    aa:7b
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Authority Key Identifier: 
                FB:17:D7:0D:73:48:70:E9:19:C4:E8:E6:03:97:5E:66:4E:0E:43:DE
            X509v3 Subject Alternative Name: critical
                DirName:/tcg-at-tpmManufacturer=id:53544D20/tcg-at-tpmModel=ST33HTPHAHD8/tcg-at-tpmVersion=id:00010102
            X509v3 Subject Directory Attributes: 
                TPM Specification:
    0:d=0  hl=2 l=  12 cons: SEQUENCE          
    2:d=1  hl=2 l=   3 prim:  UTF8STRING        :2.0
    7:d=1  hl=2 l=   1 prim:  INTEGER           :00
   10:d=1  hl=2 l=   2 prim:  INTEGER           :8A


            X509v3 Basic Constraints: critical
                CA:FALSE
            X509v3 Extended Key Usage: 
                Endorsement Key Certificate
            X509v3 Key Usage: critical
                Key Encipherment
            Authority Information Access: 
                CA Issuers - URI:http://secure.globalsign.com/stmtpmekint06.crt
    Signature Algorithm: sha256WithRSAEncryption

```

Then the attribute Certificate may include the serial number as such

```text
     PlatformCertificate Issuer: CN=www.intel.com,OU=Transparent Supply Chain,O=Intel Corporation,L=Santa Clara,ST=CA,C=US
     PlatformCertificate Version: 2
     PlatformCertificate CredentialSpecification: 
     PlatformCertificate PlatformManufacturer: Intel
     PlatformCertificate PlatformModel: DE3815TYKH
     PlatformCertificate PlatformVersion: H26998-402
     PlatformCertificate PropertiesURI: 
     PlatformCertificate Holder.Issuer: CN=STM TPM EK Intermediate CA 06
     PlatformCertificate Holder.Serial: 24EBBDB3086F8AABE5D691D555F9D014E75F29BB
     PlatformCertificate Holder.Issuer.CommonName: C=CH, O=STMicroelectronics NV, CN=STM TPM EK Intermediate CA 06
     PlatformCertificate TBBSecurityAssertions.Iso9000URI: 
     PlatformCertificate TBBSecurityAssertions.CcInfo.ProfileOid: 
     PlatformCertificate TBBSecurityAssertions.CcInfo.ProfileURI: 
     PlatformCertificate TBBSecurityAssertions.CcInfo.TargetOid: 
     PlatformCertificate TBBSecurityAssertions.CcInfo.TargetURI: 
     PlatformCertificate TBBSecurityAssertions.CcInfo.Version: 
     PlatformCertificate TCGPlatformSpecification.Version: {1 2 1}
     PlatformCertificate TCGPlatformSpecification.Version.MajorVersion: 1
     PlatformCertificate TCGPlatformSpecification.Version.MinorVersion: 2
     PlatformCertificate TCGPlatformSpecification.Version.Revision: 1
     PlatformCertificate UserNotice.UserNotice.ExplicitText: 
     PlatformCertificate UserNotice.UserNotice.Organization: 
     PlatformCertificate UserNotice.UserNotice.NoticeNumbers: []
```

Note the serialNumber in the attribute certificate and EKCertificate

```
3.2 Platform Certificate
This section contains the format for a Platform Certificate conforming to version 1.0 of this specification.
The Platform Certificate makes the assertions listed in section 2.1.6. This certificate format
adheres to RFC 5755 [11] and all requirements and limitations from that specification apply unless otherwise noted.
```

Note: attribute cert parsing is [supported in openssl](https://github.com/openssl/openssl/issues/14648) but i haven't tried using this.

You can also use [paccor](https://github.com/salrashid123/attribute_certificate0.)


### Applications

This is just an academic exercise (so do not use the code as is).   However, some applications of this


- [TPM based Google Service Account Credentials](https://github.com/salrashid123/oauth2#usage-tpmtokensource)
- [TPM based mTLS](https://github.com/salrashid123/signer#usage-tls)
- [Trusted Platform Module (TPM) recipes with tpm2_tools and go-tpm](https://github.com/salrashid123/tpm2)

