# TPM Remote Attestation protocol using go-tpm and gRPC

This repo contains a sample `gRPC` client server application that uses a Trusted Platform Module for:

* TPM [Remote Attestation](https://tpm2-software.github.io/tpm2-tss/getting-started/2019/12/18/Remote-Attestation.html)
* TPM [Quote-Verify](https://github.com/salrashid123/tpm2/tree/master/quote_verify)
* Sealed and PCR bound Transfer of RSA or AES keys.
* Parse TPM EventLog

* You can use this standalone to setup a gRPC client/server for remote attestation.

There are *TWO* branches to this repo: 

* [push](https://github.com/salrashid123/go_tpm_remote_attestation/tree/push) (this branch):  In this mode, the attestor is the server and the verifier makes an rpc call to the attestor
* [pull](https://github.com/salrashid123/go_tpm_remote_attestation/tree/pull):  In this mode, the attestor is the client initiator that makes an rpc call to the verifier


Attestation:

( Images taken from [Remote Attestation](https://tpm2-software.github.io/tpm2-tss/getting-started/2019/12/18/Remote-Attestation.html) )


![images/diag1.png](images/diag1.png)

Quote/Verify:

![images/diag2.png](images/diag2.png)

EventLog

![images/diag3.png](images/diag3.png)

>>> **NOTE** the code and procedure outlined here is **NOT** supported by google.

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

18. (really optional) Initiate TLS with Attested ECC Key ([TPM based TLS using Attested Keys](https://github.com/salrashid123/tls_ak))

---

also see

 - [TPM based TLS using Attested Keys](https://github.com/salrashid123/tls_ak)
 - [Sign, Verify and decode using Google Cloud vTPM Attestation Key and Certificate](https://github.com/salrashid123/gcp-vtpm-ek-ak)
 - [go-attestation](https://github.com/google/go-attestation)


#### Setup Local TPM

If you want to test locally with a real TPM, you need to acquire your TPM's issuer and intermediate root certificates.

For my laptop, the PCR value and issuers was `certs/ECCert.pem` 

To get the EKCert, install `tpm2_tools` first and then:

```bash
## public key
# tpm2_createek -c /tmp/ek.ctx -G rsa -u /tmp/ek.pub
# tpm2_readpublic -c /tmp/ek.ctx  -o certs/ECCPub.pem -f PEM

## x509
tpm2_getekcertificate -X -o /tmp/ECcert.bin
openssl x509 -in /tmp/ECcert.bin -inform DER -out certs/ECCert.pem
```

The EKCert was in the form:

```bash
$ openssl x509 -in certs/ECCert.pem -inform PEM -noout -text 

Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            7e:36:61:65:3e:7b:5a:81:74:3d:03:f1:1a:92:56:ec:ff:be:04:81
        Signature Algorithm: sha384WithRSAEncryption
        Issuer: C=CH, O=STMicroelectronics NV, CN=STSAFE TPM RSA Intermediate CA 10
        Validity
            Not Before: Apr 16 10:33:45 2023 GMT
            Not After : Dec 31 23:59:59 9999 GMT
        Subject: 
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Modulus:
                    00:d2:
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Authority Key Identifier: 
                65:70:62:A7:10:56:91:6F:8C:7F:79:8A:92:DD:E6:D8:1D:0A:98:DA
            X509v3 Subject Alternative Name: critical
                DirName:/tcg-at-tpmManufacturer=id:53544D20/tcg-at-tpmModel=ST33KTPM2X/tcg-at-tpmVersion=id:00090100
            X509v3 Subject Directory Attributes: 
                TPM Specification:
    0:d=0  hl=2 l=  12 cons: SEQUENCE          
    2:d=1  hl=2 l=   3 prim:  UTF8STRING        :2.0
    7:d=1  hl=2 l=   1 prim:  INTEGER           :00
   10:d=1  hl=2 l=   2 prim:  INTEGER           :9F


            X509v3 Basic Constraints: critical
                CA:FALSE
            X509v3 Extended Key Usage: 
                Endorsement Key Certificate
            X509v3 Key Usage: critical
                Key Encipherment
            Authority Information Access: 
                CA Issuers - URI:http://sw-center.st.com/STSAFE/stsafetpmrsaint10.crt
    Signature Algorithm: sha384WithRSAEncryption
    Signature Value:
        a3:62:a4:f9:2
```

The next step is to acquire the certification trust chain.  Note that for me the `CAIssuer` is `URI:http://sw-center.st.com/STSAFE/stsafetpmrsaint10.crt` (yours maybe different)

So to get the chains, first get the intermediate

```bash
wget http://sw-center.st.com/STSAFE/stsafetpmrsaint10.crt
openssl x509 -in stsafetpmrsaint10.crt -inform DER -noout -text 
```

Which prints out 

```bash
openssl x509 -in stsafetpmrsaint10.crt -inform DER -out certs/stmtpmekint10.pem

Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 1073741840 (0x40000010)
        Signature Algorithm: sha384WithRSAEncryption
        Issuer: C=CH, O=STMicroelectronics NV, CN=STSAFE RSA Root CA 02
        Validity
            Not Before: Jan 20 00:00:00 2022 GMT
            Not After : Jan  1 00:00:00 2042 GMT
        Subject: C=CH, O=STMicroelectronics NV, CN=STSAFE TPM RSA Intermediate CA 10
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (4096 bit)
                Modulus:
                    00:cb:b5:
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Subject Key Identifier: 
                65:70:62:A7:10:56:91:6F:8C:7F:79:8A:92:DD:E6:D8:1D:0A:98:DA
            X509v3 Authority Key Identifier: 
                7C:C2:8D:BE:6E:59:D8:4A:54:03:46:9B:13:08:00:D2:F8:F0:6D:27
            X509v3 Certificate Policies: critical
                Policy: X509v3 Any Policy
                  CPS: http://sw-center.st.com/STSAFE/
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:0
            Authority Information Access: 
                CA Issuers - URI:http://sw-center.st.com/STSAFE/STSAFERsaRootCA02.crt
            X509v3 CRL Distribution Points: 
                Full Name:
                  URI:http://sw-center.st.com/STSAFE/STSAFERsaRootCA02.crl

    Signature Algorithm: sha384WithRSAEncryption
    Signature Value:
        80:4e:30:4e:14:71:22:39
```

Now get the root by reading the parsed intermediate  `URI:http://sw-center.st.com/STSAFE/STSAFERsaRootCA02.crt`

```bash
wget http://sw-center.st.com/STSAFE/STSAFERsaRootCA02.crt
openssl x509 -in STSAFERsaRootCA02.crt -inform DER -noout -text
openssl x509 -in STSAFERsaRootCA02.crt -inform DER -out certs/stmtpmekroot.pem
```

Now read the PCR's on the Attestor (which in this case is the same laptop as the verifier):

```bash
sudo tpm2_pcrread  sha1:0+sha256:0,7
  sha1:
  sha256:
    0 : 0x7BB4353897632FD086982175A027DAFCC33F61ADBAB4EBFC6D13927B97A8C084
    7 : 0x46D45493DC751AF8C46996EEDAF69D7D4012D46CA8D75BBB141D23103361E59E
```

Note, your system must generate a [tpm2_eventlog](https://github.com/tpm2-software/tpm2-tools/blob/master/man/tpm2_eventlog.1.md) since this is used during quote/verification steps.

To verify that its there, run

```bash
sudo tpm2_eventlog /sys/kernel/security/tpm0/binary_bios_measurements
```

### Attestor

Now run the Attestor:

```bash
sudo go run src/server/grpc_attestor.go --grpcport :50051  --v=10 -alsologtostderr
```

```log
I0515 05:57:52.291592  208717 grpc_attestor.go:291] Getting EKCert
I0515 05:57:52.309236  208717 grpc_attestor.go:311] ECCert with available Issuer: CN=STSAFE TPM RSA Intermediate CA 10,O=STMicroelectronics NV,C=CH
I0515 05:57:53.851893  208717 grpc_attestor.go:407] Generated ECC Public 
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEHt/0kwFfF6LXGyK4ktCTH/Aw/h6Q
hw24Zb37gjQVwAscYNgwrHqF3xcM8jpk21rwkDz27bN+tntmXXVDBJlqPw==
-----END PUBLIC KEY-----
I0515 05:57:53.852899  208717 grpc_attestor.go:432] Starting gRPC server on port :50051
I0515 05:58:04.151182  208717 grpc_attestor.go:126] ======= GetPlatformCert ========
I0515 05:58:04.151397  208717 grpc_attestor.go:144]      Returning GetPlatformCert ========
I0515 05:58:04.153708  208717 grpc_attestor.go:151] ======= GetEK ========
I0515 05:58:04.157826  208717 grpc_attestor.go:163] ======= GetAK ========
I0515 05:58:04.582365  208717 grpc_attestor.go:186] ======= Attest ========
I0515 05:58:06.959677  208717 grpc_attestor.go:220] ======= Quote ========
I0515 05:58:12.920138  208717 grpc_attestor.go:257] ======= GetTLSKey ========
```

### Verifier

Run Verifier

```bash
export ATTESTOR_ADDRESS=127.0.0.1
go run src/client/grpc_verifier.go --host=$ATTESTOR_ADDRESS:50051 \
       --ekintermediateCA=certs/stmtpmekint10.pem --ekrootCA=certs/stmtpmekroot.pem \
       --expectedPCRMapSHA256=0:7bb4353897632fd086982175a027dafcc33f61adbab4ebfc6d13927b97a8c084  \
       --v=40 -alsologtostderr
```


```log
I0515 05:58:04.142669  208902 grpc_verifier.go:90] =============== GetPlatformCert ===============
I0515 05:58:04.151909  208902 grpc_verifier.go:97] =============== GetPlatformCert Returned from remote ===============
I0515 05:58:04.152292  208902 grpc_verifier.go:117]      PlatformCertificate Issuer: CN=www.intel.com,OU=TrustedSupplyChain,O=Intel Corporation,L=Santa Clara,ST=California,C=US
I0515 05:58:04.152368  208902 grpc_verifier.go:118]      PlatformCertificate Version: 2
I0515 05:58:04.152387  208902 grpc_verifier.go:120]      PlatformCertificate CredentialSpecification: 
I0515 05:58:04.152406  208902 grpc_verifier.go:121]      PlatformCertificate PlatformManufacturer: Intel
I0515 05:58:04.152422  208902 grpc_verifier.go:122]      PlatformCertificate PlatformModel: S2600KP
I0515 05:58:04.152440  208902 grpc_verifier.go:123]      PlatformCertificate PlatformVersion: H76962-350
I0515 05:58:04.152457  208902 grpc_verifier.go:124]      PlatformCertificate PropertiesURI: 
I0515 05:58:04.152476  208902 grpc_verifier.go:139]      PlatformCertificate Holder.Issuer: CN=STMicro
I0515 05:58:04.152502  208902 grpc_verifier.go:140]      PlatformCertificate Holder.Serial: 449600017855339869538679649152375580078880538087
I0515 05:58:04.152535  208902 grpc_verifier.go:141]      PlatformCertificate Holder.Issuer.CommonName: STMicro
I0515 05:58:04.152560  208902 grpc_verifier.go:146]      PlatformCertificate TBBSecurityAssertions.Iso9000URI: URL to iso9000 certificate
I0515 05:58:04.152585  208902 grpc_verifier.go:147]      PlatformCertificate TBBSecurityAssertions.CcInfo.ProfileOid: 
I0515 05:58:04.152615  208902 grpc_verifier.go:148]      PlatformCertificate TBBSecurityAssertions.CcInfo.ProfileURI: 
I0515 05:58:04.152643  208902 grpc_verifier.go:149]      PlatformCertificate TBBSecurityAssertions.CcInfo.TargetOid: 
I0515 05:58:04.152670  208902 grpc_verifier.go:150]      PlatformCertificate TBBSecurityAssertions.CcInfo.TargetURI: 
I0515 05:58:04.152697  208902 grpc_verifier.go:151]      PlatformCertificate TBBSecurityAssertions.CcInfo.Version: CC Version
I0515 05:58:04.152726  208902 grpc_verifier.go:153]      PlatformCertificate TCGPlatformSpecification.Version: {1 2 1}
I0515 05:58:04.152759  208902 grpc_verifier.go:154]      PlatformCertificate TCGPlatformSpecification.Version.MajorVersion: 1
I0515 05:58:04.152789  208902 grpc_verifier.go:155]      PlatformCertificate TCGPlatformSpecification.Version.MinorVersion: 2
I0515 05:58:04.152818  208902 grpc_verifier.go:156]      PlatformCertificate TCGPlatformSpecification.Version.Revision: 1
I0515 05:58:04.152848  208902 grpc_verifier.go:158]      PlatformCertificate UserNotice.UserNotice.ExplicitText: TCPA Trusted Platform Endorsement
I0515 05:58:04.152879  208902 grpc_verifier.go:159]      PlatformCertificate UserNotice.UserNotice.Organization: Credential Type Label
I0515 05:58:04.152909  208902 grpc_verifier.go:160]      PlatformCertificate UserNotice.UserNotice.NoticeNumbers: []
I0515 05:58:04.153110  208902 grpc_verifier.go:167]  Verified Platform cert signed by privacyCA
I0515 05:58:04.153146  208902 grpc_verifier.go:172]  Platform Cert's Holder SerialNumber 4ec0c316cbdf7f039e97a14145468b0320633de7
I0515 05:58:04.153180  208902 grpc_verifier.go:183] =============== start GetEK ===============
I0515 05:58:04.154069  208902 grpc_verifier.go:197]         AuthType, ServerName tls, attestor.domain.com
I0515 05:58:04.154146  208902 grpc_verifier.go:208]         EKM my_nonce: 95d967570a407703b85d426858d9dd342a4668e33debb53b160aa5032eabf173
I0515 05:58:04.154323  208902 grpc_verifier.go:263]      TPM Manufacturer id:53544D20
I0515 05:58:04.154429  208902 grpc_verifier.go:266]      TPM Model ST33KTPM2X
I0515 05:58:04.154528  208902 grpc_verifier.go:270]      TPM Version id:00090100
I0515 05:58:04.154636  208902 grpc_verifier.go:303]      TPM Family 2.0
I0515 05:58:04.154753  208902 grpc_verifier.go:304]      TPM Level 0
I0515 05:58:04.154845  208902 grpc_verifier.go:305]      TPM Revision 159
I0515 05:58:04.154953  208902 grpc_verifier.go:320]         EKCertificate ========
-----BEGIN CERTIFICATE-----
MIIFDzCCAvegAwIBAgIUfjZhZT57WoF0PQPxGpJW7P++BIEwDQYJKoZIhvcNAQEM
BQAwWTELMAkGA1UEBhMCQ0gxHjAcBgNVBAoTFVNUTWljcm9lbGVjdHJvbmljcyBO
VjEqMCgGA1UEAxMhU1RTQUZFIFRQTSBSU0EgSW50ZXJtZWRpYXRlIENBIDEwMCAX
DTIzMDQxNjEwMzM0NVoYDzk5OTkxMjMxMjM1OTU5WjAAMIIBIjANBgkqhkiG9w0B
AQEFAAOCAQ8AMIIBCgKCAQEA0shjU+4tGz+FRFoe4SVxNtZA7hGxA1MeC891SLmn
OMiXGZGgBJGPv+USVLY2OJFln4X94vvNE1Rh06HFG9FoPBA//coeFavi7cjV9GUh
3beY8wX6ergOMTxl38xbiBN6LKYuqwQ51wuMrOB5Q0n8XIJwjCfnSWGCAo16FadU
xteEixOuWbHW+If7T/j3FsHzD+QCbCYrQ1AzrHCHNsiwMAyKXdIncJnNaKi8qLDl
D4IXT2RbjijSoAFWO086Li5gwtVVoMULN4B4d83309EI11LvCiNCWGAJZ7pxTME7
+WJMurXcJec19c9M4YrjEAEggxfxKc+Bktv1ibCCeOegVwIDAQABo4IBJDCCASAw
HwYDVR0jBBgwFoAUZXBipxBWkW+Mf3mKkt3m2B0KmNowVwYDVR0RAQH/BE0wS6RJ
MEcxFjAUBgVngQUCAQwLaWQ6NTM1NDREMjAxFTATBgVngQUCAgwKU1QzM0tUUE0y
WDEWMBQGBWeBBQIDDAtpZDowMDA5MDEwMDAiBgNVHQkEGzAZMBcGBWeBBQIQMQ4w
DAwDMi4wAgEAAgIAnzAMBgNVHRMBAf8EAjAAMBAGA1UdJQQJMAcGBWeBBQgBMA4G
A1UdDwEB/wQEAwIFIDBQBggrBgEFBQcBAQREMEIwQAYIKwYBBQUHMAKGNGh0dHA6
Ly9zdy1jZW50ZXIuc3QuY29tL1NUU0FGRS9zdHNhZmV0cG1yc2FpbnQxMC5jcnQw
DQYJKoZIhvcNAQEMBQADggIBAKNipPkkgRUMAyTJh8xWRAmOP2put6d/DEuVsYRn
hvsVwJPUYc2Ki1hm8fy8OCnRAcChwQDj0tgcyAjol1qusSG5Z+pkIwdet4WLcYiE
0uf/EWMz4xvsmIDDIpn38flbAM+5XjsVczGC8/WM2DFxSllmmD5BpZDm0tBDnwCU
3bpBNoeUZ/gGoYNdDxWPnwqc5Zy1+AheaigQzGUPFKRU2xMuBkOTmdJgY357dvLZ
vVrJUWGSJq8Ee/bRgj/UFFPABLFQgV8S8x7HnMxmwUUwgHC3F94wEs5/mo/VQXbU
uJ2TlKhT3Dy/3ssKjNgVOnIOb7G54yjg2CzR8ncI9oz0QGJm4P243Zv+iBSsKTXb
2di1CxWuuE7s23ajExBnTKTfnERfeHbtiT8MUqre02kDHX8ql/xrM0fOq02+JODZ
U0DnsZI3wXDEvjRy8X+GyiDGU+wnpgycSNzoSAWvvIRxRdqcaZ4QJh9diABX41CE
teI4QdS32b7LejPcbJH566NhlPReZDFgssIEGjdYYLaGFZdya3YEqgZMfyRfVL16
93DBivvYwgtyqQj+aKAhAGLJTQEXqdQh662hMPZ5bBQS8FZ8MncS6CodLYvsXJUw
qYloxK9lcNDk0rkIibqzSUL1+lPbpQwE2xV+LQZbNIyj2hQ6XTYmwrsT+C8Fp/vU
Cfz7
-----END CERTIFICATE-----

I0515 05:58:04.155080  208902 grpc_verifier.go:336]      EKCert  Issuer CN=STSAFE TPM RSA Intermediate CA 10,O=STMicroelectronics NV,C=CH
I0515 05:58:04.155153  208902 grpc_verifier.go:337]      EKCert  IssuingCertificateURL [http://sw-center.st.com/STSAFE/stsafetpmrsaint10.crt]
I0515 05:58:04.155211  208902 grpc_verifier.go:338]      EKCert  SerialNumber 720545561707831497387264474846090629232862299265
I0515 05:58:04.155258  208902 grpc_verifier.go:340]     EkCert Public Key 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0shjU+4tGz+FRFoe4SVx
NtZA7hGxA1MeC891SLmnOMiXGZGgBJGPv+USVLY2OJFln4X94vvNE1Rh06HFG9Fo
PBA//coeFavi7cjV9GUh3beY8wX6ergOMTxl38xbiBN6LKYuqwQ51wuMrOB5Q0n8
XIJwjCfnSWGCAo16FadUxteEixOuWbHW+If7T/j3FsHzD+QCbCYrQ1AzrHCHNsiw
MAyKXdIncJnNaKi8qLDlD4IXT2RbjijSoAFWO086Li5gwtVVoMULN4B4d83309EI
11LvCiNCWGAJZ7pxTME7+WJMurXcJec19c9M4YrjEAEggxfxKc+Bktv1ibCCeOeg
VwIDAQAB
-----END PUBLIC KEY-----

I0515 05:58:04.155319  208902 grpc_verifier.go:343]     Verifying EKCert
I0515 05:58:04.155622  208902 grpc_verifier.go:371]      EKCert Includes tcg-kp-EKCertificate ExtendedKeyUsage 2.23.133.8.1
I0515 05:58:04.157209  208902 grpc_verifier.go:398]     EKCert Verified
I0515 05:58:04.157259  208902 grpc_verifier.go:400]      EKPub: 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0shjU+4tGz+FRFoe4SVx
NtZA7hGxA1MeC891SLmnOMiXGZGgBJGPv+USVLY2OJFln4X94vvNE1Rh06HFG9Fo
PBA//coeFavi7cjV9GUh3beY8wX6ergOMTxl38xbiBN6LKYuqwQ51wuMrOB5Q0n8
XIJwjCfnSWGCAo16FadUxteEixOuWbHW+If7T/j3FsHzD+QCbCYrQ1AzrHCHNsiw
MAyKXdIncJnNaKi8qLDlD4IXT2RbjijSoAFWO086Li5gwtVVoMULN4B4d83309EI
11LvCiNCWGAJZ7pxTME7+WJMurXcJec19c9M4YrjEAEggxfxKc+Bktv1ibCCeOeg
VwIDAQAB
-----END PUBLIC KEY-----

I0515 05:58:04.157356  208902 grpc_verifier.go:416] =============== end GetEKCert ===============
I0515 05:58:04.157410  208902 grpc_verifier.go:419] =============== start GetAK ===============
I0515 05:58:04.580982  208902 grpc_verifier.go:452]       ak public 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwLebuMYQBYc6JFZdlhtE
J81b5FSF28GRHNOC2X272QuFQQgRhBtZMU03i4cXBOAV55HFf8M7q1G17jAJIF0q
HtDnJNWmNLLodHo2wR2jHUhkHAbQH+jbv589wb4OPi00Sq0n6yKR8AiQ2P8U7yEa
hpS7S7BhluwIEBrAYce35MK6ZqUbnnmck3jsfMtYXcwjNu2gGfMHxakjoEjzBeFp
+FqZbDVq5W2JM6jK+z3N/sKMu3r+6/y75sK6kVe9nZlemdGLkh+g1phVOcbdMlwA
3MVo5jryYXVjqoG1QRNoYbrI+L0fzUZqiZld7ELwS163Fxpw7zlFTYu+I3jRD+aC
1QIDAQAB
-----END PUBLIC KEY-----

I0515 05:58:04.581114  208902 grpc_verifier.go:453] =============== end GetAK ===============
I0515 05:58:04.581177  208902 grpc_verifier.go:456] =============== start Attest ===============
I0515 05:58:04.581741  208902 grpc_verifier.go:469]       Outbound Secret: WTahtmK83gZTIY49c/m1mWwRhJMhADG7lxoGn7gB204=
I0515 05:58:06.958635  208902 grpc_verifier.go:485]       Inbound Secret: WTahtmK83gZTIY49c/m1mWwRhJMhADG7lxoGn7gB204=
I0515 05:58:06.958754  208902 grpc_verifier.go:488]       inbound/outbound Secrets Match; accepting AK
I0515 05:58:06.958885  208902 grpc_verifier.go:493] =============== end Attest ===============
I0515 05:58:06.959004  208902 grpc_verifier.go:496] =============== start Quote/Verify ===============
I0515 05:58:12.917979  208902 grpc_verifier.go:541]       quote-attested public 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwLebuMYQBYc6JFZdlhtE
J81b5FSF28GRHNOC2X272QuFQQgRhBtZMU03i4cXBOAV55HFf8M7q1G17jAJIF0q
HtDnJNWmNLLodHo2wR2jHUhkHAbQH+jbv589wb4OPi00Sq0n6yKR8AiQ2P8U7yEa
hpS7S7BhluwIEBrAYce35MK6ZqUbnnmck3jsfMtYXcwjNu2gGfMHxakjoEjzBeFp
+FqZbDVq5W2JM6jK+z3N/sKMu3r+6/y75sK6kVe9nZlemdGLkh+g1phVOcbdMlwA
3MVo5jryYXVjqoG1QRNoYbrI+L0fzUZqiZld7ELwS163Fxpw7zlFTYu+I3jRD+aC
1QIDAQAB
-----END PUBLIC KEY-----

I0515 05:58:12.918234  208902 grpc_verifier.go:556]      PCR: 0, verified: true value: 7bb4353897632fd086982175a027dafcc33f61adbab4ebfc6d13927b97a8c084
I0515 05:58:12.918314  208902 grpc_verifier.go:556]      PCR: 1, verified: true value: 0e2c30270bbf1e52967a5ebedc6cdffb7f5166c70fb5fbda021ab5db4f87ca80
I0515 05:58:12.918323  208902 grpc_verifier.go:556]      PCR: 2, verified: true value: f8650efffd171c5d05d0aface51ef1ab216e25b7660faa6d6b9d1731b7c2f748
I0515 05:58:12.918330  208902 grpc_verifier.go:556]      PCR: 3, verified: true value: 3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969
I0515 05:58:12.918337  208902 grpc_verifier.go:556]      PCR: 4, verified: true value: 061ba5c6dd464ee6f9bbb6040070a9f0fc9e571f02e3b25d903cde8a881d05eb
I0515 05:58:12.918344  208902 grpc_verifier.go:556]      PCR: 5, verified: true value: 07ffb98f19e294b075eeac8405a8121ee3be0aceb7a5c3dfa4c204a0e7f492f8
I0515 05:58:12.918351  208902 grpc_verifier.go:556]      PCR: 6, verified: true value: 3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969
I0515 05:58:12.918357  208902 grpc_verifier.go:556]      PCR: 7, verified: true value: 46d45493dc751af8c46996eedaf69d7d4012d46ca8d75bbb141d23103361e59e
I0515 05:58:12.918363  208902 grpc_verifier.go:556]      PCR: 8, verified: true value: 10e6796c8f61d4b7ec0e13234f2940c8ef7406a328dbadaeced68b8b892dbc4f
I0515 05:58:12.918369  208902 grpc_verifier.go:556]      PCR: 9, verified: true value: 2717bb4bd752179da9956be4ee2f841ba0da2e6dc59474b46868170612299db0
I0515 05:58:12.918376  208902 grpc_verifier.go:556]      PCR: 10, verified: true value: 578d11d830b0f822bcc2703f5144229e00ca3c9a3528dfde8dd195b16d9ad16d
I0515 05:58:12.918387  208902 grpc_verifier.go:556]      PCR: 11, verified: true value: c6b83488982b0ddbb8e815630c6ea02415981a4229f81d938a764ef11089d4df
I0515 05:58:12.918395  208902 grpc_verifier.go:556]      PCR: 12, verified: true value: 0000000000000000000000000000000000000000000000000000000000000000
I0515 05:58:12.918401  208902 grpc_verifier.go:556]      PCR: 13, verified: true value: 0000000000000000000000000000000000000000000000000000000000000000
I0515 05:58:12.918407  208902 grpc_verifier.go:556]      PCR: 14, verified: true value: 0000000000000000000000000000000000000000000000000000000000000000
I0515 05:58:12.918420  208902 grpc_verifier.go:556]      PCR: 15, verified: true value: 0000000000000000000000000000000000000000000000000000000000000000
I0515 05:58:12.918428  208902 grpc_verifier.go:556]      PCR: 16, verified: true value: 0000000000000000000000000000000000000000000000000000000000000000
I0515 05:58:12.918434  208902 grpc_verifier.go:556]      PCR: 17, verified: true value: ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
I0515 05:58:12.918440  208902 grpc_verifier.go:556]      PCR: 18, verified: true value: ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
I0515 05:58:12.918446  208902 grpc_verifier.go:556]      PCR: 19, verified: true value: ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
I0515 05:58:12.918454  208902 grpc_verifier.go:556]      PCR: 20, verified: true value: ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
I0515 05:58:12.918461  208902 grpc_verifier.go:556]      PCR: 21, verified: true value: ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
I0515 05:58:12.918469  208902 grpc_verifier.go:556]      PCR: 22, verified: true value: ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
I0515 05:58:12.918475  208902 grpc_verifier.go:556]      PCR: 23, verified: true value: 0000000000000000000000000000000000000000000000000000000000000000
I0515 05:58:12.918483  208902 grpc_verifier.go:568]      quotes verified
I0515 05:58:12.919386  208902 grpc_verifier.go:597]      secureBoot State enabled: [true]
I0515 05:58:12.919548  208902 grpc_verifier.go:603] =============== end Quote/Verify ===============
I0515 05:58:12.919626  208902 grpc_verifier.go:606] =============== start NewKey ===============
I0515 05:58:13.326590  208902 grpc_verifier.go:618]         PublicKey ========
-----BEGIN Public Key-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEHt/0kwFfF6LXGyK4ktCTH/Aw/h6Q
hw24Zb37gjQVwAscYNgwrHqF3xcM8jpk21rwkDz27bN+tntmXXVDBJlqPw==
-----END Public Key-----

I0515 05:58:13.327043  208902 grpc_verifier.go:643]      Key AuthPolicy []
I0515 05:58:13.327129  208902 grpc_verifier.go:653]      Key TPM Properties mask: 262258
I0515 05:58:13.327270  208902 grpc_verifier.go:656]      Key Expected Properties mask 262258
I0515 05:58:13.327383  208902 grpc_verifier.go:687]      key verified 
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEHt/0kwFfF6LXGyK4ktCTH/Aw/h6Q
hw24Zb37gjQVwAscYNgwrHqF3xcM8jpk21rwkDz27bN+tntmXXVDBJlqPw==
-----END PUBLIC KEY-----

I0515 05:58:13.327463  208902 grpc_verifier.go:688] =============== end NewKey ===============
```

---

## Setup on GCE

If you want to instead test with GCP VM:

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

I0511 00:04:30.432145    4402 grpc_attestor.go:291] Getting EKCert
I0511 00:04:30.447129    4402 grpc_attestor.go:311] ECCert with available Issuer: CN=EK/AK CA Intermediate,OU=Google Cloud,O=Google LLC,L=Mountain View,ST=California,C=US
I0511 00:04:30.863962    4402 grpc_attestor.go:407] Generated ECC Public 
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEpkUDmEEkQ5wQnyJLS4eAhHjanuF/
27WvMnWziBn2wR39sxmVG2XvIlIjlSR/pvTLAy23umuUmwoIGd2UdZcu/g==
-----END PUBLIC KEY-----
I0511 00:04:30.864605    4402 grpc_attestor.go:432] Starting gRPC server on port :50051
I0511 00:05:29.704283    4402 grpc_attestor.go:126] ======= GetPlatformCert ========
I0511 00:05:29.704376    4402 grpc_attestor.go:144]      Returning GetPlatformCert ========
I0511 00:05:30.540157    4402 grpc_attestor.go:151] ======= GetEK ========
I0511 00:05:31.641160    4402 grpc_attestor.go:163] ======= GetAK ========
I0511 00:05:32.022458    4402 grpc_attestor.go:186] ======= Attest ========
I0511 00:05:32.843147    4402 grpc_attestor.go:220] ======= Quote ========
I0511 00:05:35.966199    4402 grpc_attestor.go:257] ======= GetTLSKey ========

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
#            Authority Information Access: 
#                CA Issuers - URI:http://privateca-content-65d53b14-0000-212a-a633-883d24f57bb8.storage.googleapis.com/0c3e79eb0898d02ebb0a/ca.crt


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

go run src/client/grpc_verifier.go --host=$ATTESTOR_ADDRESS:50051 \
       --ekintermediateCA=certs/ek_intermediate.pem  --ekrootCA=certs/ek_root.pem  --expectedPCRMapSHA256=0:a0b5ff3383a1116bd7dc6df177c0c2d433b9ee1813ea958fa5d166a202cb2a85 \
        --v=10 -alsologtostderr
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

