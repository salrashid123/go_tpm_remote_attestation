# TPM Remote Attestation protocol using go-tpm and gRPC

This repo contains a sample `gRPC` client server application that uses a Trusted Platform Module for:

* TPM [Remote Attestation](https://tpm2-software.github.io/tpm2-tss/getting-started/2019/12/18/Remote-Attestation.html)
* TPM [Quote-Verify](https://github.com/salrashid123/tpm2/tree/master/quote_verify)
* TPM Attestation of signing key
* Parse TPM EventLog; verify SecureBoot

>>> **NOTE** the code outlined here is **NOT** supported by google.


You can use this standalone to setup a gRPC client/server for remote attestation.

There are *TWO* branches to this repo: 

* [pull](https://github.com/salrashid123/go_tpm_remote_attestation/tree/pull) (this branch):  In this mode, the attestor is the client initiator that makes an rpc call to the verifier
* [push](https://github.com/salrashid123/go_tpm_remote_attestation/tree/push):  In this mode, the attestor is the server and the verifier makes an rpc call to the attestor


There are two parts to this application:

* `attestor`: a `gRPC` TPM client which connects to the corresponding verifier and provides apis which allows RemoteAttestation, QuoteVerify and finally transmits an new ECC key and recieves an x509 from the verifier.

* `verifier`:  a `gRPC` server which accepts connections from a attestor, and then instructs the performs remote attestation, quote/verify and then transmits an ECC public key back to the verifier which is certified to exist on that TPM

Finally, there are three ways to test this

* locally using as software TPM with a synthetic eventlog and PCRs
* locally using a real TPM (if you have secure boot and eventlog already)
* remotely on two GCE Shielded VMs with TPM and secure boot

---

On startup:

1. Attestor contacts the Verifier
2. Attestor sends the Platform Certificate
3. Verifier checks the platform certificate specifications and verifies it with a demo platform CA
4. Attestor sends EKCert (EK)
5. Verifier checks Issuer and Signature of EKCert with CAs
6. Verifier optionally compares EK SerialNumber with PlatformCert
7. (start `MakeCredential`) Attestor sends AKPublic (AK)
8. Verifier uses EK and AK to generate (secret,encryptedCredential) via MakeCredential
9. Verifier returnes encryptedCredential to Attestor
10. (start `ActivateCredential`)Attestor uses TPM to decode encryptedCredential and acquire secret
11. Attestor transmit secret to Verifier
12. Verifer compares secrets and accepts AK
13. (start `Quote/Verify`) Attestor Quote initiation request to Verifer 
14. Verifer generates random nonce
15. Verifer returns nonce to Attestor
16. Attestor generates Quote over PCR values, nonce and uses AK to sign
17. Attestor generates EventLog 
18. Attestor returns Quote and EventLog to Verifier 
19. Verifier checks signature of the Attestation is by the AK and the
    PCR values from the Quote and the nonce values match.
    Verifier replays the eventLog to confirm derived PCR value.
20. (optiona Issue New ECC x509) Attestor genrates an ECC newKey on TPM 
21. Attestor uses AK to certify newKey
22. Attestor transmits newKey and certification data to Verifer
23. Verifer confirms newKey is on the TPM and was certified by AK
24. Attestor uses newKey to generate a CSR
25. Attestor sends CSR to Verifier
26. Verifer confirms CSR's public key is certified newKey
27. Verifer signes csr and issues x509
28. Verifer returns x509 to Attestor
29. As a final step, the client initiate an mTLS connection to the Verifier

![images/pull.png](images/pull.png)

Note that prior to the start of this protocol, the Attestor creates a gRPC [HealthCheck](https://github.com/grpc/grpc/blob/master/doc/health-checking.md) request over TLS to the Verifier.

The TLS connection for that request returns a unique connection-specific [Exported Key Material](https://github.com/salrashid123/go_ekm_tls).  This `EKM` value is unique to the connection and is derived simultaneously by both the client and server.  The EKM value is used to populate the an internal session database on the Verifier for each of the steps from step `2` to step `28` after which the EKM entry in the datatabase is discarded.  This means that those steps 2->28 *must* be done on the same TLS session.


---

also see

 - [TPM based TLS using Attested Keys](https://github.com/salrashid123/tls_ak)
 - [Sign, Verify and decode using Google Cloud vTPM Attestation Key and Certificate](https://github.com/salrashid123/gcp-vtpm-ek-ak)
 - [go-attestation](https://github.com/google/go-attestation)


---

#### Setup using SoftwreTPM

If you want to test locally with a a software TPM, you will first need to install [swtpm](https://github.com/stefanberger/swtpm) and acquire an eventlog for quote/verify steps.

Note, the follwoing uses a sample event log acquired from a GCE instance.  The eventlog from a real GCE instance is replayed and used to increment the PCR values.  In the end, the eventlog and pcr values will match for the software TPM

First setup a swtpm with a named CA:

```bash
cd swtpm/
export XDG_CONFIG_HOME=`pwd`/config/
rm -rf myvtpm && mkdir myvtpm
swtpm_setup --tpmstate myvtpm --tpm2 --create-ek-cert --pcr-banks sha256 --create-platform-cert --write-ek-cert-files ekcerts/ 
swtpm socket --tpmstate dir=myvtpm --tpm2 --server type=tcp,port=2321 --ctrl type=tcp,port=2322 --flags not-need-init,startup-clear --log level=2

### then synchronize the eventlog's pcr values with the swtpm
go run eventlog.go  --eventLogFile=binary_bios_measurements --tpm-path="127.0.0.1:2321"

### so the current tpm2_pcrread
export TPM2TOOLS_TCTI="swtpm:port=2321"

$ tpm2_pcrread
  sha256:
    0 : 0xA0B5FF3383A1116BD7DC6DF177C0C2D433B9EE1813EA958FA5D166A202CB2A85
    1 : 0xE50EDB964F66A7417954B1506F78A49D62062228CE84EE0B4E7E3B0E19B64A69
    2 : 0x3D458CFE55CC03EA1F443F1562BEEC8DF51C75E14A9FCF9A7234A13F198E7969
    3 : 0x3D458CFE55CC03EA1F443F1562BEEC8DF51C75E14A9FCF9A7234A13F198E7969
    4 : 0xA3358453A5148B4E3F4B96B006AE1761A2CE4AEA75F6A13E10EB3E0903DFD6E2
    5 : 0x098A2AE2D1AABED3E346B9FEF96EC64056EA4043514672243BBF40B7D0972302
    6 : 0x3D458CFE55CC03EA1F443F1562BEEC8DF51C75E14A9FCF9A7234A13F198E7969
    7 : 0x0A3F60CEA411388B09EAC782999F5E62246AB5469F9047EB508AA22C4DCD2237
    8 : 0xA775D521739876ECDE2C17D0E856C584EC513E8758D9199A3D5C735836BA0EBE
    9 : 0x4A7254A1740444F04EC61CF3F8EB8FFB5DAE2069B44AD900E894B34A07626B36
    10: 0x0000000000000000000000000000000000000000000000000000000000000000
    11: 0x0000000000000000000000000000000000000000000000000000000000000000
    12: 0x0000000000000000000000000000000000000000000000000000000000000000
    13: 0x0000000000000000000000000000000000000000000000000000000000000000
    14: 0x306F9D8B94F17D93DC6E7CF8F5C79D652EB4C6C4D13DE2DDDC24AF416E13ECAF
    15: 0x0000000000000000000000000000000000000000000000000000000000000000
    16: 0x0000000000000000000000000000000000000000000000000000000000000000
    17: 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    18: 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    19: 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    20: 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    21: 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    22: 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    23: 0x0000000000000000000000000000000000000000000000000000000000000000

### you'll see its the same as the eventlog's replay

$ tpm2_eventlog binary_bios_measurements
  sha256:
    0  : 0xa0b5ff3383a1116bd7dc6df177c0c2d433b9ee1813ea958fa5d166a202cb2a85
    1  : 0xe50edb964f66a7417954b1506f78a49d62062228ce84ee0b4e7e3b0e19b64a69
    2  : 0x3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969
    3  : 0x3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969
    4  : 0xa3358453a5148b4e3f4b96b006ae1761a2ce4aea75f6a13e10eb3e0903dfd6e2
    5  : 0x098a2ae2d1aabed3e346b9fef96ec64056ea4043514672243bbf40b7d0972302
    6  : 0x3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969
    7  : 0x0a3f60cea411388b09eac782999f5e62246ab5469f9047eb508aa22c4dcd2237
    8  : 0xa775d521739876ecde2c17d0e856c584ec513e8758d9199a3d5c735836ba0ebe
    9  : 0x4a7254a1740444f04ec61cf3f8eb8ffb5dae2069b44ad900e894b34a07626b36
    14 : 0x306f9d8b94f17d93dc6e7cf8f5c79d652eb4c6c4d13de2dddc24af416e13ecaf
```

##### Verifier

So first start the verifier and specifiy the CA that signed the EK and the pcr value for the evenlog seeded values for pcr=0

```bash
go run src/server/grpc_verifier.go  \
       --ekrootCA swtpm/config/var/lib/swtpm-localca/issuercert.pem \
       --expectedPCRMapSHA256=0:a0b5ff3383a1116bd7dc6df177c0c2d433b9ee1813ea958fa5d166a202cb2a85 \
        --v=40 -alsologtostderr

I0901 01:20:14.191135 3921794 grpc_verifier.go:1402] Starting gRPC server on port :50051
I0901 01:20:14.191211 3921794 grpc_verifier.go:1403] Starting https server on port :50051
I0901 01:20:16.434752 3921794 grpc_verifier.go:175] ======= HealthCheck ========
I0901 01:20:16.443454 3921794 grpc_verifier.go:209] ======= OfferPlatformCert ========
I0901 01:20:16.443808 3921794 grpc_verifier.go:253]      PlatformCertificate Issuer: CN=Platform Root CA,OU=Enterprise,O=Google,C=US
I0901 01:20:16.443868 3921794 grpc_verifier.go:254]      PlatformCertificate Version: 2
I0901 01:20:16.443886 3921794 grpc_verifier.go:256]      PlatformCertificate CredentialSpecification: 
I0901 01:20:16.443901 3921794 grpc_verifier.go:257]      PlatformCertificate PlatformManufacturer: 
I0901 01:20:16.443916 3921794 grpc_verifier.go:258]      PlatformCertificate PlatformModel: 
I0901 01:20:16.443931 3921794 grpc_verifier.go:259]      PlatformCertificate PlatformVersion: 
I0901 01:20:16.443946 3921794 grpc_verifier.go:260]      PlatformCertificate PropertiesURI: 
I0901 01:20:16.443962 3921794 grpc_verifier.go:275]      PlatformCertificate Holder.Issuer: CN=swtpm-localca
I0901 01:20:16.443987 3921794 grpc_verifier.go:276]      PlatformCertificate Holder.Serial: 1240
I0901 01:20:16.444022 3921794 grpc_verifier.go:277]      PlatformCertificate Holder.Issuer.CommonName: swtpm-localca
I0901 01:20:16.444047 3921794 grpc_verifier.go:282]      PlatformCertificate TBBSecurityAssertions.Iso9000URI: 
I0901 01:20:16.444072 3921794 grpc_verifier.go:283]      PlatformCertificate TBBSecurityAssertions.CcInfo.ProfileOid: 
I0901 01:20:16.444102 3921794 grpc_verifier.go:284]      PlatformCertificate TBBSecurityAssertions.CcInfo.ProfileURI: 
I0901 01:20:16.444129 3921794 grpc_verifier.go:285]      PlatformCertificate TBBSecurityAssertions.CcInfo.TargetOid: 
I0901 01:20:16.444157 3921794 grpc_verifier.go:286]      PlatformCertificate TBBSecurityAssertions.CcInfo.TargetURI: 
I0901 01:20:16.444188 3921794 grpc_verifier.go:287]      PlatformCertificate TBBSecurityAssertions.CcInfo.Version: 
I0901 01:20:16.444216 3921794 grpc_verifier.go:289]      PlatformCertificate TCGPlatformSpecification.Version: {0 0 0}
I0901 01:20:16.444249 3921794 grpc_verifier.go:290]      PlatformCertificate TCGPlatformSpecification.Version.MajorVersion: 0
I0901 01:20:16.444279 3921794 grpc_verifier.go:291]      PlatformCertificate TCGPlatformSpecification.Version.MinorVersion: 0
I0901 01:20:16.444308 3921794 grpc_verifier.go:292]      PlatformCertificate TCGPlatformSpecification.Version.Revision: 0
I0901 01:20:16.444338 3921794 grpc_verifier.go:294]      PlatformCertificate UserNotice.UserNotice.ExplicitText: 
I0901 01:20:16.444369 3921794 grpc_verifier.go:295]      PlatformCertificate UserNotice.UserNotice.Organization: 
I0901 01:20:16.444400 3921794 grpc_verifier.go:296]      PlatformCertificate UserNotice.UserNotice.NoticeNumbers: []
I0901 01:20:16.444605 3921794 grpc_verifier.go:303]      Verified Platform cert signed by privacyCA
I0901 01:20:16.445812 3921794 grpc_verifier.go:324] ======= OfferEK ========
I0901 01:20:16.445928 3921794 grpc_verifier.go:371]      TPM Manufacturer id:00001014
I0901 01:20:16.445946 3921794 grpc_verifier.go:374]      TPM Model swtpm
I0901 01:20:16.445959 3921794 grpc_verifier.go:378]      TPM Version id:20240125
I0901 01:20:16.445991 3921794 grpc_verifier.go:410]      TPM Family 2.0
I0901 01:20:16.446009 3921794 grpc_verifier.go:411]      TPM Level 0
I0901 01:20:16.446026 3921794 grpc_verifier.go:412]      TPM Revision 183
I0901 01:20:16.446055 3921794 grpc_verifier.go:427]         EKCertificate ========
-----BEGIN CERTIFICATE-----
MIID9TCCAl2gAwIBAgICBNgwDQYJKoZIhvcNAQELBQAwGDEWMBQGA1UEAxMNc3d0
cG0tbG9jYWxjYTAgFw0yNjA5MDEwNDU3MjhaGA85OTk5MTIzMTIzNTk1OVowEjEQ
MA4GA1UEAxMHdW5rbm93bjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
AOtRH3GbA3IOMffhGngZyT55CHxRxaVdrd0JPEh4bR2Ry49kLWAWuv2mKHkA3YNd
6R2RvIbUcjBJJHl76rKc1wT4nEpeZ+6mfFNSZNXqa0WW5iXKrXKEoQ62reZgJieD
JEGr8gzkqIXpV9+BX7Pkv9YLJxkXJj9GrGTMiMRsRIrj/Phq6Gv1BWfZGjJWLwV7
j0i9VPv9IDqPKYdqEKTxf27MT8izli3iNxo4xFhV9joZ06T+vTbXZ/35IBxMK7n0
qkDgZAUZP3NSBR0BlMU/TBvg6QwpMawfKHVa/C25ZTHM/JRcbQpcdCbJUWb3Vmcl
Io3/gu1oFmjOiBhDz2t+nT8CAwEAAaOBzDCByTAQBgNVHSUECTAHBgVngQUIATBS
BgNVHREBAf8ESDBGpEQwQjEWMBQGBWeBBQIBDAtpZDowMDAwMTAxNDEQMA4GBWeB
BQICDAVzd3RwbTEWMBQGBWeBBQIDDAtpZDoyMDI0MDEyNTAMBgNVHRMBAf8EAjAA
MCIGA1UdCQQbMBkwFwYFZ4EFAhAxDjAMDAMyLjACAQACAgC3MB8GA1UdIwQYMBaA
FC9tUdt3Nuy5Lc3iJ4AxyLHsw4e0MA4GA1UdDwEB/wQEAwIFIDANBgkqhkiG9w0B
AQsFAAOCAYEAHuRqc32MtPOUGGIjMurzXaPfx5B7rO8qOB6Yr9V2j2c+Z6RLfVnF
njFXbpDh2wbYJQcD03AhZlP/WVqKi5o17XIzyc8sJtSTMCEeHAl/NlEdU1D4zyAp
9Ps3hwP+CGi7bvR3cjgZ2oZw6RbcSB+clX7p9iJ4yK4Woa47ks0yIypHxUnPBNmt
OQWVo7hWJ7UaqIBVYltnhFHw8lXzXNkD69iHsdsTOEeEsHR/1ne2pWe/5ro4YY/A
zaL7r/yxm4QA41aWrPf6n2mC3E6W1xpDZ1RLIB7OEmI7WLDu0ycAg/Mw6lxxU0eL
wC+Jqav8zmuaDc0Zp29YARNvugj3oJezzfzBLZSeZAaO1Z4kAoWTsla/INHlXvwd
Te5Zw/AlX8HvTafBR3IHr4MVdIXVjkCuI6+DtzSaPrvTe+olaC2uPNjHG9dokMR5
b5pD9fdaxWB5fYSNAScIQWJ0SgFgtL5k07Jvn0ykv0PGHn9hfnTCjfsxxRNCofe0
lDGEK+W+W3A9
-----END CERTIFICATE-----

I0901 01:20:16.446128 3921794 grpc_verifier.go:443]      EKCert  Issuer CN=swtpm-localca
I0901 01:20:16.446162 3921794 grpc_verifier.go:444]      EKCert  IssuingCertificateURL []
I0901 01:20:16.446190 3921794 grpc_verifier.go:445]      EKCert  SerialNumber 1240
I0901 01:20:16.446213 3921794 grpc_verifier.go:447]     EkCert Public Key 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA61EfcZsDcg4x9+EaeBnJ
PnkIfFHFpV2t3Qk8SHhtHZHLj2QtYBa6/aYoeQDdg13pHZG8htRyMEkkeXvqspzX
BPicSl5n7qZ8U1Jk1eprRZbmJcqtcoShDrat5mAmJ4MkQavyDOSohelX34Ffs+S/
1gsnGRcmP0asZMyIxGxEiuP8+Groa/UFZ9kaMlYvBXuPSL1U+/0gOo8ph2oQpPF/
bsxPyLOWLeI3GjjEWFX2OhnTpP69Ntdn/fkgHEwrufSqQOBkBRk/c1IFHQGUxT9M
G+DpDCkxrB8odVr8LbllMcz8lFxtClx0JslRZvdWZyUijf+C7WgWaM6IGEPPa36d
PwIDAQAB
-----END PUBLIC KEY-----

I0901 01:20:16.446244 3921794 grpc_verifier.go:450]     Verifying EKCert
I0901 01:20:16.446392 3921794 grpc_verifier.go:478]      EKCert Includes tcg-kp-EKCertificate ExtendedKeyUsage 2.23.133.8.1
I0901 01:20:16.446796 3921794 grpc_verifier.go:507]     EKCert Verified
I0901 01:20:16.446828 3921794 grpc_verifier.go:530] =============== end OfferEK ===============
I0901 01:20:16.540559 3921794 grpc_verifier.go:535] ======= OfferAK ========
I0901 01:20:16.540851 3921794 grpc_verifier.go:579]       ak public 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxMQFyqBEZzf+HnofofNQ
7mTCx4k+VuBQupA0iKRM5SWRz0XciXY5WW4JTQyFb6V3vL2upwXVRxW4RSzDrJDZ
/Jim+VQqQQl67967wYN9t7NUNqVFLCGSubYQLvShay/yz93pMbHixJw64VD61ggl
CBoRAwMgXtIRAOK7XRJn79zoFjSxZIf8/tTW7SYNWgt/z+qF9hwt/gE8iT5EPHLb
wU0iW0r7nuKpABs9TfUQD4aJdtySPJ7Y3x1k75Db8zs8KFZgHNl4tefarIO8vw6+
ORuqBK9PcUD46HPtgdtuHJywfOKRg5PxOThYLORBCibj3zApzEUA1klA2r/kXDZg
ZQIDAQAB
-----END PUBLIC KEY-----

I0901 01:20:16.540974 3921794 grpc_verifier.go:593] =============== end GetAK ===============
I0901 01:20:16.542220 3921794 grpc_verifier.go:599] ======= GetMakeCredential ========
I0901 01:20:16.542258 3921794 grpc_verifier.go:616] =============== end GetMakeCredential ===============
I0901 01:20:16.542778 3921794 grpc_verifier.go:630]       Outbound Secret: 6VhrZH0/pZ/qlVUyV+J7NWLZmOSPxPeqcAAzGP5BiCU=
I0901 01:20:16.550885 3921794 grpc_verifier.go:648] ======= SetActivateCredential ========
I0901 01:20:16.550918 3921794 grpc_verifier.go:678] =============== end SetActivateCredential ===============
I0901 01:20:16.551766 3921794 grpc_verifier.go:683] ======= OfferQuote ========
I0901 01:20:16.551804 3921794 grpc_verifier.go:708] =============== end OfferQuote ===============
I0901 01:20:16.563004 3921794 grpc_verifier.go:715] ======= SetQuote ========
I0901 01:20:16.565161 3921794 grpc_verifier.go:768]       quote-attested public 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxMQFyqBEZzf+HnofofNQ
7mTCx4k+VuBQupA0iKRM5SWRz0XciXY5WW4JTQyFb6V3vL2upwXVRxW4RSzDrJDZ
/Jim+VQqQQl67967wYN9t7NUNqVFLCGSubYQLvShay/yz93pMbHixJw64VD61ggl
CBoRAwMgXtIRAOK7XRJn79zoFjSxZIf8/tTW7SYNWgt/z+qF9hwt/gE8iT5EPHLb
wU0iW0r7nuKpABs9TfUQD4aJdtySPJ7Y3x1k75Db8zs8KFZgHNl4tefarIO8vw6+
ORuqBK9PcUD46HPtgdtuHJywfOKRg5PxOThYLORBCibj3zApzEUA1klA2r/kXDZg
ZQIDAQAB
-----END PUBLIC KEY-----

I0901 01:20:16.565443 3921794 grpc_verifier.go:798]      PCR: 0, verified: true value: a0b5ff3383a1116bd7dc6df177c0c2d433b9ee1813ea958fa5d166a202cb2a85
I0901 01:20:16.565474 3921794 grpc_verifier.go:798]      PCR: 1, verified: true value: e50edb964f66a7417954b1506f78a49d62062228ce84ee0b4e7e3b0e19b64a69
I0901 01:20:16.565490 3921794 grpc_verifier.go:798]      PCR: 2, verified: true value: 3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969
I0901 01:20:16.565500 3921794 grpc_verifier.go:798]      PCR: 3, verified: true value: 3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969
I0901 01:20:16.565510 3921794 grpc_verifier.go:798]      PCR: 4, verified: true value: a3358453a5148b4e3f4b96b006ae1761a2ce4aea75f6a13e10eb3e0903dfd6e2
I0901 01:20:16.565519 3921794 grpc_verifier.go:798]      PCR: 5, verified: true value: 098a2ae2d1aabed3e346b9fef96ec64056ea4043514672243bbf40b7d0972302
I0901 01:20:16.565528 3921794 grpc_verifier.go:798]      PCR: 6, verified: true value: 3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969
I0901 01:20:16.565537 3921794 grpc_verifier.go:798]      PCR: 7, verified: true value: 0a3f60cea411388b09eac782999f5e62246ab5469f9047eb508aa22c4dcd2237
I0901 01:20:16.565546 3921794 grpc_verifier.go:798]      PCR: 8, verified: true value: a775d521739876ecde2c17d0e856c584ec513e8758d9199a3d5c735836ba0ebe
I0901 01:20:16.565555 3921794 grpc_verifier.go:798]      PCR: 9, verified: true value: 4a7254a1740444f04ec61cf3f8eb8ffb5dae2069b44ad900e894b34a07626b36
I0901 01:20:16.565584 3921794 grpc_verifier.go:798]      PCR: 10, verified: true value: 0000000000000000000000000000000000000000000000000000000000000000
I0901 01:20:16.565595 3921794 grpc_verifier.go:798]      PCR: 11, verified: true value: 0000000000000000000000000000000000000000000000000000000000000000
I0901 01:20:16.565661 3921794 grpc_verifier.go:798]      PCR: 12, verified: true value: 0000000000000000000000000000000000000000000000000000000000000000
I0901 01:20:16.565677 3921794 grpc_verifier.go:798]      PCR: 13, verified: true value: 0000000000000000000000000000000000000000000000000000000000000000
I0901 01:20:16.565683 3921794 grpc_verifier.go:798]      PCR: 14, verified: true value: 306f9d8b94f17d93dc6e7cf8f5c79d652eb4c6c4d13de2dddc24af416e13ecaf
I0901 01:20:16.565689 3921794 grpc_verifier.go:798]      PCR: 15, verified: true value: 0000000000000000000000000000000000000000000000000000000000000000
I0901 01:20:16.565694 3921794 grpc_verifier.go:798]      PCR: 16, verified: true value: 0000000000000000000000000000000000000000000000000000000000000000
I0901 01:20:16.565699 3921794 grpc_verifier.go:798]      PCR: 17, verified: true value: ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
I0901 01:20:16.565704 3921794 grpc_verifier.go:798]      PCR: 18, verified: true value: ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
I0901 01:20:16.565710 3921794 grpc_verifier.go:798]      PCR: 19, verified: true value: ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
I0901 01:20:16.565715 3921794 grpc_verifier.go:798]      PCR: 20, verified: true value: ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
I0901 01:20:16.565721 3921794 grpc_verifier.go:798]      PCR: 21, verified: true value: ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
I0901 01:20:16.565727 3921794 grpc_verifier.go:798]      PCR: 22, verified: true value: ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
I0901 01:20:16.565735 3921794 grpc_verifier.go:798]      PCR: 23, verified: true value: 0000000000000000000000000000000000000000000000000000000000000000
I0901 01:20:16.565745 3921794 grpc_verifier.go:810]      quotes verified
I0901 01:20:16.566892 3921794 grpc_verifier.go:838]      secureBoot State enabled: [true]
I0901 01:20:16.570732 3921794 grpc_verifier.go:996] Issued AK Certificate: 
-----BEGIN CERTIFICATE-----
MIIEWjCCA0KgAwIBAgIRALq00gy4bcRWCqgYDqse3VcwDQYJKoZIhvcNAQELBQAw
TDELMAkGA1UEBhMCVVMxDzANBgNVBAoMBkdvb2dsZTETMBEGA1UECwwKRW50ZXJw
cmlzZTEXMBUGA1UEAwwOU2luZ2xlIFJvb3QgQ0EwHhcNMjYwOTAxMDUyMDE2WhcN
MjYwOTAyMDUyMDE2WjCBsTELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3Ju
aWExFjAUBgNVBAcTDU1vdW50YWluIFZpZXcxEDAOBgNVBAoTB0FjbWUgQ28xEzAR
BgNVBAsTCkVudGVycHJpc2UxHDAaBgNVBAMTE2F0dGVzdG9yLmRvbWFpbi5jb20x
MDAuBgNVBAUTJzExNDU3NjI1NjU5MzY5MTUwODA5NzM1MTcxMjc1MzE1ODAzNjU1
OTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMTEBcqgRGc3/h56H6Hz
UO5kwseJPlbgULqQNIikTOUlkc9F3Il2OVluCU0MhW+ld7y9rqcF1UcVuEUsw6yQ
2fyYpvlUKkEJeu/eu8GDfbezVDalRSwhkrm2EC70oWsv8s/d6TGx4sScOuFQ+tYI
JQgaEQMDIF7SEQDiu10SZ+/c6BY0sWSH/P7U1u0mDVoLf8/qhfYcLf4BPIk+RDxy
28FNIltK+57iqQAbPU31EA+GiXbckjye2N8dZO+Q2/M7PChWYBzZeLXn2qyDvL8O
vjkbqgSvT3FA+Ohz7YHbbhycsHzikYOT8Tk4WCzkQQom498wKcxFANZJQNq/5Fw2
YGUCAwEAAaOB0DCBzTAOBgNVHQ8BAf8EBAMCB4AwDAYDVR0TAQH/BAIwADAfBgNV
HSMEGDAWgBTs8OpTUz+fI9zBDjEQNwfe3udu8zCBiwYDVR0RBIGDMIGAoCwGCCsG
AQUFBwgEoCAwHoQcU0lNMDovbVHbdzbsuS3N4ieAMcix7MOHtDoE2KBQBggrBgEF
BQcIA6BEMEIMQDAyMzNhYWFjYjNmNGI1NGUwZGI1NjJkNzZhNjJmYzFmODVjZTRl
MTE3ZWE3MWZjZTY3YzJmNWZjNDMwMzliM2EwDQYJKoZIhvcNAQELBQADggEBAFoG
+crJCk/86l1GFJvX/KDQsLz9oo5E5ZApxIy2i5ybwJTF0xNFMOziFEmgmrOjzc0V
hqzOhnKzT0y11yXGD3fqXCl6dFwReUo2Lkfb69rPpyI6geLwxuqKjFzczBRZEjLi
7N2Kr3IPj2po9pLsgTrCiKPyUw+nlaklVkOZesb14Hlzy9vLlEYW8FuzfEnJAO1I
D4FZRA+2aMm1h1AilPUi8UTj08DrCyKwab6egUXy2B8xuxaeXe/Bt6ZtyzTcoITO
ASVSz955tQfAZ+sWztpsIofoUwnYkxAwOowsoF1YF6p4LN088EoZec8DFC/dHtRg
O0/0zVK1pyKucJUT4dc=
-----END CERTIFICATE-----

Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 248175280964363280247688692799333391703 (0xbab4d20cb86dc4560aa8180eab1edd57)
        Signature Algorithm: SHA256-RSA
        Issuer: C=US,O=Google,OU=Enterprise,CN=Single Root CA
        Validity
            Not Before: Sep 1 05:20:16 2026 UTC
            Not After : Sep 2 05:20:16 2026 UTC
        Subject: C=US,ST=California,L=Mountain View,O=Acme Co,OU=Enterprise,CN=attestor.domain.com,SERIALNUMBER=114576256593691508097351712753158036559
        Subject Public Key Info:
            Public Key Algorithm: RSA
                Public-Key: (2048 bit)
                Modulus:
                    c4:c4:05:ca:a0:44:67:37:fe:1e:7a:1f:a1:f3:50:
                    ee:64:c2:c7:89:3e:56:e0:50:ba:90:34:88:a4:4c:
                    e5:25:91:cf:45:dc:89:76:39:59:6e:09:4d:0c:85:
                    6f:a5:77:bc:bd:ae:a7:05:d5:47:15:b8:45:2c:c3:
                    ac:90:d9:fc:98:a6:f9:54:2a:41:09:7a:ef:de:bb:
                    c1:83:7d:b7:b3:54:36:a5:45:2c:21:92:b9:b6:10:
                    2e:f4:a1:6b:2f:f2:cf:dd:e9:31:b1:e2:c4:9c:3a:
                    e1:50:fa:d6:08:25:08:1a:11:03:03:20:5e:d2:11:
                    00:e2:bb:5d:12:67:ef:dc:e8:16:34:b1:64:87:fc:
                    fe:d4:d6:ed:26:0d:5a:0b:7f:cf:ea:85:f6:1c:2d:
                    fe:01:3c:89:3e:44:3c:72:db:c1:4d:22:5b:4a:fb:
                    9e:e2:a9:00:1b:3d:4d:f5:10:0f:86:89:76:dc:92:
                    3c:9e:d8:df:1d:64:ef:90:db:f3:3b:3c:28:56:60:
                    1c:d9:78:b5:e7:da:ac:83:bc:bf:0e:be:39:1b:aa:
                    04:af:4f:71:40:f8:e8:73:ed:81:db:6e:1c:9c:b0:
                    7c:e2:91:83:93:f1:39:38:58:2c:e4:41:0a:26:e3:
                    df:30:29:cc:45:00:d6:49:40:da:bf:e4:5c:36:60:
                    65
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Basic Constraints: critical
                CA:FALSE
            X509v3 Authority Key Identifier:
                EC:F0:EA:53:53:3F:9F:23:DC:C1:0E:31:10:37:07:DE:DE:E7:6E:F3
            X509v3 Subject Alternative Name:
                OtherName: Type: 1.3.6.1.5.5.7.8.4, Value: 0x301e841c53494d303a2f6d51db7736ecb92dcde2278031c8b1ecc387b43a04d8
                Permanent Identifier: 0233aaacb3f4b54e0db562d76a62fc1f85ce4e117ea71fce67c2f5fc43039b3a
    Signature Algorithm: SHA256-RSA
         5a:06:f9:ca:c9:0a:4f:fc:ea:5d:46:14:9b:d7:fc:a0:d0:b0:
         bc:fd:a2:8e:44:e5:90:29:c4:8c:b6:8b:9c:9b:c0:94:c5:d3:
         13:45:30:ec:e2:14:49:a0:9a:b3:a3:cd:cd:15:86:ac:ce:86:
         72:b3:4f:4c:b5:d7:25:c6:0f:77:ea:5c:29:7a:74:5c:11:79:
         4a:36:2e:47:db:eb:da:cf:a7:22:3a:81:e2:f0:c6:ea:8a:8c:
         5c:dc:cc:14:59:12:32:e2:ec:dd:8a:af:72:0f:8f:6a:68:f6:
         92:ec:81:3a:c2:88:a3:f2:53:0f:a7:95:a9:25:56:43:99:7a:
         c6:f5:e0:79:73:cb:db:cb:94:46:16:f0:5b:b3:7c:49:c9:00:
         ed:48:0f:81:59:44:0f:b6:68:c9:b5:87:50:22:94:f5:22:f1:
         44:e3:d3:c0:eb:0b:22:b0:69:be:9e:81:45:f2:d8:1f:31:bb:
         16:9e:5d:ef:c1:b7:a6:6d:cb:34:dc:a0:84:ce:01:25:52:cf:
         de:79:b5:07:c0:67:eb:16:ce:da:6c:22:87:e8:53:09:d8:93:
         10:30:3a:8c:2c:a0:5d:58:17:aa:78:2c:dd:3c:f0:4a:19:79:
         cf:03:14:2f:dd:1e:d4:60:3b:4f:f4:cd:52:b5:a7:22:ae:70:
         95:13:e1:d7

I0901 01:20:16.570824 3921794 grpc_verifier.go:1002] =============== end SetQuote ===============
I0901 01:20:16.579750 3921794 grpc_verifier.go:1009] ======= SetAttestedKey ========
I0901 01:20:16.579799 3921794 grpc_verifier.go:1030]         New PublicKey ========
I0901 01:20:16.580229 3921794 grpc_verifier.go:1055]         Key CertificationParameters.QualifyingData [somecustomdata]
I0901 01:20:16.580266 3921794 grpc_verifier.go:1063]      Key AuthPolicy []
I0901 01:20:16.580285 3921794 grpc_verifier.go:1073]      Key TPM Properties mask: 262258
I0901 01:20:16.580309 3921794 grpc_verifier.go:1076]      Key Expected Properties mask 262258
I0901 01:20:16.580375 3921794 grpc_verifier.go:1109]      key verified 
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEYkRx167DTysRKFXllHArbzha+xdY
AO92OhJ/y8MBa5zgklXcPgWXocsg8dzKszmDrGZOBdACyVdoM5qcyNtbHQ==
-----END PUBLIC KEY-----

I0901 01:20:16.580404 3921794 grpc_verifier.go:1111] =============== end SetAttestedKey ===============
I0901 01:20:16.583257 3921794 grpc_verifier.go:1116] ======= GetCertificate ========
I0901 01:20:16.583377 3921794 grpc_verifier.go:1149] Creating public x509
I0901 01:20:16.587434 3921794 grpc_verifier.go:1275] Issued Certificate SerialNumber: 130548425181959730075247988219205626921
I0901 01:20:16.587737 3921794 grpc_verifier.go:1288] Issued Certificate: 
-----BEGIN CERTIFICATE-----
MIIDlTCCAn2gAwIBAgIQYja2TdPWjYwh6Q+B98esKTANBgkqhkiG9w0BAQsFADBM
MQswCQYDVQQGEwJVUzEPMA0GA1UECgwGR29vZ2xlMRMwEQYDVQQLDApFbnRlcnBy
aXNlMRcwFQYDVQQDDA5TaW5nbGUgUm9vdCBDQTAeFw0yNjA5MDEwNTIwMTZaFw0y
NjA5MDIwNTIwMTZaMIGjMQswCQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5p
YTEWMBQGA1UEBxMNTW91bnRhaW4gVmlldzEQMA4GA1UEChMHQWNtZSBDbzETMBEG
A1UECxMKRW50ZXJwcmlzZTEOMAwGA1UEAxMFbXl0cG0xMDAuBgNVBAUTJzExNDU3
NjI1NjU5MzY5MTUwODA5NzM1MTcxMjc1MzE1ODAzNjU1OTBZMBMGByqGSM49AgEG
CCqGSM49AwEHA0IABGJEcdeuw08rEShV5ZRwK284WvsXWADvdjoSf8vDAWuc4JJV
3D4Fl6HLIPHcyrM5g6xmTgXQAslXaDOanMjbWx2jgeUwgeIwDgYDVR0PAQH/BAQD
AgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMCMAwGA1UdEwEB/wQCMAAwHwYDVR0jBBgw
FoAU7PDqU1M/nyPcwQ4xEDcH3t7nbvMwgYsGA1UdEQSBgzCBgKAsBggrBgEFBQcI
BKAgMB6EHFNJTTA6L21R23c27LktzeIngDHIsezDh7Q6BNigUAYIKwYBBQUHCAOg
RDBCDEAwMjMzYWFhY2IzZjRiNTRlMGRiNTYyZDc2YTYyZmMxZjg1Y2U0ZTExN2Vh
NzFmY2U2N2MyZjVmYzQzMDM5YjNhMA0GCSqGSIb3DQEBCwUAA4IBAQAGyHcc01kE
3GEIzkzCS8ifpdDGQW14MXY+D6B14ibofxEFMtx7dw4BrymxYgz5KvlnJvcjm+uD
Vimz881zD6P+qYYlEN8YH8MVFPkM3Gj8mFV7Alkl/iq3RrJ019Bb9a8VtW/mQXQ1
FKWqMonKTXmkxf/IAQeU1+x5cis8F3HEARm+88bgSj1Xj6wjigsWC3wlF7hvOmuv
6O9JbHq06koosB7m9xsS1PD/wf4XHFyvq1oQKn/xMQr55XegppZMJmWIlOzbYcVQ
t3m/kWKvSlDM3EXnjGzrubt0DxTH3V7Srx5jU0xinKTdY7A8ZsUWtqvFKJObCK2h
eO4QW6QFqDZA
-----END CERTIFICATE-----

Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 130548425181959730075247988219205626921 (0x6236b64dd3d68d8c21e90f81f7c7ac29)
        Signature Algorithm: SHA256-RSA
        Issuer: C=US,O=Google,OU=Enterprise,CN=Single Root CA
        Validity
            Not Before: Sep 1 05:20:16 2026 UTC
            Not After : Sep 2 05:20:16 2026 UTC
        Subject: C=US,ST=California,L=Mountain View,O=Acme Co,OU=Enterprise,CN=mytpm,SERIALNUMBER=114576256593691508097351712753158036559
        Subject Public Key Info:
            Public Key Algorithm: ECDSA
                Public-Key: (256 bit)
                X:
                    62:44:71:d7:ae:c3:4f:2b:11:28:55:e5:94:70:2b:
                    6f:38:5a:fb:17:58:00:ef:76:3a:12:7f:cb:c3:01:
                    6b:9c
                Y:
                    e0:92:55:dc:3e:05:97:a1:cb:20:f1:dc:ca:b3:39:
                    83:ac:66:4e:05:d0:02:c9:57:68:33:9a:9c:c8:db:
                    5b:1d
                Curve: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Extended Key Usage:
                Client Authentication
            X509v3 Basic Constraints: critical
                CA:FALSE
            X509v3 Authority Key Identifier:
                EC:F0:EA:53:53:3F:9F:23:DC:C1:0E:31:10:37:07:DE:DE:E7:6E:F3
            X509v3 Subject Alternative Name:
                OtherName: Type: 1.3.6.1.5.5.7.8.4, Value: 0x301e841c53494d303a2f6d51db7736ecb92dcde2278031c8b1ecc387b43a04d8
                Permanent Identifier: 0233aaacb3f4b54e0db562d76a62fc1f85ce4e117ea71fce67c2f5fc43039b3a
    Signature Algorithm: SHA256-RSA
         06:c8:77:1c:d3:59:04:dc:61:08:ce:4c:c2:4b:c8:9f:a5:d0:
         c6:41:6d:78:31:76:3e:0f:a0:75:e2:26:e8:7f:11:05:32:dc:
         7b:77:0e:01:af:29:b1:62:0c:f9:2a:f9:67:26:f7:23:9b:eb:
         83:56:29:b3:f3:cd:73:0f:a3:fe:a9:86:25:10:df:18:1f:c3:
         15:14:f9:0c:dc:68:fc:98:55:7b:02:59:25:fe:2a:b7:46:b2:
         74:d7:d0:5b:f5:af:15:b5:6f:e6:41:74:35:14:a5:aa:32:89:
         ca:4d:79:a4:c5:ff:c8:01:07:94:d7:ec:79:72:2b:3c:17:71:
         c4:01:19:be:f3:c6:e0:4a:3d:57:8f:ac:23:8a:0b:16:0b:7c:
         25:17:b8:6f:3a:6b:af:e8:ef:49:6c:7a:b4:ea:4a:28:b0:1e:
         e6:f7:1b:12:d4:f0:ff:c1:fe:17:1c:5c:af:ab:5a:10:2a:7f:
         f1:31:0a:f9:e5:77:a0:a6:96:4c:26:65:88:94:ec:db:61:c5:
         50:b7:79:bf:91:62:af:4a:50:cc:dc:45:e7:8c:6c:eb:b9:bb:
         74:0f:14:c7:dd:5e:d2:af:1e:63:53:4c:62:9c:a4:dd:63:b0:
         3c:66:c5:16:b6:ab:c5:28:93:9b:08:ad:a1:78:ee:10:5b:a4:
         05:a8:36:40

I0901 01:20:16.587800 3921794 grpc_verifier.go:1293] =============== end GetCertificate ===============
I0901 01:20:16.598104 3921794 grpc_verifier.go:1384] =============== Got MTLS HTTPS request: mtls client Subject Common Name: mytpm, SerialNumber 130548425181959730075247988219205626921
```


##### Attestor

Now run the attestor and specify the verifier

```bash
go run src/client/grpc_attestor.go -host 127.0.0.1:50051 \
   --tpm-path="127.0.0.1:2321"   --eventLogPath=swtpm/binary_bios_measurements  \
    --v=10 -alsologtostderr

I0901 01:20:16.424657 3921885 grpc_attestor.go:116] =============== HealthCheck ===============
I0901 01:20:16.435417 3921885 grpc_attestor.go:132] RPC HealthChekStatus: SERVING
I0901 01:20:16.435491 3921885 grpc_attestor.go:149] EKM: c90bb807e42dea894b9ba862b519c72bb4592a0d39a48da55b299f27a779211c
I0901 01:20:16.435572 3921885 grpc_attestor.go:160] Opening swtpm socket
I0901 01:20:16.436724 3921885 grpc_attestor.go:202] Manufacturer: IBM
I0901 01:20:16.436786 3921885 grpc_attestor.go:203] VendorInfo: SW   TPM
I0901 01:20:16.436811 3921885 grpc_attestor.go:204] FirmwareVersionMajor: 8228
I0901 01:20:16.436834 3921885 grpc_attestor.go:205] FirmwareVersionMinor: 293
I0901 01:20:16.437715 3921885 grpc_attestor.go:215] EKCert Issuer: CN=swtpm-localca
I0901 01:20:16.437794 3921885 grpc_attestor.go:241] EKCert SerialNumber: 1240
I0901 01:20:16.437831 3921885 grpc_attestor.go:244] =============== OfferPlatformCert ===============
I0901 01:20:16.445290 3921885 grpc_attestor.go:327] Verified Platform Cert
I0901 01:20:16.445344 3921885 grpc_attestor.go:329] =============== OfferEK ===============
I0901 01:20:16.447153 3921885 grpc_attestor.go:338] Verified EK Cert
I0901 01:20:16.447208 3921885 grpc_attestor.go:340] =============== OfferAK ===============
I0901 01:20:16.533223 3921885 grpc_attestor.go:371] Creating AK CSR
I0901 01:20:16.539640 3921885 grpc_attestor.go:406] AK CSR 
-----BEGIN CERTIFICATE REQUEST-----
MIIC9TCCAd0CAQAwfzELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWEx
FjAUBgNVBAcTDU1vdW50YWluIFZpZXcxEDAOBgNVBAoTB0FjbWUgQ28xEzARBgNV
BAsTCkVudGVycHJpc2UxHDAaBgNVBAMTE2F0dGVzdG9yLmRvbWFpbi5jb20wggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDExAXKoERnN/4eeh+h81DuZMLH
iT5W4FC6kDSIpEzlJZHPRdyJdjlZbglNDIVvpXe8va6nBdVHFbhFLMOskNn8mKb5
VCpBCXrv3rvBg323s1Q2pUUsIZK5thAu9KFrL/LP3ekxseLEnDrhUPrWCCUIGhED
AyBe0hEA4rtdEmfv3OgWNLFkh/z+1NbtJg1aC3/P6oX2HC3+ATyJPkQ8ctvBTSJb
Svue4qkAGz1N9RAPhol23JI8ntjfHWTvkNvzOzwoVmAc2Xi159qsg7y/Dr45G6oE
r09xQPjoc+2B224cnLB84pGDk/E5OFgs5EEKJuPfMCnMRQDWSUDav+RcNmBlAgMB
AAGgMTAvBgkqhkiG9w0BCQ4xIjAgMB4GA1UdEQQXMBWCE2F0dGVzdG9yLmRvbWFp
bi5jb20wDQYJKoZIhvcNAQELBQADggEBAGvOyN4M4azNzZqoNDQkwOVn+4TXf978
sD+WuVcRS2Za6kV4qvrCg0wVaKDyE/TC7ULKZXqEcBkcMk/SptPpWNj7EGF+qUNf
SZGbBoEmS6PsbbhwLuogyzcoNdfsO3O1TsGsFzzz5Z/T3xpmKDqbtVowzEvGkMMP
J8K/CeblqjdXzu8ASgLbx2Tco6RjXYxaOszvi3+BAmB4flGs4CwSDACfhoRB0eZ8
k0GsKR3l2u2+fUh91ZcAA0AEtTrhRF9zvuP8P9fM5eMe64rVCCDphLgWKJBk02T3
+O+Bwr1bBYCkXQBFZK/HP7vDNGP+JU4v9fdho+ggxnt4Bu9TMfsZKlg=
-----END CERTIFICATE REQUEST-----

I0901 01:20:16.541510 3921885 grpc_attestor.go:417] Verified AK 
I0901 01:20:16.541692 3921885 grpc_attestor.go:419] =============== GetMakeCredential ===============
I0901 01:20:16.550232 3921885 grpc_attestor.go:448] EncryptedCredentials Secret 6VhrZH0/pZ/qlVUyV+J7NWLZmOSPxPeqcAAzGP5BiCU=
I0901 01:20:16.550302 3921885 grpc_attestor.go:450] =============== SetActivateCredential ===============
I0901 01:20:16.551302 3921885 grpc_attestor.go:459] SetActivateCredential complete 
I0901 01:20:16.551371 3921885 grpc_attestor.go:461] =============== OfferQuote ===============
I0901 01:20:16.552604 3921885 grpc_attestor.go:468] OfferQuote complete 
I0901 01:20:16.552728 3921885 grpc_attestor.go:470] =============== SetQuote ===============
I0901 01:20:16.571454 3921885 grpc_attestor.go:503] Issued AK Certificate: 
-----BEGIN CERTIFICATE-----
MIIEWjCCA0KgAwIBAgIRALq00gy4bcRWCqgYDqse3VcwDQYJKoZIhvcNAQELBQAw
TDELMAkGA1UEBhMCVVMxDzANBgNVBAoMBkdvb2dsZTETMBEGA1UECwwKRW50ZXJw
cmlzZTEXMBUGA1UEAwwOU2luZ2xlIFJvb3QgQ0EwHhcNMjYwOTAxMDUyMDE2WhcN
MjYwOTAyMDUyMDE2WjCBsTELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3Ju
aWExFjAUBgNVBAcTDU1vdW50YWluIFZpZXcxEDAOBgNVBAoTB0FjbWUgQ28xEzAR
BgNVBAsTCkVudGVycHJpc2UxHDAaBgNVBAMTE2F0dGVzdG9yLmRvbWFpbi5jb20x
MDAuBgNVBAUTJzExNDU3NjI1NjU5MzY5MTUwODA5NzM1MTcxMjc1MzE1ODAzNjU1
OTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMTEBcqgRGc3/h56H6Hz
UO5kwseJPlbgULqQNIikTOUlkc9F3Il2OVluCU0MhW+ld7y9rqcF1UcVuEUsw6yQ
2fyYpvlUKkEJeu/eu8GDfbezVDalRSwhkrm2EC70oWsv8s/d6TGx4sScOuFQ+tYI
JQgaEQMDIF7SEQDiu10SZ+/c6BY0sWSH/P7U1u0mDVoLf8/qhfYcLf4BPIk+RDxy
28FNIltK+57iqQAbPU31EA+GiXbckjye2N8dZO+Q2/M7PChWYBzZeLXn2qyDvL8O
vjkbqgSvT3FA+Ohz7YHbbhycsHzikYOT8Tk4WCzkQQom498wKcxFANZJQNq/5Fw2
YGUCAwEAAaOB0DCBzTAOBgNVHQ8BAf8EBAMCB4AwDAYDVR0TAQH/BAIwADAfBgNV
HSMEGDAWgBTs8OpTUz+fI9zBDjEQNwfe3udu8zCBiwYDVR0RBIGDMIGAoCwGCCsG
AQUFBwgEoCAwHoQcU0lNMDovbVHbdzbsuS3N4ieAMcix7MOHtDoE2KBQBggrBgEF
BQcIA6BEMEIMQDAyMzNhYWFjYjNmNGI1NGUwZGI1NjJkNzZhNjJmYzFmODVjZTRl
MTE3ZWE3MWZjZTY3YzJmNWZjNDMwMzliM2EwDQYJKoZIhvcNAQELBQADggEBAFoG
+crJCk/86l1GFJvX/KDQsLz9oo5E5ZApxIy2i5ybwJTF0xNFMOziFEmgmrOjzc0V
hqzOhnKzT0y11yXGD3fqXCl6dFwReUo2Lkfb69rPpyI6geLwxuqKjFzczBRZEjLi
7N2Kr3IPj2po9pLsgTrCiKPyUw+nlaklVkOZesb14Hlzy9vLlEYW8FuzfEnJAO1I
D4FZRA+2aMm1h1AilPUi8UTj08DrCyKwab6egUXy2B8xuxaeXe/Bt6ZtyzTcoITO
ASVSz955tQfAZ+sWztpsIofoUwnYkxAwOowsoF1YF6p4LN088EoZec8DFC/dHtRg
O0/0zVK1pyKucJUT4dc=
-----END CERTIFICATE-----

I0901 01:20:16.571581 3921885 grpc_attestor.go:504] SetQuote complete 
I0901 01:20:16.571631 3921885 grpc_attestor.go:506] =============== SetAttestedKey ===============
I0901 01:20:16.578746 3921885 grpc_attestor.go:558] Generated ECC Public 
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEYkRx167DTysRKFXllHArbzha+xdY
AO92OhJ/y8MBa5zgklXcPgWXocsg8dzKszmDrGZOBdACyVdoM5qcyNtbHQ==
-----END PUBLIC KEY-----
I0901 01:20:16.580915 3921885 grpc_attestor.go:575] SetAttestedKey complete 
I0901 01:20:16.581015 3921885 grpc_attestor.go:577] =============== GetCertificate ===============
I0901 01:20:16.581112 3921885 grpc_attestor.go:579] Creating CSR
I0901 01:20:16.582620 3921885 grpc_attestor.go:612] CSR 
-----BEGIN CERTIFICATE REQUEST-----
MIIBTzCB9gIBADBxMQswCQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTEW
MBQGA1UEBxMNTW91bnRhaW4gVmlldzEQMA4GA1UEChMHQWNtZSBDbzETMBEGA1UE
CxMKRW50ZXJwcmlzZTEOMAwGA1UEAxMFbXl0cG0wWTATBgcqhkjOPQIBBggqhkjO
PQMBBwNCAARiRHHXrsNPKxEoVeWUcCtvOFr7F1gA73Y6En/LwwFrnOCSVdw+BZeh
yyDx3MqzOYOsZk4F0ALJV2gzmpzI21sdoCMwIQYJKoZIhvcNAQkOMRQwEjAQBgNV
HREECTAHggVteXRwbTAKBggqhkjOPQQDAgNIADBFAiBQeGyjLhoGv88YAkMQy7WV
l/+3Uh3p5G+1ycYyiPYNOQIhAIjQlbzPlPwJwuAmtLG5kOcjS81xRnYrSevtG+UD
aAci
-----END CERTIFICATE REQUEST-----

I0901 01:20:16.588361 3921885 grpc_attestor.go:624] Issued Certificate: 
-----BEGIN CERTIFICATE-----
MIIDlTCCAn2gAwIBAgIQYja2TdPWjYwh6Q+B98esKTANBgkqhkiG9w0BAQsFADBM
MQswCQYDVQQGEwJVUzEPMA0GA1UECgwGR29vZ2xlMRMwEQYDVQQLDApFbnRlcnBy
aXNlMRcwFQYDVQQDDA5TaW5nbGUgUm9vdCBDQTAeFw0yNjA5MDEwNTIwMTZaFw0y
NjA5MDIwNTIwMTZaMIGjMQswCQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5p
YTEWMBQGA1UEBxMNTW91bnRhaW4gVmlldzEQMA4GA1UEChMHQWNtZSBDbzETMBEG
A1UECxMKRW50ZXJwcmlzZTEOMAwGA1UEAxMFbXl0cG0xMDAuBgNVBAUTJzExNDU3
NjI1NjU5MzY5MTUwODA5NzM1MTcxMjc1MzE1ODAzNjU1OTBZMBMGByqGSM49AgEG
CCqGSM49AwEHA0IABGJEcdeuw08rEShV5ZRwK284WvsXWADvdjoSf8vDAWuc4JJV
3D4Fl6HLIPHcyrM5g6xmTgXQAslXaDOanMjbWx2jgeUwgeIwDgYDVR0PAQH/BAQD
AgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMCMAwGA1UdEwEB/wQCMAAwHwYDVR0jBBgw
FoAU7PDqU1M/nyPcwQ4xEDcH3t7nbvMwgYsGA1UdEQSBgzCBgKAsBggrBgEFBQcI
BKAgMB6EHFNJTTA6L21R23c27LktzeIngDHIsezDh7Q6BNigUAYIKwYBBQUHCAOg
RDBCDEAwMjMzYWFhY2IzZjRiNTRlMGRiNTYyZDc2YTYyZmMxZjg1Y2U0ZTExN2Vh
NzFmY2U2N2MyZjVmYzQzMDM5YjNhMA0GCSqGSIb3DQEBCwUAA4IBAQAGyHcc01kE
3GEIzkzCS8ifpdDGQW14MXY+D6B14ibofxEFMtx7dw4BrymxYgz5KvlnJvcjm+uD
Vimz881zD6P+qYYlEN8YH8MVFPkM3Gj8mFV7Alkl/iq3RrJ019Bb9a8VtW/mQXQ1
FKWqMonKTXmkxf/IAQeU1+x5cis8F3HEARm+88bgSj1Xj6wjigsWC3wlF7hvOmuv
6O9JbHq06koosB7m9xsS1PD/wf4XHFyvq1oQKn/xMQr55XegppZMJmWIlOzbYcVQ
t3m/kWKvSlDM3EXnjGzrubt0DxTH3V7Srx5jU0xinKTdY7A8ZsUWtqvFKJObCK2h
eO4QW6QFqDZA
-----END CERTIFICATE-----

I0901 01:20:16.588494 3921885 grpc_attestor.go:626] GetCertificate complete 
I0901 01:20:16.588562 3921885 grpc_attestor.go:628] Making mTLS HTTPS call 
I0901 01:20:16.598443 3921885 grpc_attestor.go:669] Server Response: Client certificate found! Subject Common Name: mytpm, SerialNumber 130548425181959730075247988219205626921
```

Note, to get a GCE instance's swtpm,

```bash
gcloud compute instances create remote --zone=us-central1-a     --machine-type=n2d-standard-2  --min-cpu-platform="AMD Milan"        --shielded-secure-boot --no-service-account --no-scopes         --shielded-vtpm --confidential-compute-type=SEV     --shielded-integrity-monitoring

gcloud compute ssh remote
sudo cp /sys/kernel/security/tpm0/binary_bios_measurements /tmp/
sudo chmod  o+r /tmp/binary_bios_measurements

gcloud compute scp remote:/tmp/binary_bios_measurements .
```

#### Setup Local TPM

If you want to test locally with a real TPM, you need to acquire your TPM's issuer and intermediate root certificates.

If you don't have access to a TPM, this repo also shows how to use two Google Cloud VMs with vTPMs to demo with.  Its somewhat easier to demo with the VMs

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

### Verifier

First run the  Verifier

```bash
go run src/server/grpc_verifier.go  \
       --ekintermediateCA=certs/stmtpmekint10.pem --ekrootCA=certs/stmtpmekroot.pem \
       --expectedPCRMapSHA256=0:7bb4353897632fd086982175a027dafcc33f61adbab4ebfc6d13927b97a8c084  \
       --v=40 -alsologtostderr
```

### Attestor

Now run the Attestor:

```bash
export VERIFIER_ADDRESS=127.0.0.1

sudo go run src/client/grpc_attestor.go -host $VERIFIER_ADDRESS:50051 \
  --tpm-path="/dev/tpmrm0"  --v=10 -alsologtostderr

```