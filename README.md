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
$ go run src/server/grpc_verifier.go  \
       --ekrootCA swtpm/config/var/lib/swtpm-localca/issuercert.pem \
       --expectedPCRMapSHA256=0:a0b5ff3383a1116bd7dc6df177c0c2d433b9ee1813ea958fa5d166a202cb2a85 \
        --v=40 -alsologtostderr

I0412 14:06:19.736735 2091732 grpc_verifier.go:1159] Starting gRPC server on port :50051
usign signer
I0412 14:06:34.428365 2091732 grpc_verifier.go:155]      EKM: 6bd1b46be2e6835b90d4e31c0968063c9e579f2adc4a6226b848556bde9f3149
I0412 14:06:34.436372 2091732 grpc_verifier.go:155]      EKM: 6bd1b46be2e6835b90d4e31c0968063c9e579f2adc4a6226b848556bde9f3149
I0412 14:06:34.436410 2091732 grpc_verifier.go:203] ======= OfferPlatformCert ========
I0412 14:06:34.436782 2091732 grpc_verifier.go:247]      PlatformCertificate Issuer: CN=Platform Root CA,OU=Enterprise,O=Google,C=US
I0412 14:06:34.436838 2091732 grpc_verifier.go:248]      PlatformCertificate Version: 2
I0412 14:06:34.436856 2091732 grpc_verifier.go:250]      PlatformCertificate CredentialSpecification: 
I0412 14:06:34.436872 2091732 grpc_verifier.go:251]      PlatformCertificate PlatformManufacturer: 
I0412 14:06:34.436888 2091732 grpc_verifier.go:252]      PlatformCertificate PlatformModel: 
I0412 14:06:34.436904 2091732 grpc_verifier.go:253]      PlatformCertificate PlatformVersion: 
I0412 14:06:34.436921 2091732 grpc_verifier.go:254]      PlatformCertificate PropertiesURI: 
I0412 14:06:34.436940 2091732 grpc_verifier.go:269]      PlatformCertificate Holder.Issuer: CN=swtpm-localca
I0412 14:06:34.436966 2091732 grpc_verifier.go:270]      PlatformCertificate Holder.Serial: 1216
I0412 14:06:34.437002 2091732 grpc_verifier.go:271]      PlatformCertificate Holder.Issuer.CommonName: swtpm-localca
I0412 14:06:34.437028 2091732 grpc_verifier.go:276]      PlatformCertificate TBBSecurityAssertions.Iso9000URI: 
I0412 14:06:34.437053 2091732 grpc_verifier.go:277]      PlatformCertificate TBBSecurityAssertions.CcInfo.ProfileOid: 
I0412 14:06:34.437083 2091732 grpc_verifier.go:278]      PlatformCertificate TBBSecurityAssertions.CcInfo.ProfileURI: 
I0412 14:06:34.437109 2091732 grpc_verifier.go:279]      PlatformCertificate TBBSecurityAssertions.CcInfo.TargetOid: 
I0412 14:06:34.437137 2091732 grpc_verifier.go:280]      PlatformCertificate TBBSecurityAssertions.CcInfo.TargetURI: 
I0412 14:06:34.437165 2091732 grpc_verifier.go:281]      PlatformCertificate TBBSecurityAssertions.CcInfo.Version: 
I0412 14:06:34.437194 2091732 grpc_verifier.go:283]      PlatformCertificate TCGPlatformSpecification.Version: {0 0 0}
I0412 14:06:34.437228 2091732 grpc_verifier.go:284]      PlatformCertificate TCGPlatformSpecification.Version.MajorVersion: 0
I0412 14:06:34.437258 2091732 grpc_verifier.go:285]      PlatformCertificate TCGPlatformSpecification.Version.MinorVersion: 0
I0412 14:06:34.437288 2091732 grpc_verifier.go:286]      PlatformCertificate TCGPlatformSpecification.Version.Revision: 0
I0412 14:06:34.437318 2091732 grpc_verifier.go:288]      PlatformCertificate UserNotice.UserNotice.ExplicitText: 
I0412 14:06:34.437349 2091732 grpc_verifier.go:289]      PlatformCertificate UserNotice.UserNotice.Organization: 
I0412 14:06:34.437380 2091732 grpc_verifier.go:290]      PlatformCertificate UserNotice.UserNotice.NoticeNumbers: []
I0412 14:06:34.437598 2091732 grpc_verifier.go:297]      Verified Platform cert signed by privacyCA
I0412 14:06:34.438327 2091732 grpc_verifier.go:155]      EKM: 6bd1b46be2e6835b90d4e31c0968063c9e579f2adc4a6226b848556bde9f3149
I0412 14:06:34.438365 2091732 grpc_verifier.go:318] ======= OfferEK ========
I0412 14:06:34.438484 2091732 grpc_verifier.go:365]      TPM Manufacturer id:00001014
I0412 14:06:34.438528 2091732 grpc_verifier.go:368]      TPM Model swtpm
I0412 14:06:34.438565 2091732 grpc_verifier.go:372]      TPM Version id:20240125
I0412 14:06:34.438624 2091732 grpc_verifier.go:404]      TPM Family 2.0
I0412 14:06:34.438656 2091732 grpc_verifier.go:405]      TPM Level 0
I0412 14:06:34.438688 2091732 grpc_verifier.go:406]      TPM Revision 183
I0412 14:06:34.438732 2091732 grpc_verifier.go:421]         EKCertificate ========
-----BEGIN CERTIFICATE-----
MIID9TCCAl2gAwIBAgICBMAwDQYJKoZIhvcNAQELBQAwGDEWMBQGA1UEAxMNc3d0
cG0tbG9jYWxjYTAgFw0yNjA0MTIxODA1NTJaGA85OTk5MTIzMTIzNTk1OVowEjEQ
MA4GA1UEAxMHdW5rbm93bjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
ALJgqd44EA21foZTfTO8RNNLnfBHrAMqN7IZBPF9pjDGxxq6iYHoD3Rmem6fKTrU
c4VOIs975ygOM7rgnY7Lqx/n9AOqdH7NZ5Bw+LYLhM6stWWK8BTox2hYBRnqHp1f
xwNMwe6DWYlwFT3UYvGJ5+vpCcWqNpJAugkK1dy0UjA8uGLW1BZKKQA/Lasr7Ejw
leEfJU5RJ2GmfjHPvD1tt+oDE08qkJstRVcRa/QVEZ7pZnORsHpztBz7yEWvkDdt
zbeEMz1yjyMVSXLvWtWh+AVnkOOWLYy5hUZAgwCSbtZdt01V7OpRS501KRt3Jov6
s0YnsUiPUQr4NnM+pHfBUT0CAwEAAaOBzDCByTAQBgNVHSUECTAHBgVngQUIATBS
BgNVHREBAf8ESDBGpEQwQjEWMBQGBWeBBQIBDAtpZDowMDAwMTAxNDEQMA4GBWeB
BQICDAVzd3RwbTEWMBQGBWeBBQIDDAtpZDoyMDI0MDEyNTAMBgNVHRMBAf8EAjAA
MCIGA1UdCQQbMBkwFwYFZ4EFAhAxDjAMDAMyLjACAQACAgC3MB8GA1UdIwQYMBaA
FC9tUdt3Nuy5Lc3iJ4AxyLHsw4e0MA4GA1UdDwEB/wQEAwIFIDANBgkqhkiG9w0B
AQsFAAOCAYEAJGs4eBEe9JJ58z2EYu1Yy7B5m6p+Qp3l2xFYC5sRoCDLDLnLsaIx
Q8P9seug8ITuInAYIB4MmrN6TnFBL1cbiT+AZqdZzuUIIeukvJCbvaJVpbuoi5uq
zxjdYGa0lgLhFdt7ccpCFU8/WfteVeteK4VR4HbPyLjUEIch+QH75M2OJZcRDvwh
Who/wqmKzTcA+0B9b9nCxuByKwURsYVQr2Qrr1Q/0YvMVzGxd/vo2Q2fyKHvQb2j
aU9aKJIBn9sucu5IvHXMhBjlrbqDkh68DkU9xAHwk2Wp8GkzsxBlB3RBawFxcxu+
niKEgtJS2r3VEOBQVzDN249f9zgA419ZDIcJS7PZdtOLDr/JzLASLm0nMfOm2l0v
ToAOyygw1MdccZr2a4+qC1E74hzTSlyJgrKCQtGaVylG+gMVI4EHeWezOa+R64dk
DKKAXOgevHDayCt5T9QU4L/PllMDqZrNeaC5ljbHH8oE+TVG0LK/VqdKrPPPfRIz
OaiFk/A4wcUJ
-----END CERTIFICATE-----

I0412 14:06:34.438818 2091732 grpc_verifier.go:437]      EKCert  Issuer CN=swtpm-localca
I0412 14:06:34.438850 2091732 grpc_verifier.go:438]      EKCert  IssuingCertificateURL []
I0412 14:06:34.438873 2091732 grpc_verifier.go:439]      EKCert  SerialNumber 1216
I0412 14:06:34.438891 2091732 grpc_verifier.go:441]     EkCert Public Key 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsmCp3jgQDbV+hlN9M7xE
00ud8EesAyo3shkE8X2mMMbHGrqJgegPdGZ6bp8pOtRzhU4iz3vnKA4zuuCdjsur
H+f0A6p0fs1nkHD4tguEzqy1ZYrwFOjHaFgFGeoenV/HA0zB7oNZiXAVPdRi8Ynn
6+kJxao2kkC6CQrV3LRSMDy4YtbUFkopAD8tqyvsSPCV4R8lTlEnYaZ+Mc+8PW23
6gMTTyqQmy1FVxFr9BURnulmc5GwenO0HPvIRa+QN23Nt4QzPXKPIxVJcu9a1aH4
BWeQ45YtjLmFRkCDAJJu1l23TVXs6lFLnTUpG3cmi/qzRiexSI9RCvg2cz6kd8FR
PQIDAQAB
-----END PUBLIC KEY-----

I0412 14:06:34.438922 2091732 grpc_verifier.go:444]     Verifying EKCert
I0412 14:06:34.439108 2091732 grpc_verifier.go:472]      EKCert Includes tcg-kp-EKCertificate ExtendedKeyUsage 2.23.133.8.1
I0412 14:06:34.439566 2091732 grpc_verifier.go:501]     EKCert Verified
I0412 14:06:34.439597 2091732 grpc_verifier.go:524] =============== end OfferEK ===============
I0412 14:06:34.698086 2091732 grpc_verifier.go:155]      EKM: 6bd1b46be2e6835b90d4e31c0968063c9e579f2adc4a6226b848556bde9f3149
I0412 14:06:34.698147 2091732 grpc_verifier.go:529] ======= OfferAK ========
I0412 14:06:34.698433 2091732 grpc_verifier.go:573]       ak public 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzOGPXBxPg5uK1bOgvsqj
22l579CooFGBnTH2ghRRhRbKyOzFYk2WTUMItM/uDDdqqb+m592Vw211cJJXh5X+
sJZtRawJIrI+Gj6V8vEqwxZwaUt20hVBBuQ+y5v1bSrwZ4A/oQ3WVTPWEWGDlq0Q
cTamWKvEv/72LSqTQDOp145XL6Za7ZkCgtcHt7009AZzFPZ+sll8LdS/Dad63XXM
fNqajdJ53NcVjkHwFC+yeJi+Zgt1JreZxZULEeIcSAvh4+ImebjBVQVxDn9Q9Wn4
B84ticFy28mxDB3hT4/N3GC47SN254hhatkGrkgIDwPJIu6yKlRLNfFkjq/OlB2f
4QIDAQAB
-----END PUBLIC KEY-----

I0412 14:06:34.698467 2091732 grpc_verifier.go:580] =============== end GetAK ===============
I0412 14:06:34.699316 2091732 grpc_verifier.go:155]      EKM: 6bd1b46be2e6835b90d4e31c0968063c9e579f2adc4a6226b848556bde9f3149
I0412 14:06:34.699357 2091732 grpc_verifier.go:586] ======= GetMakeCredential ========
I0412 14:06:34.699374 2091732 grpc_verifier.go:603] =============== end GetMakeCredential ===============
I0412 14:06:34.700271 2091732 grpc_verifier.go:617]       Outbound Secret: m9V+HoK2304QpzpO3fIjpcMUYL+akKEZivUW0ZEwaNI=
I0412 14:06:34.727447 2091732 grpc_verifier.go:155]      EKM: 6bd1b46be2e6835b90d4e31c0968063c9e579f2adc4a6226b848556bde9f3149
I0412 14:06:34.727490 2091732 grpc_verifier.go:635] ======= SetActivateCredential ========
I0412 14:06:34.727508 2091732 grpc_verifier.go:665] =============== end SetActivateCredential ===============
I0412 14:06:34.728101 2091732 grpc_verifier.go:155]      EKM: 6bd1b46be2e6835b90d4e31c0968063c9e579f2adc4a6226b848556bde9f3149
I0412 14:06:34.728135 2091732 grpc_verifier.go:670] ======= OfferQuote ========
I0412 14:06:34.728159 2091732 grpc_verifier.go:695] =============== end OfferQuote ===============
I0412 14:06:34.738017 2091732 grpc_verifier.go:155]      EKM: 6bd1b46be2e6835b90d4e31c0968063c9e579f2adc4a6226b848556bde9f3149
I0412 14:06:34.738079 2091732 grpc_verifier.go:702] ======= SetQuote ========
I0412 14:06:34.739621 2091732 grpc_verifier.go:755]       quote-attested public 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzOGPXBxPg5uK1bOgvsqj
22l579CooFGBnTH2ghRRhRbKyOzFYk2WTUMItM/uDDdqqb+m592Vw211cJJXh5X+
sJZtRawJIrI+Gj6V8vEqwxZwaUt20hVBBuQ+y5v1bSrwZ4A/oQ3WVTPWEWGDlq0Q
cTamWKvEv/72LSqTQDOp145XL6Za7ZkCgtcHt7009AZzFPZ+sll8LdS/Dad63XXM
fNqajdJ53NcVjkHwFC+yeJi+Zgt1JreZxZULEeIcSAvh4+ImebjBVQVxDn9Q9Wn4
B84ticFy28mxDB3hT4/N3GC47SN254hhatkGrkgIDwPJIu6yKlRLNfFkjq/OlB2f
4QIDAQAB
-----END PUBLIC KEY-----

I0412 14:06:34.741117 2091732 grpc_verifier.go:785]      PCR: 0, verified: true value: a0b5ff3383a1116bd7dc6df177c0c2d433b9ee1813ea958fa5d166a202cb2a85
I0412 14:06:34.741174 2091732 grpc_verifier.go:785]      PCR: 1, verified: true value: e50edb964f66a7417954b1506f78a49d62062228ce84ee0b4e7e3b0e19b64a69
I0412 14:06:34.741188 2091732 grpc_verifier.go:785]      PCR: 2, verified: true value: 3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969
I0412 14:06:34.741197 2091732 grpc_verifier.go:785]      PCR: 3, verified: true value: 3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969
I0412 14:06:34.741205 2091732 grpc_verifier.go:785]      PCR: 4, verified: true value: a3358453a5148b4e3f4b96b006ae1761a2ce4aea75f6a13e10eb3e0903dfd6e2
I0412 14:06:34.741215 2091732 grpc_verifier.go:785]      PCR: 5, verified: true value: 098a2ae2d1aabed3e346b9fef96ec64056ea4043514672243bbf40b7d0972302
I0412 14:06:34.741223 2091732 grpc_verifier.go:785]      PCR: 6, verified: true value: 3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969
I0412 14:06:34.741233 2091732 grpc_verifier.go:785]      PCR: 7, verified: true value: 0a3f60cea411388b09eac782999f5e62246ab5469f9047eb508aa22c4dcd2237
I0412 14:06:34.741244 2091732 grpc_verifier.go:785]      PCR: 8, verified: true value: a775d521739876ecde2c17d0e856c584ec513e8758d9199a3d5c735836ba0ebe
I0412 14:06:34.741254 2091732 grpc_verifier.go:785]      PCR: 9, verified: true value: 4a7254a1740444f04ec61cf3f8eb8ffb5dae2069b44ad900e894b34a07626b36
I0412 14:06:34.741266 2091732 grpc_verifier.go:785]      PCR: 10, verified: true value: 0000000000000000000000000000000000000000000000000000000000000000
I0412 14:06:34.741276 2091732 grpc_verifier.go:785]      PCR: 11, verified: true value: 0000000000000000000000000000000000000000000000000000000000000000
I0412 14:06:34.741286 2091732 grpc_verifier.go:785]      PCR: 12, verified: true value: 0000000000000000000000000000000000000000000000000000000000000000
I0412 14:06:34.741296 2091732 grpc_verifier.go:785]      PCR: 13, verified: true value: 0000000000000000000000000000000000000000000000000000000000000000
I0412 14:06:34.741306 2091732 grpc_verifier.go:785]      PCR: 14, verified: true value: 306f9d8b94f17d93dc6e7cf8f5c79d652eb4c6c4d13de2dddc24af416e13ecaf
I0412 14:06:34.741316 2091732 grpc_verifier.go:785]      PCR: 15, verified: true value: 0000000000000000000000000000000000000000000000000000000000000000
I0412 14:06:34.741326 2091732 grpc_verifier.go:785]      PCR: 16, verified: true value: 0000000000000000000000000000000000000000000000000000000000000000
I0412 14:06:34.741336 2091732 grpc_verifier.go:785]      PCR: 17, verified: true value: ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
I0412 14:06:34.741345 2091732 grpc_verifier.go:785]      PCR: 18, verified: true value: ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
I0412 14:06:34.741355 2091732 grpc_verifier.go:785]      PCR: 19, verified: true value: ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
I0412 14:06:34.741365 2091732 grpc_verifier.go:785]      PCR: 20, verified: true value: ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
I0412 14:06:34.741374 2091732 grpc_verifier.go:785]      PCR: 21, verified: true value: ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
I0412 14:06:34.741383 2091732 grpc_verifier.go:785]      PCR: 22, verified: true value: ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
I0412 14:06:34.741393 2091732 grpc_verifier.go:785]      PCR: 23, verified: true value: 0000000000000000000000000000000000000000000000000000000000000000
I0412 14:06:34.741402 2091732 grpc_verifier.go:797]      quotes verified
I0412 14:06:34.742628 2091732 grpc_verifier.go:825]      secureBoot State enabled: [true]
I0412 14:06:34.742791 2091732 grpc_verifier.go:832] =============== end SetQuote ===============
I0412 14:06:34.752972 2091732 grpc_verifier.go:155]      EKM: 6bd1b46be2e6835b90d4e31c0968063c9e579f2adc4a6226b848556bde9f3149
I0412 14:06:34.753019 2091732 grpc_verifier.go:837] ======= SetAttestedKey ========
I0412 14:06:34.753035 2091732 grpc_verifier.go:858]         New PublicKey ========
I0412 14:06:34.753378 2091732 grpc_verifier.go:883]      Key AuthPolicy []
I0412 14:06:34.753401 2091732 grpc_verifier.go:893]      Key TPM Properties mask: 262258
I0412 14:06:34.753429 2091732 grpc_verifier.go:896]      Key Expected Properties mask 262258
I0412 14:06:34.753492 2091732 grpc_verifier.go:929]      key verified 
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE/nLc7f7E1LLKEuoodB6A2uLMqn6w
pK06dIFtxrBgy9U8FR6Frii/Kxmy+I5DuefeMGxLr4vaE2Fq43N0BS1pKw==
-----END PUBLIC KEY-----

I0412 14:06:34.753519 2091732 grpc_verifier.go:931] =============== end SetAttestedKey ===============
I0412 14:06:34.756531 2091732 grpc_verifier.go:155]      EKM: 6bd1b46be2e6835b90d4e31c0968063c9e579f2adc4a6226b848556bde9f3149
I0412 14:06:34.756561 2091732 grpc_verifier.go:936] ======= GetCertificate ========
I0412 14:06:34.756663 2091732 grpc_verifier.go:969] Creating public x509
I0412 14:06:34.759496 2091732 grpc_verifier.go:1089] =============== end GetCertificate ===============
```


##### Attestor

Now run the attestor and specify the verifier

```bash
export VERIFIER_ADDRESS=127.0.0.1

go run src/client/grpc_attestor.go -host $VERIFIER_ADDRESS:50051 \
   --tpm-path="127.0.0.1:2321"   --eventLogPath=swtpm/binary_bios_measurements  \
    --v=10 -alsologtostderr

I0412 14:06:34.418225 2091915 grpc_attestor.go:114] =============== HealthCheck ===============
I0412 14:06:34.428809 2091915 grpc_attestor.go:130] RPC HealthChekStatus: SERVING
I0412 14:06:34.428889 2091915 grpc_attestor.go:147] EKM: 6bd1b46be2e6835b90d4e31c0968063c9e579f2adc4a6226b848556bde9f3149
I0412 14:06:34.428958 2091915 grpc_attestor.go:158] Opening swtpm socket
I0412 14:06:34.430842 2091915 grpc_attestor.go:189] ECCert with available Issuer: CN=swtpm-localca
I0412 14:06:34.430946 2091915 grpc_attestor.go:217] =============== OfferPlatformCert ===============
I0412 14:06:34.437890 2091915 grpc_attestor.go:300] Verified Platform Cert
I0412 14:06:34.437943 2091915 grpc_attestor.go:302] =============== OfferEK ===============
I0412 14:06:34.439871 2091915 grpc_attestor.go:311] Verified EK Cert
I0412 14:06:34.439920 2091915 grpc_attestor.go:313] =============== OfferAK ===============
I0412 14:06:34.698816 2091915 grpc_attestor.go:351] Verified AK 
I0412 14:06:34.698895 2091915 grpc_attestor.go:353] =============== GetMakeCredential ===============
I0412 14:06:34.726905 2091915 grpc_attestor.go:382] EncryptedCredentials Secret m9V+HoK2304QpzpO3fIjpcMUYL+akKEZivUW0ZEwaNI=
I0412 14:06:34.726961 2091915 grpc_attestor.go:384] =============== SetActivateCredential ===============
I0412 14:06:34.727743 2091915 grpc_attestor.go:393] SetActivateCredential complete 
I0412 14:06:34.727795 2091915 grpc_attestor.go:395] =============== OfferQuote ===============
I0412 14:06:34.728415 2091915 grpc_attestor.go:402] OfferQuote complete 
I0412 14:06:34.728497 2091915 grpc_attestor.go:404] =============== SetQuote ===============
I0412 14:06:34.743169 2091915 grpc_attestor.go:434] SetQuote complete 
I0412 14:06:34.743255 2091915 grpc_attestor.go:436] =============== SetAttestedKey ===============
I0412 14:06:34.752240 2091915 grpc_attestor.go:487] Generated ECC Public 
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE/nLc7f7E1LLKEuoodB6A2uLMqn6w
pK06dIFtxrBgy9U8FR6Frii/Kxmy+I5DuefeMGxLr4vaE2Fq43N0BS1pKw==
-----END PUBLIC KEY-----
I0412 14:06:34.753766 2091915 grpc_attestor.go:504] SetAttestedKey complete 
I0412 14:06:34.753839 2091915 grpc_attestor.go:506] =============== GetCertificate ===============
I0412 14:06:34.753894 2091915 grpc_attestor.go:508] Creating CSR
I0412 14:06:34.755977 2091915 grpc_attestor.go:541] CSR 
-----BEGIN CERTIFICATE REQUEST-----
MIIBUDCB9gIBADBxMQswCQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTEW
MBQGA1UEBxMNTW91bnRhaW4gVmlldzEQMA4GA1UEChMHQWNtZSBDbzETMBEGA1UE
CxMKRW50ZXJwcmlzZTEOMAwGA1UEAxMFbXl0cG0wWTATBgcqhkjOPQIBBggqhkjO
PQMBBwNCAAT+ctzt/sTUssoS6ih0HoDa4syqfrCkrTp0gW3GsGDL1TwVHoWuKL8r
GbL4jkO5594wbEuvi9oTYWrjc3QFLWkroCMwIQYJKoZIhvcNAQkOMRQwEjAQBgNV
HREECTAHggVteXRwbTAKBggqhkjOPQQDAgNJADBGAiEAvLKCJjiUG9Bb60hY9CIb
8NZ+pK5G6edt0k/2HTAiNAECIQDHNbOOYoAOGCt+ceR7zOBZoo464RZarcpxlI40
XzAjJg==
-----END CERTIFICATE REQUEST-----

I0412 14:06:34.759792 2091915 grpc_attestor.go:553] Issued Certificate: 
-----BEGIN CERTIFICATE-----
MIIDTjCCAjagAwIBAgIRAPeRZwf/9VIiG5TL8TH7AM4wDQYJKoZIhvcNAQELBQAw
TDELMAkGA1UEBhMCVVMxDzANBgNVBAoMBkdvb2dsZTETMBEGA1UECwwKRW50ZXJw
cmlzZTEXMBUGA1UEAwwOU2luZ2xlIFJvb3QgQ0EwHhcNMjYwNDEyMTgwNjM0WhcN
MjYwNDEzMTgwNjM0WjBxMQswCQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5p
YTEWMBQGA1UEBxMNTW91bnRhaW4gVmlldzEQMA4GA1UEChMHQWNtZSBDbzETMBEG
A1UECxMKRW50ZXJwcmlzZTEOMAwGA1UEAxMFbXl0cG0wWTATBgcqhkjOPQIBBggq
hkjOPQMBBwNCAAT+ctzt/sTUssoS6ih0HoDa4syqfrCkrTp0gW3GsGDL1TwVHoWu
KL8rGbL4jkO5594wbEuvi9oTYWrjc3QFLWkro4HQMIHNMA4GA1UdDwEB/wQEAwIH
gDAMBgNVHRMBAf8EAjAAMB8GA1UdIwQYMBaAFOzw6lNTP58j3MEOMRA3B97e527z
MIGLBgNVHREEgYMwgYCgLAYIKwYBBQUHCASgIDAehBxTSU0wOi9tUdt3Nuy5Lc3i
J4AxyLHsw4e0OgTAoFAGCCsGAQUFBwgDoEQwQgxAYjZmYTM0Yjg0MjA3Y2QwYzY5
ZTVhNjc0OTI5OGZjMTc4NDE1MGViMzc3Y2Q4ZGJiZjFmZjg3YTVhM2U1NmVlYjAN
BgkqhkiG9w0BAQsFAAOCAQEAfeDMoylWb6L7dWIsFK40iDNc3OhZPmsHifRCO/21
dePoZAwkfycKSO1Eq5jV5S1D7TZodq2d0MN6IsWs8QXvGlBFJpwKeKCzm+BVcMNk
1w+fSiawoLlhqywdIa3hd1rBTje8/5AJEPyq2NMOcR3LPPDt3+ruX3hspjdVxEQH
ihWAfJVZAcO8e4tggE9vH/fuYz8MIPEtUoDLKtfNYQIhz7u2JM8ifbneb6KvTeSx
6Bc64evOh39vVq7yuhEg9/alGoPNn+IKVJ8dNiRRahz8gB2Z5vB+tcc3GlevxCAV
SU5Y8sRw48pfLtbTuQw83VoqJxx3bnhLWnXHhBYkQA/3iw==
-----END CERTIFICATE-----

I0412 14:06:34.759870 2091915 grpc_attestor.go:555] GetCertificate complete
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