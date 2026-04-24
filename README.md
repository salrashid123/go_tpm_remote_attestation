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

        I1219 12:29:47.340005 2193152 grpc_verifier.go:136] ======= OfferPlatformCert ========
        I1219 12:29:47.340456 2193152 grpc_verifier.go:156]      PlatformCertificate Issuer: CN=www.intel.com,OU=TrustedSupplyChain,O=Intel Corporation,L=Santa Clara,ST=California,C=US
        I1219 12:29:47.340506 2193152 grpc_verifier.go:157]      PlatformCertificate Version: 2
        I1219 12:29:47.340519 2193152 grpc_verifier.go:159]      PlatformCertificate CredentialSpecification: 
        I1219 12:29:47.340531 2193152 grpc_verifier.go:160]      PlatformCertificate PlatformManufacturer: Intel
        I1219 12:29:47.340542 2193152 grpc_verifier.go:161]      PlatformCertificate PlatformModel: S2600KP
        I1219 12:29:47.340554 2193152 grpc_verifier.go:162]      PlatformCertificate PlatformVersion: H76962-350
        I1219 12:29:47.340566 2193152 grpc_verifier.go:163]      PlatformCertificate PropertiesURI: 
        I1219 12:29:47.340578 2193152 grpc_verifier.go:178]      PlatformCertificate Holder.Issuer: CN=STMicro
        I1219 12:29:47.340597 2193152 grpc_verifier.go:179]      PlatformCertificate Holder.Serial: 449600017855339869538679649152375580078880538087
        I1219 12:29:47.340624 2193152 grpc_verifier.go:180]      PlatformCertificate Holder.Issuer.CommonName: STMicro
        I1219 12:29:47.340642 2193152 grpc_verifier.go:185]      PlatformCertificate TBBSecurityAssertions.Iso9000URI: URL to iso9000 certificate
        I1219 12:29:47.340659 2193152 grpc_verifier.go:186]      PlatformCertificate TBBSecurityAssertions.CcInfo.ProfileOid: 
        I1219 12:29:47.340681 2193152 grpc_verifier.go:187]      PlatformCertificate TBBSecurityAssertions.CcInfo.ProfileURI: 
        I1219 12:29:47.340699 2193152 grpc_verifier.go:188]      PlatformCertificate TBBSecurityAssertions.CcInfo.TargetOid: 
        I1219 12:29:47.340719 2193152 grpc_verifier.go:189]      PlatformCertificate TBBSecurityAssertions.CcInfo.TargetURI: 
        I1219 12:29:47.340738 2193152 grpc_verifier.go:190]      PlatformCertificate TBBSecurityAssertions.CcInfo.Version: CC Version
        I1219 12:29:47.340758 2193152 grpc_verifier.go:192]      PlatformCertificate TCGPlatformSpecification.Version: {1 2 1}
        I1219 12:29:47.340782 2193152 grpc_verifier.go:193]      PlatformCertificate TCGPlatformSpecification.Version.MajorVersion: 1
        I1219 12:29:47.340802 2193152 grpc_verifier.go:194]      PlatformCertificate TCGPlatformSpecification.Version.MinorVersion: 2
        I1219 12:29:47.340822 2193152 grpc_verifier.go:195]      PlatformCertificate TCGPlatformSpecification.Version.Revision: 1
        I1219 12:29:47.340843 2193152 grpc_verifier.go:197]      PlatformCertificate UserNotice.UserNotice.ExplicitText: TCPA Trusted Platform Endorsement
        I1219 12:29:47.340865 2193152 grpc_verifier.go:198]      PlatformCertificate UserNotice.UserNotice.Organization: Credential Type Label
        I1219 12:29:47.340886 2193152 grpc_verifier.go:199]      PlatformCertificate UserNotice.UserNotice.NoticeNumbers: []
        I1219 12:29:47.341040 2193152 grpc_verifier.go:205]  Verified Platform cert signed by privacyCA
        I1219 12:29:47.359221 2193152 grpc_verifier.go:225] ======= OfferEK ========
        I1219 12:29:47.359431 2193152 grpc_verifier.go:262]      TPM Manufacturer id:53544D20
        I1219 12:29:47.359474 2193152 grpc_verifier.go:265]      TPM Model ST33KTPM2X
        I1219 12:29:47.359501 2193152 grpc_verifier.go:269]      TPM Version id:00090100
        I1219 12:29:47.359542 2193152 grpc_verifier.go:298]      TPM Family 2.0
        I1219 12:29:47.359565 2193152 grpc_verifier.go:299]      TPM Level 0
        I1219 12:29:47.359589 2193152 grpc_verifier.go:300]      TPM Revision 159
        I1219 12:29:47.359629 2193152 grpc_verifier.go:315]         EKCertificate ========
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

        I1219 12:29:47.359795 2193152 grpc_verifier.go:330]      EKCert  Issuer CN=STSAFE TPM RSA Intermediate CA 10,O=STMicroelectronics NV,C=CH
        I1219 12:29:47.359868 2193152 grpc_verifier.go:331]      EKCert  IssuingCertificateURL [http://sw-center.st.com/STSAFE/stsafetpmrsaint10.crt]
        I1219 12:29:47.359895 2193152 grpc_verifier.go:332]      EKCert  SerialNumber 720545561707831497387264474846090629232862299265
        I1219 12:29:47.359912 2193152 grpc_verifier.go:334]     EkCert Public Key 
        -----BEGIN PUBLIC KEY-----
        MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0shjU+4tGz+FRFoe4SVx
        NtZA7hGxA1MeC891SLmnOMiXGZGgBJGPv+USVLY2OJFln4X94vvNE1Rh06HFG9Fo
        PBA//coeFavi7cjV9GUh3beY8wX6ergOMTxl38xbiBN6LKYuqwQ51wuMrOB5Q0n8
        XIJwjCfnSWGCAo16FadUxteEixOuWbHW+If7T/j3FsHzD+QCbCYrQ1AzrHCHNsiw
        MAyKXdIncJnNaKi8qLDlD4IXT2RbjijSoAFWO086Li5gwtVVoMULN4B4d83309EI
        11LvCiNCWGAJZ7pxTME7+WJMurXcJec19c9M4YrjEAEggxfxKc+Bktv1ibCCeOeg
        VwIDAQAB
        -----END PUBLIC KEY-----

        I1219 12:29:47.359938 2193152 grpc_verifier.go:337]     Verifying EKCert
        I1219 12:29:47.360217 2193152 grpc_verifier.go:363]      EKCert Includes tcg-kp-EKCertificate ExtendedKeyUsage 2.23.133.8.1
        I1219 12:29:47.361563 2193152 grpc_verifier.go:387]     EKCert Verified
        I1219 12:29:47.361591 2193152 grpc_verifier.go:404] =============== end OfferEK ===============
        I1219 12:29:47.816001 2193152 grpc_verifier.go:409] ======= OfferAK ========
        I1219 12:29:47.816263 2193152 grpc_verifier.go:444]       ak public 
        -----BEGIN PUBLIC KEY-----
        MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmZCLU9GPIebaiLIKP9WZ
        YSqw07/VO/mEkxMHIb8QTXwo63CIf8OFmt4TTO+nIBhF3Hk4K6ztNTFce6Wgj3Bk
        dz/OJ4A+GlDSO4TjmqQmMNKmDGGLXxowB9BZKJx2e9PiaTbrhMH8TWt0GGtE0lE8
        xBuiV0Ld+5VIoN/+pvH2EPSQHDv9GKRG+4yZ3wnyb3gh9AJgvbUgjaMZnQ2jC4Lt
        a5ph+7c7e4189XUgvvDxhf5GXELChmPceg8iOcvvn69XkrXjAq4/c6REl92REsMu
        UVBD9GAxOobgXb6PIWKjrTKUMA66bGQJrdf/FJD/kc8O/rt202oQHfK+rxEROe4J
        JwIDAQAB
        -----END PUBLIC KEY-----

        I1219 12:29:47.816300 2193152 grpc_verifier.go:451] =============== end GetAK ===============
        I1219 12:29:47.817185 2193152 grpc_verifier.go:457] ======= GetMakeCredential ========
        I1219 12:29:47.817229 2193152 grpc_verifier.go:468] =============== end GetMakeCredential ===============
        I1219 12:29:47.817739 2193152 grpc_verifier.go:482]       Outbound Secret: RrCeEupGOpUqOS6w/j+ZdJCsB3uSD7rn9X1kh6Hqs7Q=
        I1219 12:29:48.732192 2193152 grpc_verifier.go:499] ======= SetActivateCredential ========
        I1219 12:29:48.732248 2193152 grpc_verifier.go:523] =============== end SetActivateCredential ===============
        I1219 12:29:48.733143 2193152 grpc_verifier.go:528] ======= OfferQuote ========
        I1219 12:29:48.733215 2193152 grpc_verifier.go:547] =============== end OfferQuote ===============
        I1219 12:29:51.701628 2193152 grpc_verifier.go:554] ======= SetQuote ========
        I1219 12:29:51.704311 2193152 grpc_verifier.go:599]       quote-attested public 
        -----BEGIN PUBLIC KEY-----
        MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmZCLU9GPIebaiLIKP9WZ
        YSqw07/VO/mEkxMHIb8QTXwo63CIf8OFmt4TTO+nIBhF3Hk4K6ztNTFce6Wgj3Bk
        dz/OJ4A+GlDSO4TjmqQmMNKmDGGLXxowB9BZKJx2e9PiaTbrhMH8TWt0GGtE0lE8
        xBuiV0Ld+5VIoN/+pvH2EPSQHDv9GKRG+4yZ3wnyb3gh9AJgvbUgjaMZnQ2jC4Lt
        a5ph+7c7e4189XUgvvDxhf5GXELChmPceg8iOcvvn69XkrXjAq4/c6REl92REsMu
        UVBD9GAxOobgXb6PIWKjrTKUMA66bGQJrdf/FJD/kc8O/rt202oQHfK+rxEROe4J
        JwIDAQAB
        -----END PUBLIC KEY-----

        I1219 12:29:51.704500 2193152 grpc_verifier.go:623]      PCR: 0, verified: true value: 7bb4353897632fd086982175a027dafcc33f61adbab4ebfc6d13927b97a8c084
        I1219 12:29:51.704521 2193152 grpc_verifier.go:623]      PCR: 1, verified: true value: 0e2c30270bbf1e52967a5ebedc6cdffb7f5166c70fb5fbda021ab5db4f87ca80
        I1219 12:29:51.704531 2193152 grpc_verifier.go:623]      PCR: 2, verified: true value: f8650efffd171c5d05d0aface51ef1ab216e25b7660faa6d6b9d1731b7c2f748
        I1219 12:29:51.704539 2193152 grpc_verifier.go:623]      PCR: 3, verified: true value: 3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969
        I1219 12:29:51.704548 2193152 grpc_verifier.go:623]      PCR: 4, verified: true value: f75dc309511a6cd8ece093f69696344540714814b4b2cd0c78a9b7e585da0f1d
        I1219 12:29:51.704557 2193152 grpc_verifier.go:623]      PCR: 5, verified: true value: 07ffb98f19e294b075eeac8405a8121ee3be0aceb7a5c3dfa4c204a0e7f492f8
        I1219 12:29:51.704564 2193152 grpc_verifier.go:623]      PCR: 6, verified: true value: 3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969
        I1219 12:29:51.704572 2193152 grpc_verifier.go:623]      PCR: 7, verified: true value: 46d45493dc751af8c46996eedaf69d7d4012d46ca8d75bbb141d23103361e59e
        I1219 12:29:51.704579 2193152 grpc_verifier.go:623]      PCR: 8, verified: true value: ff953f45135e1da2129957b5cedb8561001ca97e8fe3d45c9f1675d60481fbde
        I1219 12:29:51.704586 2193152 grpc_verifier.go:623]      PCR: 9, verified: true value: 302930637ddf7b87c3776c2ef4e275d40a5dc0018a6684e298804c3d1fd1a502
        I1219 12:29:51.704593 2193152 grpc_verifier.go:623]      PCR: 10, verified: true value: c3ebd1c735e77a46c9c99d8ca6aaecbf2fc083eb3ae33ce24c7b4e279b865bea
        I1219 12:29:51.704601 2193152 grpc_verifier.go:623]      PCR: 11, verified: true value: b6acfabc5ddd888d0ad5f4154ea940fe302528eea116dcc881aeddab2b119f91
        I1219 12:29:51.704608 2193152 grpc_verifier.go:623]      PCR: 12, verified: true value: 0000000000000000000000000000000000000000000000000000000000000000
        I1219 12:29:51.704615 2193152 grpc_verifier.go:623]      PCR: 13, verified: true value: 0000000000000000000000000000000000000000000000000000000000000000
        I1219 12:29:51.704622 2193152 grpc_verifier.go:623]      PCR: 14, verified: true value: 0000000000000000000000000000000000000000000000000000000000000000
        I1219 12:29:51.704628 2193152 grpc_verifier.go:623]      PCR: 15, verified: true value: 0000000000000000000000000000000000000000000000000000000000000000
        I1219 12:29:51.704635 2193152 grpc_verifier.go:623]      PCR: 16, verified: true value: 0000000000000000000000000000000000000000000000000000000000000000
        I1219 12:29:51.704643 2193152 grpc_verifier.go:623]      PCR: 17, verified: true value: ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
        I1219 12:29:51.704650 2193152 grpc_verifier.go:623]      PCR: 18, verified: true value: ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
        I1219 12:29:51.704657 2193152 grpc_verifier.go:623]      PCR: 19, verified: true value: ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
        I1219 12:29:51.704664 2193152 grpc_verifier.go:623]      PCR: 20, verified: true value: ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
        I1219 12:29:51.704671 2193152 grpc_verifier.go:623]      PCR: 21, verified: true value: ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
        I1219 12:29:51.704678 2193152 grpc_verifier.go:623]      PCR: 22, verified: true value: ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
        I1219 12:29:51.704685 2193152 grpc_verifier.go:623]      PCR: 23, verified: true value: 0000000000000000000000000000000000000000000000000000000000000000
        I1219 12:29:51.704692 2193152 grpc_verifier.go:634]      quotes verified
        I1219 12:29:51.705518 2193152 grpc_verifier.go:660]      secureBoot State enabled: [true]
        I1219 12:29:51.705627 2193152 grpc_verifier.go:666] =============== end SetQuote ===============
        I1219 12:29:52.880904 2193152 grpc_verifier.go:671] ======= SetAttestedKey ========
        I1219 12:29:52.880944 2193152 grpc_verifier.go:686]         New PublicKey ========
        I1219 12:29:52.881194 2193152 grpc_verifier.go:708]      Key AuthPolicy []
        I1219 12:29:52.881210 2193152 grpc_verifier.go:718]      Key TPM Properties mask: 262258
        I1219 12:29:52.881227 2193152 grpc_verifier.go:721]      Key Expected Properties mask 262258
        I1219 12:29:52.881282 2193152 grpc_verifier.go:751]      key verified 
        -----BEGIN PUBLIC KEY-----
        MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAECabv/8CPrN0S+N9BJEwxVK+RUqag
        gxo+gg8KEDacYKTGaTpAZ7WlfXjnsX0FlDCwmjKe4VNSEP+2XG72i+qKJw==
        -----END PUBLIC KEY-----

        I1219 12:29:52.881300 2193152 grpc_verifier.go:753] =============== end SetAttestedKey ===============
        I1219 12:29:53.005091 2193152 grpc_verifier.go:758] ======= GetCertificate ========
        I1219 12:29:53.005286 2193152 grpc_verifier.go:779] Creating public x509
        I1219 12:29:53.010471 2193152 grpc_verifier.go:843] =============== end GetCertificate ===============
```


### Attestor

Now run the Attestor:

```bash
export VERIFIER_ADDRESS=127.0.0.1

sudo go run src/client/grpc_attestor.go -host $VERIFIER_ADDRESS:50051 \
  --tpm-path="/dev/tpmrm0"  --v=10 -alsologtostderr

        I1219 12:29:47.332479 2193240 grpc_attestor.go:102] =============== OfferPlatformCert ===============
        I1219 12:29:47.341418 2193240 grpc_attestor.go:118] Verified Platform Cert
        I1219 12:29:47.341472 2193240 grpc_attestor.go:120] =============== OfferEK ===============
        I1219 12:29:47.358245 2193240 grpc_attestor.go:140] ECCert with available Issuer: CN=STSAFE TPM RSA Intermediate CA 10,O=STMicroelectronics NV,C=CH
        I1219 12:29:47.361999 2193240 grpc_attestor.go:175] Verified EK Cert
        I1219 12:29:47.362054 2193240 grpc_attestor.go:177] =============== OfferAK ===============
        I1219 12:29:47.816647 2193240 grpc_attestor.go:216] Verified AK 
        I1219 12:29:47.816725 2193240 grpc_attestor.go:218] =============== GetMakeCredential ===============
        I1219 12:29:48.730924 2193240 grpc_attestor.go:249] EncryptedCredentials Secret 46b09e12ea463a952a392eb0fe3f997490ac077b920fbae7f57d6487a1eab3b4
        I1219 12:29:48.731006 2193240 grpc_attestor.go:251] =============== SetActivateCredential ===============
        I1219 12:29:48.732633 2193240 grpc_attestor.go:261] SetActivateCredential complete 
        I1219 12:29:48.732682 2193240 grpc_attestor.go:263] =============== OfferQuote ===============
        I1219 12:29:48.733607 2193240 grpc_attestor.go:272] OfferQuote complete 
        I1219 12:29:48.733759 2193240 grpc_attestor.go:274] =============== SetQuote ===============
        I1219 12:29:51.706030 2193240 grpc_attestor.go:305] SetQuote complete 
        I1219 12:29:51.706112 2193240 grpc_attestor.go:307] =============== SetAttestedKey ===============
        I1219 12:29:52.879937 2193240 grpc_attestor.go:358] Generated ECC Public 
        -----BEGIN PUBLIC KEY-----
        MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAECabv/8CPrN0S+N9BJEwxVK+RUqag
        gxo+gg8KEDacYKTGaTpAZ7WlfXjnsX0FlDCwmjKe4VNSEP+2XG72i+qKJw==
        -----END PUBLIC KEY-----
        I1219 12:29:52.881690 2193240 grpc_attestor.go:376] SetAttestedKey complete 
        I1219 12:29:52.881767 2193240 grpc_attestor.go:378] =============== GetCertificate ===============
        I1219 12:29:52.881826 2193240 grpc_attestor.go:380] Creating CSR
        I1219 12:29:53.004223 2193240 grpc_attestor.go:413] CSR 
        -----BEGIN CERTIFICATE REQUEST-----
        MIIBUDCB9gIBADBxMQswCQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTEW
        MBQGA1UEBxMNTW91bnRhaW4gVmlldzEQMA4GA1UEChMHQWNtZSBDbzETMBEGA1UE
        CxMKRW50ZXJwcmlzZTEOMAwGA1UEAxMFbXl0cG0wWTATBgcqhkjOPQIBBggqhkjO
        PQMBBwNCAAQJpu//wI+s3RL430EkTDFUr5FSpqCDGj6CDwoQNpxgpMZpOkBntaV9
        eOexfQWUMLCaMp7hU1IQ/7ZcbvaL6oonoCMwIQYJKoZIhvcNAQkOMRQwEjAQBgNV
        HREECTAHggVteXRwbTAKBggqhkjOPQQDAgNJADBGAiEA3gTgKY25AEd4DTe6hTFa
        WhaFqC1yPATCTOLr5I/0QusCIQDTMRGlHa0t8rqLpomUFuxV2cZ79RIgIRY2sHMT
        +N2e5Q==
        -----END CERTIFICATE REQUEST-----

        I1219 12:29:53.010977 2193240 grpc_attestor.go:426] Isued Certificate: 
        -----BEGIN CERTIFICATE-----
        MIIC5DCCAcygAwIBAgIQdCptUsa/9+ha7ecHPOtfNDANBgkqhkiG9w0BAQsFADBM
        MQswCQYDVQQGEwJVUzEPMA0GA1UECgwGR29vZ2xlMRMwEQYDVQQLDApFbnRlcnBy
        aXNlMRcwFQYDVQQDDA5TaW5nbGUgUm9vdCBDQTAeFw0yNTEyMTkxNzI5NTNaFw0y
        NjEyMTkxNzI5NTNaMHExCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlh
        MRYwFAYDVQQHEw1Nb3VudGFpbiBWaWV3MRAwDgYDVQQKEwdBY21lIENvMRMwEQYD
        VQQLEwpFbnRlcnByaXNlMQ4wDAYDVQQDEwVteXRwbTBZMBMGByqGSM49AgEGCCqG
        SM49AwEHA0IABAmm7//Aj6zdEvjfQSRMMVSvkVKmoIMaPoIPChA2nGCkxmk6QGe1
        pX1457F9BZQwsJoynuFTUhD/tlxu9ovqiiejaDBmMA4GA1UdDwEB/wQEAwIHgDAT
        BgNVHSUEDDAKBggrBgEFBQcDAjAMBgNVHRMBAf8EAjAAMB8GA1UdIwQYMBaAFOzw
        6lNTP58j3MEOMRA3B97e527zMBAGA1UdEQQJMAeCBW15dHBtMA0GCSqGSIb3DQEB
        CwUAA4IBAQCHDPAP3kYiYihi8dDSNI/iOJtqp3Bf+pdquxtmpdGerTyoz1mDLNXX
        kSXrWzhLVZWoP7EhZi6UZTCvGGcB8xooqh8dVn6f4JxfTxapLYbrjbh0Jbs/gt9a
        E2hRPu3/RfMJFro2ALUMFOmtmYtDlLoWF1ifB7NcuhBE9rktIAAWb4os3BmLI0OT
        WDPY9f7lFq6cddGxfDhwnSPyFiVJ5EgAg3KCdWkT1APu1nPZOgfqD7irM2cC3IBY
        MlW3Od/TFTtnyPMVJ+NqSHRPc+EIEpCMW8uv9TSCbMFJ+XrCkgqjrVrRAmEsE//t
        Qzirmgn/EZGiGXj+ox1HRvfLsZo7NhbM
        -----END CERTIFICATE-----

        I1219 12:29:53.011093 2193240 grpc_attestor.go:428] GetCertificate complete 

```


---

## Setup on GCE

If you want to instead test with GCP VM:

First create a VMs

```bash
gcloud compute instances create attestor --zone=us-central1-a \
    --machine-type=n2d-standard-2  --min-cpu-platform="AMD Milan" \
    --shielded-secure-boot --no-service-account --no-scopes \
    --shielded-vtpm --confidential-compute-type=SEV \
    --shielded-integrity-monitoring 

gcloud compute instances create verifier --zone=us-central1-a \
    --machine-type=n2d-standard-2  --min-cpu-platform="AMD Milan" \
    --shielded-secure-boot --no-service-account --no-scopes \
    --shielded-vtpm --confidential-compute-type=SEV \
    --shielded-integrity-monitoring     
```

on both

Install `go 1.20+` and setup `libtspi-dev`, `gcc` (`apt-get update && apt-get install gcc libtspi-dev tpm2-tools`)

```bash
apt-get update
apt-get install libtspi-dev wget gcc git tpm2-tools -y

wget https://go.dev/dl/go1.22.3.linux-amd64.tar.gz
rm -rf /usr/local/go && tar -C /usr/local -xzf go1.22.3.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin/
```

Get the external IP for the verifier

```bash
$ gcloud compute instances list --filter=name=attestor
NAME      ZONE           MACHINE_TYPE    PREEMPTIBLE  INTERNAL_IP    EXTERNAL_IP    STATUS
verifier  us-central1-a  n2d-standard-2               10.128.15.208  34.121.64.117  RUNNING
```

For GCP Confidential VM's, PCR 0 and 7 are used for attestation and those have default values on the `attestor` vm of:

```bash
# tpm2_pcrread -o pcrs sha1:0+sha256:0,7
  sha1:
    0 : 0x2AAB58E23EA5120D70A3EBCE56BD0E6D5E3035B7
  sha256:
    0 : 0xA0B5FF3383A1116BD7DC6DF177C0C2D433B9EE1813EA958FA5D166A202CB2A85
    7 : 0x59CE152EB723A82C172B04DC3628C799F2CE322C328D75F30E1A9F01233CB4BB
```

Do the following step after running the verifier (i.,e skip ahead)

```bash
export VERIFIER_ADDRESS=10.128.15.208

go run src/client/grpc_attestor.go  -alsologtostderr -v 50 -host $VERIFIER_ADDRESS:50051
```

```log
    I1225 13:08:43.758097   12511 grpc_attestor.go:124] ECCert with available Issuer: CN=EK/AK CA Intermediate,OU=Google Cloud,O=Google LLC,L=Mountain View,ST=California,C=US
    I1225 13:08:43.758203   12511 grpc_attestor.go:152] =============== OfferPlatformCert ===============
    I1225 13:08:43.767006   12511 grpc_attestor.go:236] Verified Platform Cert
    I1225 13:08:43.767027   12511 grpc_attestor.go:238] =============== OfferEK ===============
    I1225 13:08:43.769483   12511 grpc_attestor.go:248] Verified EK Cert
    I1225 13:08:43.769602   12511 grpc_attestor.go:250] =============== OfferAK ===============
    I1225 13:08:43.895168   12511 grpc_attestor.go:289] Verified AK 
    I1225 13:08:43.895230   12511 grpc_attestor.go:291] =============== GetMakeCredential ===============
    I1225 13:08:44.008342   12511 grpc_attestor.go:322] EncryptedCredentials Secret AHwCI1YYWQbr2mVbPwhXtWm+5DK05E/z3BOBWS2kpJw=
    I1225 13:08:44.008407   12511 grpc_attestor.go:324] =============== SetActivateCredential ===============
    I1225 13:08:44.009338   12511 grpc_attestor.go:334] SetActivateCredential complete 
    I1225 13:08:44.009382   12511 grpc_attestor.go:336] =============== OfferQuote ===============
    I1225 13:08:44.010116   12511 grpc_attestor.go:345] OfferQuote complete 
    I1225 13:08:44.010152   12511 grpc_attestor.go:347] =============== SetQuote ===============
    I1225 13:08:44.213251   12511 grpc_attestor.go:378] SetQuote complete 
    I1225 13:08:44.213413   12511 grpc_attestor.go:380] =============== SetAttestedKey ===============
    I1225 13:08:44.339047   12511 grpc_attestor.go:431] Generated ECC Public 
    -----BEGIN PUBLIC KEY-----
    MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEbIJdg+2OTsskDd1/fMMu/jVoTuYd
    rtZB8wLrsOr4kHwH6ylRLwWtL3E9thjq+EXciXGIbHxTDEeXpeFuu84xqw==
    -----END PUBLIC KEY-----
    I1225 13:08:44.340596   12511 grpc_attestor.go:449] SetAttestedKey complete 
    I1225 13:08:44.340654   12511 grpc_attestor.go:451] =============== GetCertificate ===============
    I1225 13:08:44.340690   12511 grpc_attestor.go:453] Creating CSR
    I1225 13:08:44.355294   12511 grpc_attestor.go:486] CSR 
    -----BEGIN CERTIFICATE REQUEST-----
    MIIBTjCB9gIBADBxMQswCQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTEW
    MBQGA1UEBxMNTW91bnRhaW4gVmlldzEQMA4GA1UEChMHQWNtZSBDbzETMBEGA1UE
    CxMKRW50ZXJwcmlzZTEOMAwGA1UEAxMFbXl0cG0wWTATBgcqhkjOPQIBBggqhkjO
    PQMBBwNCAARsgl2D7Y5OyyQN3X98wy7+NWhO5h2u1kHzAuuw6viQfAfrKVEvBa0v
    cT22GOr4RdyJcYhsfFMMR5el4W67zjGroCMwIQYJKoZIhvcNAQkOMRQwEjAQBgNV
    HREECTAHggVteXRwbTAKBggqhkjOPQQDAgNHADBEAiA3lCOZQMoC4sW+nxKdeEl7
    ivagH9rkwtZDLTthoBFtnwIgEDBIQ2zzxvp5xmPkzNFchXrY7O7zIYP2jskNbh16
    5Ww=
    -----END CERTIFICATE REQUEST-----

    I1225 13:08:44.358944   12511 grpc_attestor.go:499] Issued Certificate: 
    -----BEGIN CERTIFICATE-----
    MIIC5TCCAc2gAwIBAgIRAPXrkeyreW1UTY3ELQoZqRMwDQYJKoZIhvcNAQELBQAw
    TDELMAkGA1UEBhMCVVMxDzANBgNVBAoMBkdvb2dsZTETMBEGA1UECwwKRW50ZXJw
    cmlzZTEXMBUGA1UEAwwOU2luZ2xlIFJvb3QgQ0EwHhcNMjUxMjI1MTMwODQ0WhcN
    MjUxMjI2MTMwODQ0WjBxMQswCQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5p
    YTEWMBQGA1UEBxMNTW91bnRhaW4gVmlldzEQMA4GA1UEChMHQWNtZSBDbzETMBEG
    A1UECxMKRW50ZXJwcmlzZTEOMAwGA1UEAxMFbXl0cG0wWTATBgcqhkjOPQIBBggq
    hkjOPQMBBwNCAARsgl2D7Y5OyyQN3X98wy7+NWhO5h2u1kHzAuuw6viQfAfrKVEv
    Ba0vcT22GOr4RdyJcYhsfFMMR5el4W67zjGro2gwZjAOBgNVHQ8BAf8EBAMCB4Aw
    EwYDVR0lBAwwCgYIKwYBBQUHAwIwDAYDVR0TAQH/BAIwADAfBgNVHSMEGDAWgBTs
    8OpTUz+fI9zBDjEQNwfe3udu8zAQBgNVHREECTAHggVteXRwbTANBgkqhkiG9w0B
    AQsFAAOCAQEAqsx0ekkwWOTm32uDQ1Kc6rBS4HhJhM2HDnYvxSQ345nhPHbvqpuj
    i88Nh9fwe0Kr9he2YPoBuKBIrE7hCu2SOqdf8E2DMG2N1/SOYpW3wROHGlH5Qfdu
    KkKabNUNmlgz3kdb4OGRRyuk5yoN6i2Tcp+c9JbQKW8jEiXsnd1GCxXb3LtpLX+E
    H9NlSJ1l5cBzWS8bLPpHL7McxV0Cd750QfTg2ox/5/R33Gnw1mR4mAyJodmMNpeb
    J9QbQXDKOGeMcb1ww8o8vMb2ln88vJRZ7KAG2KKdt9D/b78zlcSHDLck6m84+eZK
    amrPDRoumdQcULACNEN6ycww3S3wPd3pIA==
    -----END CERTIFICATE-----

    I1225 13:08:44.359066   12511 grpc_attestor.go:501] GetCertificate complete 
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

```bash
go run src/server/grpc_verifier.go  \
       --ekintermediateCA=certs/ek_intermediate.pem  --ekrootCA=certs/ek_root.pem  --expectedPCRMapSHA256=0:a0b5ff3383a1116bd7dc6df177c0c2d433b9ee1813ea958fa5d166a202cb2a85 \
        --v=50 -alsologtostderr
```

```log
    I1225 13:08:38.950267   38216 grpc_verifier.go:996] Starting gRPC server on port :50051
    I1225 13:08:43.765816   38216 grpc_verifier.go:139] ======= OfferPlatformCert ========
    I1225 13:08:43.766058   38216 grpc_verifier.go:178]      PlatformCertificate Issuer: CN=Platform Root CA,OU=Enterprise,O=Google,C=US
    I1225 13:08:43.766090   38216 grpc_verifier.go:179]      PlatformCertificate Version: 2
    I1225 13:08:43.766104   38216 grpc_verifier.go:181]      PlatformCertificate CredentialSpecification: 
    I1225 13:08:43.766115   38216 grpc_verifier.go:182]      PlatformCertificate PlatformManufacturer: 
    I1225 13:08:43.766125   38216 grpc_verifier.go:183]      PlatformCertificate PlatformModel: 
    I1225 13:08:43.766134   38216 grpc_verifier.go:184]      PlatformCertificate PlatformVersion: 
    I1225 13:08:43.766152   38216 grpc_verifier.go:185]      PlatformCertificate PropertiesURI: 
    I1225 13:08:43.766164   38216 grpc_verifier.go:200]      PlatformCertificate Holder.Issuer: CN=EK/AK CA Intermediate,OU=Google Cloud,O=Google LLC,L=Mountain View,ST=California,C=US
    I1225 13:08:43.766193   38216 grpc_verifier.go:201]      PlatformCertificate Holder.Serial: 3611588439953970456259285110145793871903745659
    I1225 13:08:43.766229   38216 grpc_verifier.go:202]      PlatformCertificate Holder.Issuer.CommonName: EK/AK CA Intermediate
    I1225 13:08:43.766247   38216 grpc_verifier.go:207]      PlatformCertificate TBBSecurityAssertions.Iso9000URI: 
    I1225 13:08:43.766264   38216 grpc_verifier.go:208]      PlatformCertificate TBBSecurityAssertions.CcInfo.ProfileOid: 
    I1225 13:08:43.766289   38216 grpc_verifier.go:209]      PlatformCertificate TBBSecurityAssertions.CcInfo.ProfileURI: 
    I1225 13:08:43.766307   38216 grpc_verifier.go:210]      PlatformCertificate TBBSecurityAssertions.CcInfo.TargetOid: 
    I1225 13:08:43.766342   38216 grpc_verifier.go:211]      PlatformCertificate TBBSecurityAssertions.CcInfo.TargetURI: 
    I1225 13:08:43.766367   38216 grpc_verifier.go:212]      PlatformCertificate TBBSecurityAssertions.CcInfo.Version: 
    I1225 13:08:43.766390   38216 grpc_verifier.go:214]      PlatformCertificate TCGPlatformSpecification.Version: {0 0 0}
    I1225 13:08:43.766418   38216 grpc_verifier.go:215]      PlatformCertificate TCGPlatformSpecification.Version.MajorVersion: 0
    I1225 13:08:43.766444   38216 grpc_verifier.go:216]      PlatformCertificate TCGPlatformSpecification.Version.MinorVersion: 0
    I1225 13:08:43.766468   38216 grpc_verifier.go:217]      PlatformCertificate TCGPlatformSpecification.Version.Revision: 0
    I1225 13:08:43.766492   38216 grpc_verifier.go:219]      PlatformCertificate UserNotice.UserNotice.ExplicitText: 
    I1225 13:08:43.766514   38216 grpc_verifier.go:220]      PlatformCertificate UserNotice.UserNotice.Organization: 
    I1225 13:08:43.766538   38216 grpc_verifier.go:221]      PlatformCertificate UserNotice.UserNotice.NoticeNumbers: []
    I1225 13:08:43.766615   38216 grpc_verifier.go:228]      Verified Platform cert signed by privacyCA
    I1225 13:08:43.767372   38216 grpc_verifier.go:249] ======= OfferEK ========
    I1225 13:08:43.767470   38216 grpc_verifier.go:341]      EKCert  GCE InstanceID 7971457955842118306
    I1225 13:08:43.767489   38216 grpc_verifier.go:342]      EKCert  GCE InstanceName attestor
    I1225 13:08:43.767502   38216 grpc_verifier.go:343]      EKCert  GCE ProjectId srashid-test2
    I1225 13:08:43.767554   38216 grpc_verifier.go:347]         EKCertificate ========
    -----BEGIN CERTIFICATE-----
    MIIF5zCCA8+gAwIBAgIUAKHzAIWLA2+Vcq1crHWOY3FYZnswDQYJKoZIhvcNAQEL
    BQAwgYYxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYwFAYDVQQH
    Ew1Nb3VudGFpbiBWaWV3MRMwEQYDVQQKEwpHb29nbGUgTExDMRUwEwYDVQQLEwxH
    b29nbGUgQ2xvdWQxHjAcBgNVBAMTFUVLL0FLIENBIEludGVybWVkaWF0ZTAgFw0y
    NTEyMTgxMTU4MTdaGA8yMDU1MTIxMTExNTgxNlowbjEWMBQGA1UEBxMNdXMtY2Vu
    dHJhbDEtYTEeMBwGA1UEChMVR29vZ2xlIENvbXB1dGUgRW5naW5lMRYwFAYDVQQL
    Ew1zcmFzaGlkLXRlc3QyMRwwGgYDVQQDExM3OTcxNDU3OTU1ODQyMTE4MzA2MIIB
    IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyed2APaDud1sGVqyh1D8Ssg/
    diCMkHnoy3GoMO/h+XUIiEACgy0TBVtprssAgUDozc1FMYx4RicMqlp5X5aiGFoE
    k9xOLAre8kwSGQ3HjD5WoM7kMG5IaXr/qcMX5vB99cUZlKEBfs8Exa1pf8hnbbYX
    dI1dHpCGgrRicnMx4JQR3e3uGgyrgYVAQRRJ2J8sgMaUe+ObDj2J1gvUvbDmiX+P
    j14GkqjvftaaRymIB0u5akEhTiSGAoSnAo3u67Rl9b/IsFEXWFUqA78TBZ4sCAiL
    OpuTs1UZ4D3rA3frFC5IMYD83zuPtrrFLO2+DKiNl3tZIPybJzQgC5MH9AVxWwID
    AQABo4IBYDCCAVwwDgYDVR0PAQH/BAQDAgUgMAwGA1UdEwEB/wQCMAAwHQYDVR0O
    BBYEFKdsHBDPRfgdQY82q/URy049L4hKMB8GA1UdIwQYMBaAFA8hnVbhqcCJxWza
    I8DE8TKwSol6MIGNBggrBgEFBQcBAQSBgDB+MHwGCCsGAQUFBzAChnBodHRwOi8v
    cHJpdmF0ZWNhLWNvbnRlbnQtNjVkMTY4OGUtMDAwMC0yMjAzLTg1MGUtMzBmZDM4
    MTQ1NmY4LnN0b3JhZ2UuZ29vZ2xlYXBpcy5jb20vODEwYWYzMTM0MDZhZDNlMjA3
    OWIvY2EuY3J0MGwGCisGAQQB1nkCARUEXjBcDA11cy1jZW50cmFsMS1hAgYApOlF
    n+AMDXNyYXNoaWQtdGVzdDICCG6gTsa37lKiDAhhdHRlc3RvcqAgMB6gAwIBAKED
    AQH/ogMBAf+jAwEBAKQDAQEApQMBAQAwDQYJKoZIhvcNAQELBQADggIBABrCILJa
    FWgY8S4AA/8npdEuHMTZdEu/ts77OBQ3WCnTB8MDgkRbmKGKReZ9mI4GL+LuyJWq
    Lf2Uh9bQ0dxvS/SZY/BYAoEABdBcZf082N7cPm9BX46abjbuiYOwZaFg9Y1Oudfw
    E97ty74TLb96hrLYThIHuqgdOKKHfDPbTi55E6YeFv/Y1ZHmJqgE/kLKW+FwgoS5
    5SRZWPXaniiCiHH414oSjMhrHnLlHTExtyGQhXg76ukHvrUnBHKEvJnffmo44GWU
    QFCQOCrmsIIHSDta+C9EEN6SHEp0gIhorRiIzE1DMzipApffc6xeXYAxuetM18PN
    OCgPg5aUzAizICnzQAL2oVjIRmsYBPalsWnPAy8N1/QwSSgauf7Os8Iwbg0i+hjP
    T/m6VAeZF+aL95Kgblcid/LmwtuQzr0bD4SyP3kx9ZjZ79K+fC6i8sRwmyMccmSo
    6ObVj2RRyJVhKxgbG9uprQhlsEnIVwBLsksi5+dCMcuPyf4HQxrR4DKXNEyABQZg
    KFx9f+ZSfUztUf/F3NHsFnFeTAmpkBFhGMXN1F4CmuuWwqMrkVK14Ge0zVB7+fFm
    NtN9soont2fHW+a6tFKjjEAq9qI+JVr0ptqccGgeMrFpfIy7+72kLXY0K68VJLn6
    KFpbri1K/wxQAJHo/4YfCe0qoKscctMl2BRx
    -----END CERTIFICATE-----

    I1225 13:08:43.767626   38216 grpc_verifier.go:363]      EKCert  Issuer CN=EK/AK CA Intermediate,OU=Google Cloud,O=Google LLC,L=Mountain View,ST=California,C=US
    I1225 13:08:43.767661   38216 grpc_verifier.go:364]      EKCert  IssuingCertificateURL [http://privateca-content-65d1688e-0000-2203-850e-30fd381456f8.storage.googleapis.com/810af313406ad3e2079b/ca.crt]
    I1225 13:08:43.767685   38216 grpc_verifier.go:365]      EKCert  SerialNumber 3611588439953970456259285110145793871903745659
    I1225 13:08:43.767703   38216 grpc_verifier.go:367]     EkCert Public Key 
    -----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyed2APaDud1sGVqyh1D8
    Ssg/diCMkHnoy3GoMO/h+XUIiEACgy0TBVtprssAgUDozc1FMYx4RicMqlp5X5ai
    GFoEk9xOLAre8kwSGQ3HjD5WoM7kMG5IaXr/qcMX5vB99cUZlKEBfs8Exa1pf8hn
    bbYXdI1dHpCGgrRicnMx4JQR3e3uGgyrgYVAQRRJ2J8sgMaUe+ObDj2J1gvUvbDm
    iX+Pj14GkqjvftaaRymIB0u5akEhTiSGAoSnAo3u67Rl9b/IsFEXWFUqA78TBZ4s
    CAiLOpuTs1UZ4D3rA3frFC5IMYD83zuPtrrFLO2+DKiNl3tZIPybJzQgC5MH9AVx
    WwIDAQAB
    -----END PUBLIC KEY-----

    I1225 13:08:43.767746   38216 grpc_verifier.go:370]     Verifying EKCert
    I1225 13:08:43.769238   38216 grpc_verifier.go:425]     EKCert Verified
    I1225 13:08:43.769269   38216 grpc_verifier.go:448] =============== end OfferEK ===============
    I1225 13:08:43.894640   38216 grpc_verifier.go:453] ======= OfferAK ========
    I1225 13:08:43.894844   38216 grpc_verifier.go:497]       ak public 
    -----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0UNDOqJog/snw1K4AO1j
    oXXIUp2YA6OQrJ5Z8mHGW1TWVdTYIrYKZfC9ve8smNwmBE9vj3Bnkeg/MvpQqZpc
    PM91lzkKhLZsPuNdcWzsTFGT1spnYlRrugZQUwsSl+/BMUOxUfp/2dl9VicrLltp
    vxE/3OPIBRd7F+H5z2e0D1/3r274IOxcV/VbuIbXEbBx5/MB2HNzanpOLklA14Qi
    ju/Zfwq84uA7djlhB4dW7XCItT7FoWzIOkyAHEBfLPgDvpZS+ISUvisgcq/VdYeG
    nvribToejtmDmnu7jId9vgjXd4976gm8k60sh7ACgQOIPCfUmbbItgRlIGfKR9r3
    7QIDAQAB
    -----END PUBLIC KEY-----

    I1225 13:08:43.894870   38216 grpc_verifier.go:504] =============== end GetAK ===============
    I1225 13:08:43.895570   38216 grpc_verifier.go:510] ======= GetMakeCredential ========
    I1225 13:08:43.895597   38216 grpc_verifier.go:527] =============== end GetMakeCredential ===============
    I1225 13:08:43.896001   38216 grpc_verifier.go:541]       Outbound Secret: AHwCI1YYWQbr2mVbPwhXtWm+5DK05E/z3BOBWS2kpJw=
    I1225 13:08:44.009016   38216 grpc_verifier.go:559] ======= SetActivateCredential ========
    I1225 13:08:44.009056   38216 grpc_verifier.go:590] =============== end SetActivateCredential ===============
    I1225 13:08:44.009735   38216 grpc_verifier.go:595] ======= OfferQuote ========
    I1225 13:08:44.009759   38216 grpc_verifier.go:620] =============== end OfferQuote ===============
    I1225 13:08:44.208014   38216 grpc_verifier.go:627] ======= SetQuote ========
    I1225 13:08:44.209165   38216 grpc_verifier.go:680]       quote-attested public 
    -----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0UNDOqJog/snw1K4AO1j
    oXXIUp2YA6OQrJ5Z8mHGW1TWVdTYIrYKZfC9ve8smNwmBE9vj3Bnkeg/MvpQqZpc
    PM91lzkKhLZsPuNdcWzsTFGT1spnYlRrugZQUwsSl+/BMUOxUfp/2dl9VicrLltp
    vxE/3OPIBRd7F+H5z2e0D1/3r274IOxcV/VbuIbXEbBx5/MB2HNzanpOLklA14Qi
    ju/Zfwq84uA7djlhB4dW7XCItT7FoWzIOkyAHEBfLPgDvpZS+ISUvisgcq/VdYeG
    nvribToejtmDmnu7jId9vgjXd4976gm8k60sh7ACgQOIPCfUmbbItgRlIGfKR9r3
    7QIDAQAB
    -----END PUBLIC KEY-----

    I1225 13:08:44.209542   38216 grpc_verifier.go:706]      PCR: 0, verified: true value: 2aab58e23ea5120d70a3ebce56bd0e6d5e3035b7
    I1225 13:08:44.209568   38216 grpc_verifier.go:706]      PCR: 1, verified: true value: bd130e032b6a08e3a560742f85ab6ec06187ca59
    I1225 13:08:44.209579   38216 grpc_verifier.go:706]      PCR: 2, verified: true value: b2a83b0ebf2f8374299a5b2bdfc31ea955ad7236
    I1225 13:08:44.209587   38216 grpc_verifier.go:706]      PCR: 3, verified: true value: b2a83b0ebf2f8374299a5b2bdfc31ea955ad7236
    I1225 13:08:44.209592   38216 grpc_verifier.go:706]      PCR: 4, verified: true value: 2bb79b803727f951c9e94b1d397dd1fdb313613b
    I1225 13:08:44.209596   38216 grpc_verifier.go:706]      PCR: 5, verified: true value: 21d0cb9381826d50a52a5bd7529b26b79cf33ce8
    I1225 13:08:44.209602   38216 grpc_verifier.go:706]      PCR: 6, verified: true value: b2a83b0ebf2f8374299a5b2bdfc31ea955ad7236
    I1225 13:08:44.209613   38216 grpc_verifier.go:706]      PCR: 7, verified: true value: f85407dacbab76af05dafa4ff33d0e8712a90222
    I1225 13:08:44.209619   38216 grpc_verifier.go:706]      PCR: 8, verified: true value: 52f1ab36cee5b33c1214938c7e4e50b6b4d1292d
    I1225 13:08:44.209624   38216 grpc_verifier.go:706]      PCR: 9, verified: true value: 39cce3f2ed3ea8c58a4fa4fa3bbf96c6595c17e5
    I1225 13:08:44.209629   38216 grpc_verifier.go:706]      PCR: 10, verified: true value: b16c0d2bc5634594126825f15429c4334715740d
    I1225 13:08:44.209634   38216 grpc_verifier.go:706]      PCR: 11, verified: true value: 0000000000000000000000000000000000000000
    I1225 13:08:44.209639   38216 grpc_verifier.go:706]      PCR: 12, verified: true value: 0000000000000000000000000000000000000000
    I1225 13:08:44.209644   38216 grpc_verifier.go:706]      PCR: 13, verified: true value: 0000000000000000000000000000000000000000
    I1225 13:08:44.209665   38216 grpc_verifier.go:706]      PCR: 14, verified: true value: a482a15e112717d6a915b989a0ea6140a507e3e6
    I1225 13:08:44.209671   38216 grpc_verifier.go:706]      PCR: 15, verified: true value: 0000000000000000000000000000000000000000
    I1225 13:08:44.209678   38216 grpc_verifier.go:706]      PCR: 16, verified: true value: 0000000000000000000000000000000000000000
    I1225 13:08:44.209691   38216 grpc_verifier.go:706]      PCR: 17, verified: true value: ffffffffffffffffffffffffffffffffffffffff
    I1225 13:08:44.209697   38216 grpc_verifier.go:706]      PCR: 18, verified: true value: ffffffffffffffffffffffffffffffffffffffff
    I1225 13:08:44.209703   38216 grpc_verifier.go:706]      PCR: 19, verified: true value: ffffffffffffffffffffffffffffffffffffffff
    I1225 13:08:44.209708   38216 grpc_verifier.go:706]      PCR: 20, verified: true value: ffffffffffffffffffffffffffffffffffffffff
    I1225 13:08:44.209713   38216 grpc_verifier.go:706]      PCR: 21, verified: true value: ffffffffffffffffffffffffffffffffffffffff
    I1225 13:08:44.209719   38216 grpc_verifier.go:706]      PCR: 22, verified: true value: ffffffffffffffffffffffffffffffffffffffff
    I1225 13:08:44.209724   38216 grpc_verifier.go:706]      PCR: 23, verified: true value: 0000000000000000000000000000000000000000
    I1225 13:08:44.209736   38216 grpc_verifier.go:706]      PCR: 0, verified: true value: a0b5ff3383a1116bd7dc6df177c0c2d433b9ee1813ea958fa5d166a202cb2a85
    I1225 13:08:44.209742   38216 grpc_verifier.go:706]      PCR: 1, verified: true value: c463da3e0c59a48f6a6ebcdbff4beadb648500b8d6efaa49b87d6a000d23c3ec
    I1225 13:08:44.209747   38216 grpc_verifier.go:706]      PCR: 2, verified: true value: 3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969
    I1225 13:08:44.209753   38216 grpc_verifier.go:706]      PCR: 3, verified: true value: 3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969
    I1225 13:08:44.209758   38216 grpc_verifier.go:706]      PCR: 4, verified: true value: a823fe03561e2cd9f2481ca450cbe637ef93551bda02935299d419c1bb5ccae1
    I1225 13:08:44.209767   38216 grpc_verifier.go:706]      PCR: 5, verified: true value: 8f772fe8ba0f52cfd8c0717a5d7167c507009af500525704e8211bf00d0fb4e3
    I1225 13:08:44.209773   38216 grpc_verifier.go:706]      PCR: 6, verified: true value: 3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969
    I1225 13:08:44.209778   38216 grpc_verifier.go:706]      PCR: 7, verified: true value: 59ce152eb723a82c172b04dc3628c799f2ce322c328d75f30e1a9f01233cb4bb
    I1225 13:08:44.209784   38216 grpc_verifier.go:706]      PCR: 8, verified: true value: 8fcfd00746a287d050231a22855499f33ceaeb0afab032fafcf5ef48796024fd
    I1225 13:08:44.209789   38216 grpc_verifier.go:706]      PCR: 9, verified: true value: 73827fab9ea3aebc47a74649e35fd5a7fdab54b4149e3a772fcbf3329da04949
    I1225 13:08:44.209794   38216 grpc_verifier.go:706]      PCR: 10, verified: true value: da4b74370b7970b13c8372420272d73a810ed9f201c2a609dc1f18badb57651d
    I1225 13:08:44.209799   38216 grpc_verifier.go:706]      PCR: 11, verified: true value: 0000000000000000000000000000000000000000000000000000000000000000
    I1225 13:08:44.209804   38216 grpc_verifier.go:706]      PCR: 12, verified: true value: 0000000000000000000000000000000000000000000000000000000000000000
    I1225 13:08:44.209815   38216 grpc_verifier.go:706]      PCR: 13, verified: true value: 0000000000000000000000000000000000000000000000000000000000000000
    I1225 13:08:44.209820   38216 grpc_verifier.go:706]      PCR: 14, verified: true value: 306f9d8b94f17d93dc6e7cf8f5c79d652eb4c6c4d13de2dddc24af416e13ecaf
    I1225 13:08:44.209831   38216 grpc_verifier.go:706]      PCR: 15, verified: true value: 0000000000000000000000000000000000000000000000000000000000000000
    I1225 13:08:44.209836   38216 grpc_verifier.go:706]      PCR: 16, verified: true value: 0000000000000000000000000000000000000000000000000000000000000000
    I1225 13:08:44.209841   38216 grpc_verifier.go:706]      PCR: 17, verified: true value: ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    I1225 13:08:44.209852   38216 grpc_verifier.go:706]      PCR: 18, verified: true value: ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    I1225 13:08:44.209857   38216 grpc_verifier.go:706]      PCR: 19, verified: true value: ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    I1225 13:08:44.209865   38216 grpc_verifier.go:706]      PCR: 20, verified: true value: ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    I1225 13:08:44.209870   38216 grpc_verifier.go:706]      PCR: 21, verified: true value: ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    I1225 13:08:44.209883   38216 grpc_verifier.go:706]      PCR: 22, verified: true value: ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    I1225 13:08:44.209901   38216 grpc_verifier.go:706]      PCR: 23, verified: true value: 0000000000000000000000000000000000000000000000000000000000000000
    I1225 13:08:44.209907   38216 grpc_verifier.go:706]      PCR: 0, verified: true value: 46384721a6cbbb845096ccf31553e49e0ee2f5f7a488e0d98ca676aaab6ebbb30888a5424d90d9eccbf59f461db8da35
    I1225 13:08:44.209917   38216 grpc_verifier.go:706]      PCR: 1, verified: true value: a4520d955c3839d5a9ad753794cf1a125d84d3856d845ca9bf0950451dfc5db2f22e1a206002af1be64f154cd3cf74e6
    I1225 13:08:44.209923   38216 grpc_verifier.go:706]      PCR: 2, verified: true value: 518923b0f955d08da077c96aaba522b9decede61c599cea6c41889cfbea4ae4d50529d96fe4d1afdafb65e7f95bf23c4
    I1225 13:08:44.209928   38216 grpc_verifier.go:706]      PCR: 3, verified: true value: 518923b0f955d08da077c96aaba522b9decede61c599cea6c41889cfbea4ae4d50529d96fe4d1afdafb65e7f95bf23c4
    I1225 13:08:44.209933   38216 grpc_verifier.go:706]      PCR: 4, verified: true value: 81d23b6b7dcbb8fd4df6d3bd7bcdff230de47d1de4e1bd41ae85854518f80ca9b6e8653d45d567f98b05aa5b3af397fe
    I1225 13:08:44.209939   38216 grpc_verifier.go:706]      PCR: 5, verified: true value: d16e6072e84bead5b1c524c87f07c778893883fa446f28470eec7a454aabcf32b167c35af73076398e38e1498b73f772
    I1225 13:08:44.209944   38216 grpc_verifier.go:706]      PCR: 6, verified: true value: 518923b0f955d08da077c96aaba522b9decede61c599cea6c41889cfbea4ae4d50529d96fe4d1afdafb65e7f95bf23c4
    I1225 13:08:44.209949   38216 grpc_verifier.go:706]      PCR: 7, verified: true value: 0153800a9b64131320ca65dc410ac503ec49de0121b0fcb51b55e33f8833d4994067ec2b94193b65ab49f759bc5b41dd
    I1225 13:08:44.209958   38216 grpc_verifier.go:706]      PCR: 8, verified: true value: 2e69e332006cb6591d2abe90d602b18392e6a4b67af49bc4d25f513699172a64571484756b68e3b7bac8b862c9ce9332
    I1225 13:08:44.209964   38216 grpc_verifier.go:706]      PCR: 9, verified: true value: 65fccce4428b54c08c8a4d44e68e6db32638edfb02512b99a26bdf04096028d1cdfdc5671774dff8d2c7bc731d7364a9
    I1225 13:08:44.209970   38216 grpc_verifier.go:706]      PCR: 10, verified: true value: 2cf9998f128407522e691d4bb129946e85938f23a8288a1a1e5d785c0889f51ca8d560da5f6394721038668101b17bff
    I1225 13:08:44.209976   38216 grpc_verifier.go:706]      PCR: 11, verified: true value: 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
    I1225 13:08:44.209981   38216 grpc_verifier.go:706]      PCR: 12, verified: true value: 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
    I1225 13:08:44.209986   38216 grpc_verifier.go:706]      PCR: 13, verified: true value: 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
    I1225 13:08:44.209991   38216 grpc_verifier.go:706]      PCR: 14, verified: true value: 937437d07298010015f4598395c9f8dc202ef36e0be3897bba89874bf612b5da092beadfe37f79714a60193819e384ad
    I1225 13:08:44.209997   38216 grpc_verifier.go:706]      PCR: 15, verified: true value: 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
    I1225 13:08:44.210008   38216 grpc_verifier.go:706]      PCR: 16, verified: true value: 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
    I1225 13:08:44.210013   38216 grpc_verifier.go:706]      PCR: 17, verified: true value: ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    I1225 13:08:44.210023   38216 grpc_verifier.go:706]      PCR: 18, verified: true value: ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    I1225 13:08:44.210028   38216 grpc_verifier.go:706]      PCR: 19, verified: true value: ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    I1225 13:08:44.210043   38216 grpc_verifier.go:706]      PCR: 20, verified: true value: ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    I1225 13:08:44.210049   38216 grpc_verifier.go:706]      PCR: 21, verified: true value: ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    I1225 13:08:44.210054   38216 grpc_verifier.go:706]      PCR: 22, verified: true value: ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    I1225 13:08:44.210059   38216 grpc_verifier.go:706]      PCR: 23, verified: true value: 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
    I1225 13:08:44.210064   38216 grpc_verifier.go:718]      quotes verified
    I1225 13:08:44.211228   38216 grpc_verifier.go:746]      secureBoot State enabled: [true]
    I1225 13:08:44.212288   38216 grpc_verifier.go:753] =============== end SetQuote ===============
    I1225 13:08:44.339813   38216 grpc_verifier.go:758] ======= SetAttestedKey ========
    I1225 13:08:44.339850   38216 grpc_verifier.go:779]         New PublicKey ========
    I1225 13:08:44.340155   38216 grpc_verifier.go:804]      Key AuthPolicy []
    I1225 13:08:44.340224   38216 grpc_verifier.go:814]      Key TPM Properties mask: 262258
    I1225 13:08:44.340249   38216 grpc_verifier.go:817]      Key Expected Properties mask 262258
    I1225 13:08:44.340300   38216 grpc_verifier.go:850]      key verified 
    -----BEGIN PUBLIC KEY-----
    MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEbIJdg+2OTsskDd1/fMMu/jVoTuYd
    rtZB8wLrsOr4kHwH6ylRLwWtL3E9thjq+EXciXGIbHxTDEeXpeFuu84xqw==
    -----END PUBLIC KEY-----

    I1225 13:08:44.340355   38216 grpc_verifier.go:852] =============== end SetAttestedKey ===============
    I1225 13:08:44.355707   38216 grpc_verifier.go:857] ======= GetCertificate ========
    I1225 13:08:44.355899   38216 grpc_verifier.go:890] Creating public x509
    I1225 13:08:44.358581   38216 grpc_verifier.go:961] =============== end GetCertificate ===============
```

---

### Platform Certificate

he platform certificate returned in this repo is just one generated dynamically by the attestor using a static 'platformCA' certificate and key.

This is *not* what is normally supposed to happen:  the platform certificate would've been issued long ago separte from the remote attestation protocol by the platform Owner itself.

For example, when the hardware device (actual system with the TPM),is setup, the TPM's EK certificate serial number is used as the platform certificate's holder filed:

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

However, just to make it easy, this repo furbishes the platformcertificate in two different ways:

1.  Statically

    The platform certificate used in this protocol is just a sample, static one I downloaded from the [go-attestation testdata](https://github.com/google/go-attestation/tree/master/attributecert/testdata).

    Specifically, [Intel_pc1.cer](https://github.com/google/go-attestation/blob/master/attributecert/testdata/Intel_pc1.cer) which is verified against [IntelSigningKey_20April2017.cer](https://github.com/google/go-attestation/blob/master/attributecert/testdata/IntelSigningKey_20April2017.cer)

2. Dynamically

   With this, the EK cert is read in from the TPM, then an attribute certificate is created and signed by a local CA.

   Again, to emphasize, this is not what is supposed to happen but i'm just doing this to complete the flow.


So, the EK cert and PlatfromCert is tied together by the serial number field:

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
            24:eb:bd:b3:08:6f:8a:ab:e5:d6:91:d5:55:f9:d0:14:e7:5f:29:bb  <<<<<<<<<<<<<<<<<<<<<<
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
     PlatformCertificate Holder.Serial: 24EBBDB3086F8AABE5D691D555F9D014E75F29BB            <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
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

### Issued Certificate Extensions

Note the certificate signed by the Verifier on steps `27` and `28` includes SAN conformal with what the TGC Specs here cover

* `pg 56`: of [TPM 2.0 Keys for Device Identity and Attestation](https://trustedcomputinggroup.org/wp-content/uploads/TPM-2p0-Keys-for-Device-Identity-and-Attestation_v1_r12_pub10082021.pdf)


- `HardwareModuleName`

```text
The hwSerialNum value is an OCTET STRING and SHALL be constructed by one of two methods:
1. When the TPM has an EK Certificate, the hwSerialNum is created by concatenating three ASCII values: The
TCG TPM Manufacturer code, the EK Authority Key Identifier and the EK CertificateSerialNumber. These three
fields SHALL be separated by a colon (‘:’) character. The three values SHALL be listed in the order specified
above.
2. When the TPM does not have an EK certificate, the hwSerialNum is a digest of the EK Certificate public key. 
```

[TCG TPM Vendor ID Registry Family 1.2 and 2.0](https://trustedcomputinggroup.org/wp-content/uploads/TCG-TPM-Vendor-ID-Registry-Family-1.2-and-2.0-Version-1.07-Revision-0.02_pub.pdf)

- `PermanentIdentifier`

```text
The identifierValue is constructed by one of the following methods:
1. When the TPM has an EK certificate, the identifierValue is a digest of the DER form of the TPM EK certificate,
which is then converted to hexadecimal form using the UTF8 character set.
2. When the TPM does not have an EK certificate, the identifierValue is a digest of a concatenation of the UTF8
string “EkPubkey” (terminating NULL not included) with the binary EK public key. 
```

```bash
cat issued_cert.pem
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

$ certtool -i --infile issued_cert.pem 

X.509 Certificate Information:
	Version: 3
	Serial Number (hex): 00f7916707fff552221b94cbf131fb00ce
	Issuer: CN=Single Root CA,OU=Enterprise,O=Google,C=US
	Validity:
		Not Before: Sun Apr 12 18:06:34 UTC 2026
		Not After: Mon Apr 13 18:06:34 UTC 2026
	Subject: CN=mytpm,OU=Enterprise,O=Acme Co,L=Mountain View,ST=California,C=US
	Subject Public Key Algorithm: EC/ECDSA
	Algorithm Security Level: High (256 bits)
		Curve:	SECP256R1
		X:
			00:fe:72:dc:ed:fe:c4:d4:b2:ca:12:ea:28:74:1e:80
			da:e2:cc:aa:7e:b0:a4:ad:3a:74:81:6d:c6:b0:60:cb
			d5
		Y:
			3c:15:1e:85:ae:28:bf:2b:19:b2:f8:8e:43:b9:e7:de
			30:6c:4b:af:8b:da:13:61:6a:e3:73:74:05:2d:69:2b
	Extensions:
		Key Usage (critical):
			Digital signature.
		Basic Constraints (critical):
			Certificate Authority (CA): FALSE
		Authority Key Identifier (not critical):
			ecf0ea53533f9f23dcc10e31103707dedee76ef3
		Subject Alternative Name (not critical):
			otherName OID: 1.3.6.1.5.5.7.8.4
			otherName DER: 301e841c53494d303a2f6d51db7736ecb92dcde2278031c8b1ecc387b43a04c0
			otherName ASCII: 0...SIM0:/mQ.w6..-..'.1......:..
			otherName OID: 1.3.6.1.5.5.7.8.3
			otherName DER: 30420c4062366661333462383432303763643063363965356136373439323938666331373834313530656233373763643864626266316666383761356133653536656562
			otherName ASCII: 0B.@b6fa34b84207cd0c69e5a6749298fc1784150eb377cd8dbbf1ff87a5a3e56eeb
	Signature Algorithm: RSA-SHA256
	Signature:
		7d:e0:cc:a3:29:56:6f:a2:fb:75:62:2c:14:ae:34:88
		33:5c:dc:e8:59:3e:6b:07:89:f4:42:3b:fd:b5:75:e3
		e8:64:0c:24:7f:27:0a:48:ed:44:ab:98:d5:e5:2d:43
		ed:36:68:76:ad:9d:d0:c3:7a:22:c5:ac:f1:05:ef:1a
		50:45:26:9c:0a:78:a0:b3:9b:e0:55:70:c3:64:d7:0f
		9f:4a:26:b0:a0:b9:61:ab:2c:1d:21:ad:e1:77:5a:c1
		4e:37:bc:ff:90:09:10:fc:aa:d8:d3:0e:71:1d:cb:3c
		f0:ed:df:ea:ee:5f:78:6c:a6:37:55:c4:44:07:8a:15
		80:7c:95:59:01:c3:bc:7b:8b:60:80:4f:6f:1f:f7:ee
		63:3f:0c:20:f1:2d:52:80:cb:2a:d7:cd:61:02:21:cf
		bb:b6:24:cf:22:7d:b9:de:6f:a2:af:4d:e4:b1:e8:17
		3a:e1:eb:ce:87:7f:6f:56:ae:f2:ba:11:20:f7:f6:a5
		1a:83:cd:9f:e2:0a:54:9f:1d:36:24:51:6a:1c:fc:80
		1d:99:e6:f0:7e:b5:c7:37:1a:57:af:c4:20:15:49:4e
		58:f2:c4:70:e3:ca:5f:2e:d6:d3:b9:0c:3c:dd:5a:2a
		27:1c:77:6e:78:4b:5a:75:c7:84:16:24:40:0f:f7:8b
Other Information:
	Fingerprint:
		sha1:de1680e370802a4002ab359e2b217f74aa154276
		sha256:88af704e0b7613b41e12a6d3ece22d97f659a2b4e01aceab954155eb9a234601
	Public Key ID:
		sha1:367bb94f1ce29a2147211a2817d1f18b8a523136
		sha256:23ab5632d99652bcf7162cb9f70035017a1c3662bd37f33b023ce9d77a459fb9
	Public Key PIN:
		pin-sha256:I6tWMtmWUrz3Fiy59wA1AXocNmK9N/M7Ajzp13pFn7k=

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
```

### Applications

This is just an academic exercise (so do not use the code as is).   However, some applications of this


- [TPM based Google Service Account Credentials](https://github.com/salrashid123/oauth2#usage-tpmtokensource)
- [TPM based mTLS](https://github.com/salrashid123/signer#usage-tls)
- [Trusted Platform Module (TPM) recipes with tpm2_tools and go-tpm](https://github.com/salrashid123/tpm2)
