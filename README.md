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

As you can see, the whole protocol is rather complicated but hinges on being able to trust the initial Endorsement Key.   As mentioned, this is normally done by validating that the EndorsementPublic certificate is infact real and signed by a 3rd party (eg, the manufacturer of the TPM).  In the case of google's shielded vTPM, it is signed by google's subordinate CA and includes information about the VM's instance_id value.

---

also see

 - [go-attestation](https://github.com/google/go-attestation)


## Setup

We will use a GCP Shielded VM for these tests 

First create two VMs

```bash
gcloud compute instances create attestor \
  --zone=us-central1-a --machine-type=e2-medium --no-service-account --no-scopes \
  --image=debian-10-buster-v20210817 --image-project=debian-cloud  \
  --shielded-secure-boot --shielded-vtpm --shielded-integrity-monitoring

gcloud compute instances create verifier \
  --zone=us-central1-a --machine-type=e2-medium --no-service-account --no-scopes \
  --image=debian-10-buster-v20210817 --image-project=debian-cloud  \
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
$ go run src/grpc_attestor.go --grpcport :50051 \
 --caCertTLS certs/CA_crt.pem --servercert certs/server_crt.pem \
 --serverkey certs/server_key.pem --pcr=0 --v=10 -alsologtostderr

I0906 15:59:52.870938   16695 grpc_attestor.go:1119] Starting gRPC server on port :50051
I0906 16:02:42.151385   16695 grpc_attestor.go:126] >> inbound request
I0906 16:02:42.151418   16695 grpc_attestor.go:146] HealthCheck called for Service [verifier.VerifierServer]
I0906 16:02:42.152887   16695 grpc_attestor.go:126] >> inbound request
I0906 16:02:42.152911   16695 grpc_attestor.go:160] ======= GetPlatformCert ========
I0906 16:02:42.152947   16695 grpc_attestor.go:161]      client provided uid: 369c327d-ad1f-401c-aa91-d9b0e69bft67
I0906 16:02:42.168326   16695 grpc_attestor.go:170]      TPM Manufacturer: GOOG
CERTIFICATE
I0906 16:02:42.168622   16695 grpc_attestor.go:185]      Found Platform Cert Issuer CN=tpm_ek_v1_cloud_host_root-signer-0-2018-04-06T10:58:26-07:00 K:1\, 1:Pw003HsFYO4:0:18,OU=Cloud,O=Google LLC,L=Mountain View,ST=California,C=US ========
I0906 16:02:42.168643   16695 grpc_attestor.go:186]      Returning GetPlatformCert ========
I0906 16:02:42.169575   16695 grpc_attestor.go:126] >> inbound request
I0906 16:02:42.169596   16695 grpc_attestor.go:194] ======= GetEKCert ========
I0906 16:02:42.169605   16695 grpc_attestor.go:195]      client provided uid: 369c327d-ad1f-401c-aa91-d9b0e69bft67
I0906 16:02:42.169612   16695 grpc_attestor.go:201] =============== Load EncryptionKey and Certifcate from NV ===============
I0906 16:02:42.175201   16695 grpc_attestor.go:217]      Encryption PEM 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwsY6zrTncJqdkbccZuoe
2eyDcvd2FzsCBDCyD6E31O2vMmy0Co/w8sqDutyeTZ4N6LvirGSdQxNZ/iv5nLRB
nlUXiJi8Spxz9FvtHoNN4ptmveqDvRl2l6NkxHZBIxLxPi0k9zmpbb5iqHcDqkyz
iQlPnWZDZMBZTnY2pOHOzn7c7qR/uuwsMxIUCXH8g93YL00b7mn53GiBn9rqg2L1
GcioHkfu8dROyoTUhrRn56ap4bwI0LsoGwiMfSw2ITFsJXHFkXcshe2ev+z29jHd
LspYW5wt+FEm1c1IYS076L4dk+yEUVZZ1JQ3iaHKn3/KDb5d5/1+yz1heBEdz83e
ZwIDAQAB
-----END PUBLIC KEY-----
I0906 16:02:42.189594   16695 grpc_attestor.go:235]      Encryption Issuer x509 tpm_ek_v1_cloud_host-signer-0-2020-10-22T14:02:08-07:00 K:1, 2:HBNpA3TPAbM:0:18
I0906 16:02:42.189627   16695 grpc_attestor.go:236]      Returning GetEKCert ========
I0906 16:02:42.190883   16695 grpc_attestor.go:126] >> inbound request
I0906 16:02:42.190909   16695 grpc_attestor.go:244] ======= GetAK ========
I0906 16:02:42.190915   16695 grpc_attestor.go:245]      client provided uid: 369c327d-ad1f-401c-aa91-d9b0e69bft67
I0906 16:02:42.192728   16695 grpc_attestor.go:252]      Current PCR 0 Value 24af52a4f429b71a3184a6d64cddad17e54ea030e2aa6576bf3a5a3d8bd3328f
I0906 16:02:42.192758   16695 grpc_attestor.go:257]      createPrimary
I0906 16:02:42.305726   16695 grpc_attestor.go:288]      ekPub Name: 000b4bd5d7f30dc3a1975ae9529404f2ec73ae5a404669c5e87d74186fa2a4c280db
I0906 16:02:42.305772   16695 grpc_attestor.go:289]      ekPubPEM: 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwsY6zrTncJqdkbccZuoe
2eyDcvd2FzsCBDCyD6E31O2vMmy0Co/w8sqDutyeTZ4N6LvirGSdQxNZ/iv5nLRB
nlUXiJi8Spxz9FvtHoNN4ptmveqDvRl2l6NkxHZBIxLxPi0k9zmpbb5iqHcDqkyz
iQlPnWZDZMBZTnY2pOHOzn7c7qR/uuwsMxIUCXH8g93YL00b7mn53GiBn9rqg2L1
GcioHkfu8dROyoTUhrRn56ap4bwI0LsoGwiMfSw2ITFsJXHFkXcshe2ev+z29jHd
LspYW5wt+FEm1c1IYS076L4dk+yEUVZZ1JQ3iaHKn3/KDb5d5/1+yz1heBEdz83e
ZwIDAQAB
-----END PUBLIC KEY-----
I0906 16:02:42.305810   16695 grpc_attestor.go:296]      CreateKeyUsingAuth
I0906 16:02:42.456327   16695 grpc_attestor.go:336]      ContextSave (ek)
I0906 16:02:42.467327   16695 grpc_attestor.go:347]      ContextLoad (ek)
I0906 16:02:42.476754   16695 grpc_attestor.go:358]      LoadUsingAuth
I0906 16:02:42.484828   16695 grpc_attestor.go:386]      AK keyName 0022000ba646ae5a0111d66ec5ad26bd559dc7caad94ba0a3f15376fed9d090d377a3433
I0906 16:02:42.488658   16695 grpc_attestor.go:408]      akPubPEM: 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5HCNm4gQ+2jeq0Lb0PSt
NR96/X9/IkMVZmuLgOaVl69fnZJ80v5oUBd8cLexe/8UBdkMS36U/SfGsEYVZVIy
9X+gSZpV/g7o/WE3yvVmz7n4Gpt6CCbx9TeHsV27k7iIc2DgUZFL5oAqr6eOzvBF
NoABUXmXVnkV/14v3ppTetVeuT5WnK5dIEf8DoHbT3ICTjpIq9571s18iImzOt8V
tp6J+PjLxlNYkMP1gcr6T1Y0OcFlw48TnwbdFYhDIyUZ+lv3DoTdDTGuwyi3uHDW
ph65SkJiCnyXDVFHefgCE8pnGfTssSLP86QOIzwhlihfVSIyigWr+vratH7P2Dxm
nwIDAQAB
-----END PUBLIC KEY-----
I0906 16:02:42.488717   16695 grpc_attestor.go:410]      Write (akPub) ========
I0906 16:02:42.488984   16695 grpc_attestor.go:415]      Write (akPriv) ========
I0906 16:02:42.489133   16695 grpc_attestor.go:425]      Returning GetAK ========
I0906 16:02:42.509771   16695 grpc_attestor.go:126] >> inbound request
I0906 16:02:42.509808   16695 grpc_attestor.go:437] ======= ActivateCredential ========
I0906 16:02:42.509833   16695 grpc_attestor.go:438]      client provided uid: 369c327d-ad1f-401c-aa91-d9b0e69bft67
I0906 16:02:42.509841   16695 grpc_attestor.go:440]      ContextLoad (ek)
I0906 16:02:42.518171   16695 grpc_attestor.go:451]      Read (akPub)
I0906 16:02:42.518364   16695 grpc_attestor.go:456]      Read (akPriv)
I0906 16:02:42.526972   16695 grpc_attestor.go:487]      keyName 0022000ba646ae5a0111d66ec5ad26bd559dc7caad94ba0a3f15376fed9d090d377a3433
I0906 16:02:42.527091   16695 grpc_attestor.go:489]      ActivateCredentialUsingAuth
I0906 16:02:42.539755   16695 grpc_attestor.go:537]      <--  activateCredential()
I0906 16:02:42.548257   16695 grpc_attestor.go:126] >> inbound request
I0906 16:02:42.548322   16695 grpc_attestor.go:547] ======= Quote ========
I0906 16:02:42.548330   16695 grpc_attestor.go:548]      client provided uid: 369c327d-ad1f-401c-aa91-d9b0e69bft67
I0906 16:02:42.550440   16695 grpc_attestor.go:555]      PCR 0 Value 24af52a4f429b71a3184a6d64cddad17e54ea030e2aa6576bf3a5a3d8bd3328f 
I0906 16:02:42.550492   16695 grpc_attestor.go:560]      ContextLoad (ek) ========
I0906 16:02:42.559632   16695 grpc_attestor.go:570]      LoadUsingAuth ========
I0906 16:02:42.563225   16695 grpc_attestor.go:592]      Read (akPub) ========
I0906 16:02:42.563318   16695 grpc_attestor.go:597]      Read (akPriv) ========
I0906 16:02:42.568124   16695 grpc_attestor.go:609]      AK keyName 0022000ba646ae5a0111d66ec5ad26bd559dc7caad94ba0a3f15376fed9d090d377a3433
I0906 16:02:42.575422   16695 grpc_attestor.go:624]      <-- End Quote
I0906 16:02:42.587605   16695 grpc_attestor.go:126] >> inbound request
I0906 16:02:42.587646   16695 grpc_attestor.go:636] ======= PushSecret ========
I0906 16:02:42.587715   16695 grpc_attestor.go:637]      client provided uid: 369c327d-ad1f-401c-aa91-d9b0e69bft67
I0906 16:02:42.587724   16695 grpc_attestor.go:640]      Loading EndorsementKeyRSA
I0906 16:02:42.594288   16695 grpc_attestor.go:655]      Importing External Key
I0906 16:02:42.616577   16695 grpc_attestor.go:660]      <-- End importKey()
I0906 16:02:42.616635   16695 grpc_attestor.go:664]      Hash of imported Key bZeQ9G0KuKpHVwfZuobcMf7tL/ViU1maVaJCAY+QjfU=
I0906 16:02:42.621055   16695 grpc_attestor.go:126] >> inbound request
I0906 16:02:42.621095   16695 grpc_attestor.go:746] ======= PullRSAKey ========
I0906 16:02:42.621113   16695 grpc_attestor.go:747]      client provided uid: 369c327d-ad1f-401c-aa91-d9b0e69bft67
I0906 16:02:42.621128   16695 grpc_attestor.go:749] ======= Generate UnrestrictedKey ========
I0906 16:02:42.621134   16695 grpc_attestor.go:751]      ContextLoad (ek) ========
I0906 16:02:42.629578   16695 grpc_attestor.go:762]      Loading AttestationKey
I0906 16:02:42.638447   16695 grpc_attestor.go:798]      AK keyName: ACIAC6ZGrloBEdZuxa0mvVWdx8qtlLoKPxU3b+2dCQ03ejQz,
I0906 16:02:42.640042   16695 grpc_attestor.go:822]      akPub PEM 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5HCNm4gQ+2jeq0Lb0PSt
NR96/X9/IkMVZmuLgOaVl69fnZJ80v5oUBd8cLexe/8UBdkMS36U/SfGsEYVZVIy
9X+gSZpV/g7o/WE3yvVmz7n4Gpt6CCbx9TeHsV27k7iIc2DgUZFL5oAqr6eOzvBF
NoABUXmXVnkV/14v3ppTetVeuT5WnK5dIEf8DoHbT3ICTjpIq9571s18iImzOt8V
tp6J+PjLxlNYkMP1gcr6T1Y0OcFlw48TnwbdFYhDIyUZ+lv3DoTdDTGuwyi3uHDW
ph65SkJiCnyXDVFHefgCE8pnGfTssSLP86QOIzwhlihfVSIyigWr+vratH7P2Dxm
nwIDAQAB
-----END PUBLIC KEY-----
I0906 16:02:42.640101   16695 grpc_attestor.go:826]      ======= CreateKeyUsingAuthUnrestricted ========
I0906 16:02:42.645249   16695 grpc_attestor.go:856]      PCR 0 Value 24af52a4f429b71a3184a6d64cddad17e54ea030e2aa6576bf3a5a3d8bd3328f 
I0906 16:02:42.743985   16695 grpc_attestor.go:872]      Write (ukPub) ========
I0906 16:02:42.744223   16695 grpc_attestor.go:877]      Write (ukPriv) ========
I0906 16:02:42.754539   16695 grpc_attestor.go:933]      uakPub PEM 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5NuN4iA65YkAy77DcHt7
Z4+vMNUKl9VmrPS+xck/GmLhabIWeLPN0TRTFg9fPrpvIPcr9DNuug5s42OAI1Ej
jkNNUIStE6Y65n4R3vtA5OYqC+DOXgIQA5YPlQnDMjv15DKmwJqK3WsvL3ZPUMOF
wQVqk1avaMy/vuz/u+7vIGydt8PKU+pDr7Zs1W7/9LMrbf4qUYPCuyT8TcHs8olD
U+5ozzQbazZq9RF9dWcesTEJkIt224Sp3pv2ROc5Y2O23W3g//Mch6EEuGg+Mc1Z
7+DFwwpGgiErjUoxLs17E6Om060Rjxa7ztTYCUZNWirWl5IffSdGPED62Ph0hrp/
1wIDAQAB
-----END PUBLIC KEY-----
I0906 16:02:42.762546   16695 grpc_attestor.go:948]      Data to sign: 369c327d-ad1f-401c-aa91-d9b0e69bft67
I0906 16:02:42.771708   16695 grpc_attestor.go:962]      Test Signature:  zhe5rznT1oAhdZBxhdQZgPZY5JzMoxTe69QofwKpEjI2OEy980eik4uREZJVqX7nP95i4N4REcCQplaTruruBtVDgLnacdjZJTn7hgI+YR72mD52Eyzu8WEbLdNXyuTiastwB0NRiKhnrhofzUowajdpT9DKDOsYktx3Z3DErcVtBIUUpKIyKPKwFT+KZNQRrJkE4phl6gNwfIUYLXNg8BDbvCah7kEPvLW/DLlMHZjXc2ZRjHZICKD71OiP1ZQmsEAc2cZzEM+5N4XNHWSKIIOpHYr1EVEGbcfFmLjpJvK5AOXn6ELySQYaYAvBmBak7mbuJrETVbLug1W8bd+iBQ
I0906 16:02:42.771863   16695 grpc_attestor.go:1010]      Decoding PublicKey for AK ========
I0906 16:02:42.772054   16695 grpc_attestor.go:1036]      Attestation Verified
I0906 16:02:42.772084   16695 grpc_attestor.go:1045]      Returning PullRSAKeyResponse
```

#### Verifier AES

```log
$ go run src/grpc_verifier.go --importMode=AES  --uid 369c327d-ad1f-401c-aa91-d9b0e69bft67 \
   -aes256Key "G-KaPdSgUkXp2s5v8y/B?E(H+MbQeThW" --expectedPCRSHA1 0f2d3a2a1adaa479aeeca8f5df76aadc41b862ea \
   --host verify.esodemoapp2.com:50051 --pcr=0 --expectedPCRValue 24af52a4f429b71a3184a6d64cddad17e54ea030e2aa6576bf3a5a3d8bd3328f \
   --caCertTLS certs/CA_crt.pem --caCertIssuer certs/CA_crt.pem --caKeyIssuer certs/CA_key.pem \
   --v=10 -alsologtostderr 

I0906 16:02:42.152001   15283 grpc_verifier.go:143] RPC HealthChekStatus:SERVING
I0906 16:02:42.152307   15283 grpc_verifier.go:147] =============== GetPlatformCert ===============
I0906 16:02:42.168990   15283 grpc_verifier.go:156] =============== GetPlatformCert Returned from remote ===============
I0906 16:02:42.169104   15283 grpc_verifier.go:174]     Platform Cert Issuer tpm_ek_v1_cloud_host_root-signer-0-2018-04-06T10:58:26-07:00 K:1, 1:Pw003HsFYO4:0:18
I0906 16:02:42.190174   15283 grpc_verifier.go:186] =============== GetEKCert Returned from remote ===============
I0906 16:02:42.190288   15283 grpc_verifier.go:204]     EkCert Cert Issuer tpm_ek_v1_cloud_host-signer-0-2020-10-22T14:02:08-07:00 K:1, 2:HBNpA3TPAbM:0:18
I0906 16:02:42.190305   15283 grpc_verifier.go:205]     EkCert Public Key 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwsY6zrTncJqdkbccZuoe
2eyDcvd2FzsCBDCyD6E31O2vMmy0Co/w8sqDutyeTZ4N6LvirGSdQxNZ/iv5nLRB
nlUXiJi8Spxz9FvtHoNN4ptmveqDvRl2l6NkxHZBIxLxPi0k9zmpbb5iqHcDqkyz
iQlPnWZDZMBZTnY2pOHOzn7c7qR/uuwsMxIUCXH8g93YL00b7mn53GiBn9rqg2L1
GcioHkfu8dROyoTUhrRn56ap4bwI0LsoGwiMfSw2ITFsJXHFkXcshe2ev+z29jHd
LspYW5wt+FEm1c1IYS076L4dk+yEUVZZ1JQ3iaHKn3/KDb5d5/1+yz1heBEdz83e
ZwIDAQAB
-----END PUBLIC KEY-----

I0906 16:02:42.190326   15283 grpc_verifier.go:208] =============== GetAKCert ===============
I0906 16:02:42.496886   15283 grpc_verifier.go:220] =============== MakeCredential ===============
I0906 16:02:42.497190   15283 grpc_verifier.go:242]      Decoded EkPublic Key: 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwsY6zrTncJqdkbccZuoe
2eyDcvd2FzsCBDCyD6E31O2vMmy0Co/w8sqDutyeTZ4N6LvirGSdQxNZ/iv5nLRB
nlUXiJi8Spxz9FvtHoNN4ptmveqDvRl2l6NkxHZBIxLxPi0k9zmpbb5iqHcDqkyz
iQlPnWZDZMBZTnY2pOHOzn7c7qR/uuwsMxIUCXH8g93YL00b7mn53GiBn9rqg2L1
GcioHkfu8dROyoTUhrRn56ap4bwI0LsoGwiMfSw2ITFsJXHFkXcshe2ev+z29jHd
LspYW5wt+FEm1c1IYS076L4dk+yEUVZZ1JQ3iaHKn3/KDb5d5/1+yz1heBEdz83e
ZwIDAQAB
-----END PUBLIC KEY-----
I0906 16:02:42.501391   15283 grpc_verifier.go:270]      Decoded AkPub: 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5HCNm4gQ+2jeq0Lb0PSt
NR96/X9/IkMVZmuLgOaVl69fnZJ80v5oUBd8cLexe/8UBdkMS36U/SfGsEYVZVIy
9X+gSZpV/g7o/WE3yvVmz7n4Gpt6CCbx9TeHsV27k7iIc2DgUZFL5oAqr6eOzvBF
NoABUXmXVnkV/14v3ppTetVeuT5WnK5dIEf8DoHbT3ICTjpIq9571s18iImzOt8V
tp6J+PjLxlNYkMP1gcr6T1Y0OcFlw48TnwbdFYhDIyUZ+lv3DoTdDTGuwyi3uHDW
ph65SkJiCnyXDVFHefgCE8pnGfTssSLP86QOIzwhlihfVSIyigWr+vratH7P2Dxm
nwIDAQAB
-----END PUBLIC KEY-----
I0906 16:02:42.501688   15283 grpc_verifier.go:273]      AK Default parameter match template
I0906 16:02:42.504941   15283 grpc_verifier.go:282]      Loaded AK KeyName 000ba646ae5a0111d66ec5ad26bd559dc7caad94ba0a3f15376fed9d090d377a3433
I0906 16:02:42.504989   15283 grpc_verifier.go:284]      MakeCredential Start
I0906 16:02:42.505140   15283 grpc_verifier.go:290]      Sending Nonce: GOQJJEiJytwgfXYjgxKAhOXxQtcZdQyw
I0906 16:02:42.508776   15283 grpc_verifier.go:297]      <-- End makeCredential()
I0906 16:02:42.508905   15283 grpc_verifier.go:302] =============== ActivateCredential ===============
I0906 16:02:42.547423   15283 grpc_verifier.go:313]      Returned Secret: GOQJJEiJytwgfXYjgxKAhOXxQtcZdQyw
I0906 16:02:42.547473   15283 grpc_verifier.go:318]      Attestation Complete
I0906 16:02:42.547494   15283 grpc_verifier.go:320] =============== Quote/Verify ===============
I0906 16:02:42.547518   15283 grpc_verifier.go:325]      Sending Quote with Nonce: TgxUbrXEubFeFOpAtIKIZjoOTSiZadwi
I0906 16:02:42.580483   15283 grpc_verifier.go:347]      Attestation ExtraData (nonce): TgxUbrXEubFeFOpAtIKIZjoOTSiZadwi 
I0906 16:02:42.580535   15283 grpc_verifier.go:348]      Attestation PCR#: [0] 
I0906 16:02:42.580575   15283 grpc_verifier.go:349]      Attestation Hash: 2ba7022b59f2158786ea3ea29a7ad12ff0c6c9d6682da6555d8926075b643b1f 
I0906 16:02:42.580606   15283 grpc_verifier.go:365]      Expected PCR Value:           --> 24af52a4f429b71a3184a6d64cddad17e54ea030e2aa6576bf3a5a3d8bd3328f
I0906 16:02:42.580625   15283 grpc_verifier.go:366]      sha256 of Expected PCR Value: --> 2ba7022b59f2158786ea3ea29a7ad12ff0c6c9d6682da6555d8926075b643b1f
I0906 16:02:42.580650   15283 grpc_verifier.go:372]      Decoding PublicKey for AK ========
I0906 16:02:42.580805   15283 grpc_verifier.go:386]      Attestation Signature Verified 
I0906 16:02:42.580833   15283 grpc_verifier.go:388]      Reading EventLog
I0906 16:02:42.580949   15283 grpc_verifier.go:403]      Event Type EV_S_CRTM_VERSION
I0906 16:02:42.581005   15283 grpc_verifier.go:404]      PCR Index 0
I0906 16:02:42.581051   15283 grpc_verifier.go:405]      Event Data 47004300450020005600690072007400750061006c0020004600690072006d0077006100720065002000760031000000
I0906 16:02:42.581133   15283 grpc_verifier.go:406]      Event Digest 3f708bdbaff2006655b540360e16474c100c1310
I0906 16:02:42.581176   15283 grpc_verifier.go:403]      Event Type EV_NONHOST_INFO
I0906 16:02:42.581221   15283 grpc_verifier.go:404]      PCR Index 0
I0906 16:02:42.581275   15283 grpc_verifier.go:405]      Event Data 474345204e6f6e486f7374496e666f0000000000000000000000000000000000
I0906 16:02:42.581322   15283 grpc_verifier.go:406]      Event Digest 9e8af742718df04092551f27c117723769acfe7e
I0906 16:02:42.581368   15283 grpc_verifier.go:403]      Event Type EV_SEPARATOR
I0906 16:02:42.581417   15283 grpc_verifier.go:404]      PCR Index 0
I0906 16:02:42.581464   15283 grpc_verifier.go:405]      Event Data 00000000
I0906 16:02:42.581514   15283 grpc_verifier.go:406]      Event Digest 9069ca78e7450a285173431b3e52c5c25299e473
I0906 16:02:42.581546   15283 grpc_verifier.go:408]      EventLog Verified 
I0906 16:02:42.581573   15283 grpc_verifier.go:414]      Generate Test Certificate for AK 
I0906 16:02:42.586338   15283 grpc_verifier.go:483]      X509 issued by Verifier for Ak: 
-----BEGIN CERTIFICATE-----
MIID1TCCAr2gAwIBAgIRAIwMVX0rfs+T0Q0ERVb/iX8wDQYJKoZIhvcNAQELBQAw
bzELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExFjAUBgNVBAcTDU1v
dW50YWluIFZpZXcxDzANBgNVBAoTBkdvb2dsZTETMBEGA1UECxMKRW50ZXJwcmlz
ZTENMAsGA1UEAxMETXlDQTAeFw0yMTA5MDYxNjAyNDJaFw0yMjA5MDYxNjAyNDJa
MIGCMQswCQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTEWMBQGA1UEBxMN
TW91bnRhaW4gVmlldzEQMA4GA1UEChMHQWNtZSBDbzETMBEGA1UECxMKRW50ZXJw
cmlzZTEfMB0GA1UEAxMWdmVyaWZ5LmVzb2RlbW9hcHAyLmNvbTCCASIwDQYJKoZI
hvcNAQEBBQADggEPADCCAQoCggEBAORwjZuIEPto3qtC29D0rTUfev1/fyJDFWZr
i4DmlZevX52SfNL+aFAXfHC3sXv/FAXZDEt+lP0nxrBGFWVSMvV/oEmaVf4O6P1h
N8r1Zs+5+Bqbeggm8fU3h7Fdu5O4iHNg4FGRS+aAKq+njs7wRTaAAVF5l1Z5Ff9e
L96aU3rVXrk+VpyuXSBH/A6B209yAk46SKvee9bNfIiJszrfFbaeifj4y8ZTWJDD
9YHK+k9WNDnBZcOPE58G3RWIQyMlGfpb9w6E3Q0xrsMot7hw1qYeuUpCYgp8lw1R
R3n4AhPKZxn07LEiz/OkDiM8IZYoX1UiMooFq/r62rR+z9g8Zp8CAwEAAaNYMFYw
DgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMAwGA1UdEwEB/wQC
MAAwIQYDVR0RBBowGIIWdmVyaWZ5LmVzb2RlbW9hcHAyLmNvbTANBgkqhkiG9w0B
AQsFAAOCAQEAllMhEHF01yfvVzMaEm4seowMA3Rti9yTB1rakEhE1oxR+T59e4kC
MiLDRgi5zMePxStbD8nWikbDwquowVYDU3bQ/IBiM3FA4wLKC6NkK/RF0n8neKZm
rmFkDICpm44QEJCEOkuxox3N9mcad/MRWjsyu2pHGwnvGJ9JxDuDHfxofSoUH31N
0XsSsW53OiA6E0HA36YRaDVpLj6mJlUQi7+2IlKdbGLdxhk7rxpychlwjAKnpMQ6
4FOTZ1XBIPmBtip8HxqPmKFCDxVngRtkjBrcdv0OexHP5BLquiud93Jjk+rfwDoW
EzmZOLTwppjsTTT7s1C0Bc83nvTr+0rgdQ==
-----END CERTIFICATE-----
I0906 16:02:42.586390   15283 grpc_verifier.go:485]      <-- End verifyQuote()
I0906 16:02:42.586411   15283 grpc_verifier.go:487] =============== PushSecret ===============
I0906 16:02:42.586430   15283 grpc_verifier.go:489]      Pushing AES
I0906 16:02:42.586731   15283 grpc_verifier.go:521]      Hash of AES Key:  bZeQ9G0KuKpHVwfZuobcMf7tL/ViU1maVaJCAY+QjfU
I0906 16:02:42.620167   15283 grpc_verifier.go:589]      Verification bZeQ9G0KuKpHVwfZuobcMf7tL/ViU1maVaJCAY+QjfU
I0906 16:02:42.620336   15283 grpc_verifier.go:594] =============== PullRSAKey ===============
I0906 16:02:42.780942   15283 grpc_verifier.go:625]      Attestation of Unrestricted Signing Key Verified
I0906 16:02:42.781080   15283 grpc_verifier.go:646]      uakPub PEM 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5NuN4iA65YkAy77DcHt7
Z4+vMNUKl9VmrPS+xck/GmLhabIWeLPN0TRTFg9fPrpvIPcr9DNuug5s42OAI1Ej
jkNNUIStE6Y65n4R3vtA5OYqC+DOXgIQA5YPlQnDMjv15DKmwJqK3WsvL3ZPUMOF
wQVqk1avaMy/vuz/u+7vIGydt8PKU+pDr7Zs1W7/9LMrbf4qUYPCuyT8TcHs8olD
U+5ozzQbazZq9RF9dWcesTEJkIt224Sp3pv2ROc5Y2O23W3g//Mch6EEuGg+Mc1Z
7+DFwwpGgiErjUoxLs17E6Om060Rjxa7ztTYCUZNWirWl5IffSdGPED62Ph0hrp/
1wIDAQAB
-----END PUBLIC KEY-----
I0906 16:02:42.781266   15283 grpc_verifier.go:651]      SigningKey Test Signature zhe5rznT1oAhdZBxhdQZgPZY5JzMoxTe69QofwKpEjI2OEy980eik4uREZJVqX7nP95i4N4REcCQplaTruruBtVDgLnacdjZJTn7hgI+YR72mD52Eyzu8WEbLdNXyuTiastwB0NRiKhnrhofzUowajdpT9DKDOsYktx3Z3DErcVtBIUUpKIyKPKwFT+KZNQRrJkE4phl6gNwfIUYLXNg8BDbvCah7kEPvLW/DLlMHZjXc2ZRjHZICKD71OiP1ZQmsEAc2cZzEM+5N4XNHWSKIIOpHYr1EVEGbcfFmLjpJvK5AOXn6ELySQYaYAvBmBak7mbuJrETVbLug1W8bd+iBQ==
I0906 16:02:42.781344   15283 grpc_verifier.go:652]      Data to verify signature with: 369c327d-ad1f-401c-aa91-d9b0e69bft67
I0906 16:02:42.781519   15283 grpc_verifier.go:659]      Test Signature Verified
I0906 16:02:42.781628   15283 grpc_verifier.go:680]      Unrestricted RSA Public key parameters matches AttestedCertifyInfo  true
I0906 16:02:42.785967   15283 grpc_verifier.go:718]      X509 issued by Verifier for unrestricted Key: 
-----BEGIN CERTIFICATE-----
MIID0TCCArmgAwIBAgIRAIwMVX0rfs+T0Q0ERVb/iX8wDQYJKoZIhvcNAQELBQAw
bzELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExFjAUBgNVBAcTDU1v
dW50YWluIFZpZXcxDzANBgNVBAoTBkdvb2dsZTETMBEGA1UECxMKRW50ZXJwcmlz
ZTENMAsGA1UEAxMETXlDQTAeFw0yMTA5MDYxNjAyNDJaFw0yMjA5MDYxNjAyNDJa
MIGCMQswCQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTEWMBQGA1UEBxMN
TW91bnRhaW4gVmlldzEQMA4GA1UEChMHQWNtZSBDbzETMBEGA1UECxMKRW50ZXJw
cmlzZTEfMB0GA1UEAxMWdmVyaWZ5LmVzb2RlbW9hcHAyLmNvbTCCASIwDQYJKoZI
hvcNAQEBBQADggEPADCCAQoCggEBAOTbjeIgOuWJAMu+w3B7e2ePrzDVCpfVZqz0
vsXJPxpi4WmyFnizzdE0UxYPXz66byD3K/QzbroObONjgCNRI45DTVCErROmOuZ+
Ed77QOTmKgvgzl4CEAOWD5UJwzI79eQypsCait1rLy92T1DDhcEFapNWr2jMv77s
/7vu7yBsnbfDylPqQ6+2bNVu//SzK23+KlGDwrsk/E3B7PKJQ1PuaM80G2s2avUR
fXVnHrExCZCLdtuEqd6b9kTnOWNjtt1t4P/zHIehBLhoPjHNWe/gxcMKRoIhK41K
MS7NexOjptOtEY8Wu87U2AlGTVoq1peSH30nRjxA+tj4dIa6f9cCAwEAAaNUMFIw
DgYDVR0PAQH/BAQDAgeAMA8GA1UdJQQIMAYGBFUdJQAwDAYDVR0TAQH/BAIwADAh
BgNVHREEGjAYghZ2ZXJpZnkuZXNvZGVtb2FwcDIuY29tMA0GCSqGSIb3DQEBCwUA
A4IBAQBQSU62JE7kOa7XdbZMtJSjGTeeG/7GeetkWav8dSoWOJbpHD5YxDhM9Z3M
ZUh6Bbucidoiz7A2UwtZTH1oVKGrf+b9bLqxKCNf/jSzIEgzvyQgNOfJKG2ZCNVY
M473NehW38fgzOcAzjYPo/w4EPa5rw1y4XAZ8oRmrZlDt6K8VBy5iYhPWzleUARe
z9dt2XIthttt7wBORTbAzc8pWJvecwSeG/3jHtw8uWOj7VYmFxgttvfIyNtiz5RN
DGm6iLHK8GyKDYpl+8Mkzbyvj1+Pb2dnJACx6lUYXT6O8uwMYwE4mO07ngxJuI8M
z+OH56Eg0ZXW2cShe30i/zQsAIj+
-----END CERTIFICATE-----
I0906 16:02:42.786188   15283 grpc_verifier.go:720]      Pulled Signing Key  complete 369c327d-ad1f-401c-aa91-d9b0e69bft67
```

### RSA

#### Attestor RSA

```log
$ go run src/grpc_attestor.go --grpcport :50051 --caCertTLS certs/CA_crt.pem \
  --servercert certs/server_crt.pem \
  --serverkey certs/server_key.pem --pcr=0 \
  --v=10 -alsologtostderr

I0906 16:03:29.762952   16742 grpc_attestor.go:1119] Starting gRPC server on port :50051
I0906 16:03:39.265298   16742 grpc_attestor.go:126] >> inbound request
I0906 16:03:39.265330   16742 grpc_attestor.go:146] HealthCheck called for Service [verifier.VerifierServer]
I0906 16:03:39.266689   16742 grpc_attestor.go:126] >> inbound request
I0906 16:03:39.266715   16742 grpc_attestor.go:160] ======= GetPlatformCert ========
I0906 16:03:39.266723   16742 grpc_attestor.go:161]      client provided uid: 369c327d-ad1f-401c-aa91-d9b0e69bft67
I0906 16:03:39.286109   16742 grpc_attestor.go:170]      TPM Manufacturer: GOOG
CERTIFICATE
I0906 16:03:39.286362   16742 grpc_attestor.go:185]      Found Platform Cert Issuer CN=tpm_ek_v1_cloud_host_root-signer-0-2018-04-06T10:58:26-07:00 K:1\, 1:Pw003HsFYO4:0:18,OU=Cloud,O=Google LLC,L=Mountain View,ST=California,C=US ========
I0906 16:03:39.286384   16742 grpc_attestor.go:186]      Returning GetPlatformCert ========
I0906 16:03:39.287527   16742 grpc_attestor.go:126] >> inbound request
I0906 16:03:39.287547   16742 grpc_attestor.go:194] ======= GetEKCert ========
I0906 16:03:39.287552   16742 grpc_attestor.go:195]      client provided uid: 369c327d-ad1f-401c-aa91-d9b0e69bft67
I0906 16:03:39.287572   16742 grpc_attestor.go:201] =============== Load EncryptionKey and Certifcate from NV ===============
I0906 16:03:39.293566   16742 grpc_attestor.go:217]      Encryption PEM 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwsY6zrTncJqdkbccZuoe
2eyDcvd2FzsCBDCyD6E31O2vMmy0Co/w8sqDutyeTZ4N6LvirGSdQxNZ/iv5nLRB
nlUXiJi8Spxz9FvtHoNN4ptmveqDvRl2l6NkxHZBIxLxPi0k9zmpbb5iqHcDqkyz
iQlPnWZDZMBZTnY2pOHOzn7c7qR/uuwsMxIUCXH8g93YL00b7mn53GiBn9rqg2L1
GcioHkfu8dROyoTUhrRn56ap4bwI0LsoGwiMfSw2ITFsJXHFkXcshe2ev+z29jHd
LspYW5wt+FEm1c1IYS076L4dk+yEUVZZ1JQ3iaHKn3/KDb5d5/1+yz1heBEdz83e
ZwIDAQAB
-----END PUBLIC KEY-----
I0906 16:03:39.308133   16742 grpc_attestor.go:235]      Encryption Issuer x509 tpm_ek_v1_cloud_host-signer-0-2020-10-22T14:02:08-07:00 K:1, 2:HBNpA3TPAbM:0:18
I0906 16:03:39.308170   16742 grpc_attestor.go:236]      Returning GetEKCert ========
I0906 16:03:39.309604   16742 grpc_attestor.go:126] >> inbound request
I0906 16:03:39.309630   16742 grpc_attestor.go:244] ======= GetAK ========
I0906 16:03:39.309636   16742 grpc_attestor.go:245]      client provided uid: 369c327d-ad1f-401c-aa91-d9b0e69bft67
I0906 16:03:39.310416   16742 grpc_attestor.go:252]      Current PCR 0 Value 24af52a4f429b71a3184a6d64cddad17e54ea030e2aa6576bf3a5a3d8bd3328f
I0906 16:03:39.310435   16742 grpc_attestor.go:257]      createPrimary
I0906 16:03:39.392885   16742 grpc_attestor.go:288]      ekPub Name: 000b4bd5d7f30dc3a1975ae9529404f2ec73ae5a404669c5e87d74186fa2a4c280db
I0906 16:03:39.392921   16742 grpc_attestor.go:289]      ekPubPEM: 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwsY6zrTncJqdkbccZuoe
2eyDcvd2FzsCBDCyD6E31O2vMmy0Co/w8sqDutyeTZ4N6LvirGSdQxNZ/iv5nLRB
nlUXiJi8Spxz9FvtHoNN4ptmveqDvRl2l6NkxHZBIxLxPi0k9zmpbb5iqHcDqkyz
iQlPnWZDZMBZTnY2pOHOzn7c7qR/uuwsMxIUCXH8g93YL00b7mn53GiBn9rqg2L1
GcioHkfu8dROyoTUhrRn56ap4bwI0LsoGwiMfSw2ITFsJXHFkXcshe2ev+z29jHd
LspYW5wt+FEm1c1IYS076L4dk+yEUVZZ1JQ3iaHKn3/KDb5d5/1+yz1heBEdz83e
ZwIDAQAB
-----END PUBLIC KEY-----
I0906 16:03:39.392956   16742 grpc_attestor.go:296]      CreateKeyUsingAuth
I0906 16:03:39.485763   16742 grpc_attestor.go:336]      ContextSave (ek)
I0906 16:03:39.496024   16742 grpc_attestor.go:347]      ContextLoad (ek)
I0906 16:03:39.503874   16742 grpc_attestor.go:358]      LoadUsingAuth
I0906 16:03:39.512298   16742 grpc_attestor.go:386]      AK keyName 0022000b75afd591852ae04f1587cf717dfe8b61737b3550fa83e75e0e07f10eb37e970e
I0906 16:03:39.515787   16742 grpc_attestor.go:408]      akPubPEM: 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuFQqmRqf4tfujeMHAd65
ZCdfa6ubKjnbqHPwIYT2z8dxGfA4im7mc6aLYShG9uesJFBh33DLg66teV6EzMYW
w16FfKRCzO5ahvOCwn4n15ZQ5qaRuLa9cc0Jh/k5fE/3oesUv/YW3c7WsDndgjhl
7sRAKxvzrY1SXekM2l35uffT3mhTEsx/Pm0w/OrNWoI6EE6L9tVAMKlfOQwLxg8l
FNcwLm358tsyUFy+EglzVSQNkeMUmD5SxJQemppnh7bLUnA4vZrzeBrRLqCJSmdL
bsDGSH1TPGNAZA29EYUw8Na0VYvF6wqj+ZP2HIaBEyakXOD1nX6etjU15ooPw5M/
bwIDAQAB
-----END PUBLIC KEY-----
I0906 16:03:39.515837   16742 grpc_attestor.go:410]      Write (akPub) ========
I0906 16:03:39.516027   16742 grpc_attestor.go:415]      Write (akPriv) ========
I0906 16:03:39.516135   16742 grpc_attestor.go:425]      Returning GetAK ========
I0906 16:03:39.535363   16742 grpc_attestor.go:126] >> inbound request
I0906 16:03:39.535393   16742 grpc_attestor.go:437] ======= ActivateCredential ========
I0906 16:03:39.535400   16742 grpc_attestor.go:438]      client provided uid: 369c327d-ad1f-401c-aa91-d9b0e69bft67
I0906 16:03:39.535410   16742 grpc_attestor.go:440]      ContextLoad (ek)
I0906 16:03:39.544597   16742 grpc_attestor.go:451]      Read (akPub)
I0906 16:03:39.544689   16742 grpc_attestor.go:456]      Read (akPriv)
I0906 16:03:39.552149   16742 grpc_attestor.go:487]      keyName 0022000b75afd591852ae04f1587cf717dfe8b61737b3550fa83e75e0e07f10eb37e970e
I0906 16:03:39.552184   16742 grpc_attestor.go:489]      ActivateCredentialUsingAuth
I0906 16:03:39.564760   16742 grpc_attestor.go:537]      <--  activateCredential()
I0906 16:03:39.572541   16742 grpc_attestor.go:126] >> inbound request
I0906 16:03:39.572570   16742 grpc_attestor.go:547] ======= Quote ========
I0906 16:03:39.572579   16742 grpc_attestor.go:548]      client provided uid: 369c327d-ad1f-401c-aa91-d9b0e69bft67
I0906 16:03:39.574372   16742 grpc_attestor.go:555]      PCR 0 Value 24af52a4f429b71a3184a6d64cddad17e54ea030e2aa6576bf3a5a3d8bd3328f 
I0906 16:03:39.574397   16742 grpc_attestor.go:560]      ContextLoad (ek) ========
I0906 16:03:39.583235   16742 grpc_attestor.go:570]      LoadUsingAuth ========
I0906 16:03:39.586671   16742 grpc_attestor.go:592]      Read (akPub) ========
I0906 16:03:39.586739   16742 grpc_attestor.go:597]      Read (akPriv) ========
I0906 16:03:39.591700   16742 grpc_attestor.go:609]      AK keyName 0022000b75afd591852ae04f1587cf717dfe8b61737b3550fa83e75e0e07f10eb37e970e
I0906 16:03:39.598339   16742 grpc_attestor.go:624]      <-- End Quote
I0906 16:03:39.613581   16742 grpc_attestor.go:126] >> inbound request
I0906 16:03:39.613619   16742 grpc_attestor.go:636] ======= PushSecret ========
I0906 16:03:39.613629   16742 grpc_attestor.go:637]      client provided uid: 369c327d-ad1f-401c-aa91-d9b0e69bft67
I0906 16:03:39.613636   16742 grpc_attestor.go:640]      Loading EndorsementKeyRSA
I0906 16:03:39.620371   16742 grpc_attestor.go:668]      Loading ImportSigningKey
I0906 16:03:39.646418   16742 grpc_attestor.go:687]      Public portion of RSA Keypair to import: 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqwK/eG8GB9TC8adQB0ph
+R8qZPePz6bVlKE+8mk1pqVxqpOS3odGID2yCVdflMO7apOmyzs3NOrulcGqhtc6
ZF7N9utLPcpOVppTEJQP3Q2eky5I3F9x03aWmk/OpjVDVaqWNJwIPePLqnlRIIsL
DKH1IXbBQHIs/wnbDgXxw1VHkdpXUlyXdCliUvVA/YAZhIPcIBBZipNBOzJHiHTk
I97KMb1acCm9aRi0A9odZUsQLduVqhwKALw+U5+aMInT/vI4JS0KLlzZfvov3wPR
PgaZnhDCLs2gr/BDM4mJAMZ4Tp9FMdeeg8fSCVbx75cyLTPwD2RQDKNBXxI+9LIj
9QIDAQAB
-----END PUBLIC KEY-----
I0906 16:03:39.646498   16742 grpc_attestor.go:689]      Saving Key Handle as importedKey.bin
I0906 16:03:39.655673   16742 grpc_attestor.go:702]      Generating Test Signature ========
I0906 16:03:39.657699   16742 grpc_attestor.go:717]      Data to sign: 369c327d-ad1f-401c-aa91-d9b0e69bft67
I0906 16:03:39.664871   16742 grpc_attestor.go:732]      Test Signature data:  FBdOOCvkAdCPxuxXSzomtLx5ayURHGEsWMIiP90ve4zqvLGDOLH9mE5MGbPbdpYF2HUxwh4r1ISVbYCdZV7O/1CI68LN1uDLjaMNwOaQAs1FMoeLdGfD04mLVBQ/i67hLBEZj3WY0m0mwo1W7anyKYyav1L/rAWB0W+guT02zibxhaI+CemixLAXObthWHFsfipmmZNJPvApNP8Ro4MtBbla4S3UYi1HCEHlLOpmvFHvPwoG1WBr529CltzQ5xf/NfBpQ/nhlDTNkpgka40uEX5qoW1uRYIZOtbmTZcgb1FPqEEW2+GUH7TvVNFhTdL6lSLstVNfnokGPHWoDiErqw
I0906 16:03:39.677494   16742 grpc_attestor.go:126] >> inbound request
I0906 16:03:39.677540   16742 grpc_attestor.go:746] ======= PullRSAKey ========
I0906 16:03:39.677581   16742 grpc_attestor.go:747]      client provided uid: 369c327d-ad1f-401c-aa91-d9b0e69bft67
I0906 16:03:39.677595   16742 grpc_attestor.go:749] ======= Generate UnrestrictedKey ========
I0906 16:03:39.677608   16742 grpc_attestor.go:751]      ContextLoad (ek) ========
I0906 16:03:39.685777   16742 grpc_attestor.go:762]      Loading AttestationKey
I0906 16:03:39.694305   16742 grpc_attestor.go:798]      AK keyName: ACIAC3Wv1ZGFKuBPFYfPcX3+i2FzezVQ+oPnXg4H8Q6zfpcO,
I0906 16:03:39.696005   16742 grpc_attestor.go:822]      akPub PEM 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuFQqmRqf4tfujeMHAd65
ZCdfa6ubKjnbqHPwIYT2z8dxGfA4im7mc6aLYShG9uesJFBh33DLg66teV6EzMYW
w16FfKRCzO5ahvOCwn4n15ZQ5qaRuLa9cc0Jh/k5fE/3oesUv/YW3c7WsDndgjhl
7sRAKxvzrY1SXekM2l35uffT3mhTEsx/Pm0w/OrNWoI6EE6L9tVAMKlfOQwLxg8l
FNcwLm358tsyUFy+EglzVSQNkeMUmD5SxJQemppnh7bLUnA4vZrzeBrRLqCJSmdL
bsDGSH1TPGNAZA29EYUw8Na0VYvF6wqj+ZP2HIaBEyakXOD1nX6etjU15ooPw5M/
bwIDAQAB
-----END PUBLIC KEY-----
I0906 16:03:39.696058   16742 grpc_attestor.go:826]      ======= CreateKeyUsingAuthUnrestricted ========
I0906 16:03:39.701727   16742 grpc_attestor.go:856]      PCR 0 Value 24af52a4f429b71a3184a6d64cddad17e54ea030e2aa6576bf3a5a3d8bd3328f 
I0906 16:03:39.837902   16742 grpc_attestor.go:872]      Write (ukPub) ========
I0906 16:03:39.838239   16742 grpc_attestor.go:877]      Write (ukPriv) ========
I0906 16:03:39.848338   16742 grpc_attestor.go:933]      uakPub PEM 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwB/ERFgyUVLKG8pzjOEJ
N5xi2qL56BWQrA1zRMi4t+U/Zlja5EaWbgjpoBurkiOZJMVvn5RF3Th0FGgM9idp
9CnFk1lG0srLhLHd8mC07JEtO3eUidhTBnVYhikeer9lhwBELBWD6LfDKyj7Ge39
gjUET5k548H5oW/T+MvPe6jbh2Jpx6cmKrMHkZztxiM3Lq0qFEmlnCo6t85vfM8S
HkjKlCxJqfcmHm1TW8KpQ+baSmyhza3UGknxAUeqF8/FdkTDjaaqpwHtKmtoPLgw
REp4Q6BAOu1jdm9V8zZywE9+J5dr7qLdxdaFfk+4y3PmiiOpJwW32q/yv9Tz5NMk
IwIDAQAB
-----END PUBLIC KEY-----
I0906 16:03:39.856173   16742 grpc_attestor.go:948]      Data to sign: 369c327d-ad1f-401c-aa91-d9b0e69bft67
I0906 16:03:39.864586   16742 grpc_attestor.go:962]      Test Signature:  Jta/Js2ixcNNbFN78CV9wVourU/1gzi2wyWh+uf+UGYuTYqxSCsaojFt1+2X63Q5BJMqXCkTgf3rqewmlEAq7EJ7Ny0VrVjFacps4vgyrQ+FMn0EvJfz6PlD8Mv4h6VB0UfEf8SA9JPnJiW1CRmVSJzT5ulxxeK9pjuq+OUMhrl4oOeX2yMsT/b6fmUQo2cvmmmnrW8GSkCTXG2pxrfUEXXeiO/Da7IoeVVsgJnZnZ77JsspfsTZtfrkDOlcTqshhbNYoc9vgG23THf6UXq6TAhMHN3+hrIS7cGfZWSsymlhI7xQq+gMljX1nWcuZMsux8DhgqiF29pZgqSWlV856w
I0906 16:03:39.864722   16742 grpc_attestor.go:1010]      Decoding PublicKey for AK ========
I0906 16:03:39.864875   16742 grpc_attestor.go:1036]      Attestation Verified
I0906 16:03:39.864906   16742 grpc_attestor.go:1045]      Returning PullRSAKeyResponse
```

#### Verifier RSA

```log
$ go run src/grpc_verifier.go --importMode=RSA  --uid 369c327d-ad1f-401c-aa91-d9b0e69bft67 \
  --pcr=0  --expectedPCRValue 24af52a4f429b71a3184a6d64cddad17e54ea030e2aa6576bf3a5a3d8bd3328f  --rsaCert=certs/tpm_client.crt \
  --expectedPCRSHA1 0f2d3a2a1adaa479aeeca8f5df76aadc41b862ea \
  --caCertTLS certs/CA_crt.pem --caCertIssuer certs/CA_crt.pem --caKeyIssuer certs/CA_key.pem \
  --rsaKey=certs/tpm_client.key  --host verify.esodemoapp2.com:50051   \
  --v=10 -alsologtostderr 

I0906 16:03:39.265818   15340 grpc_verifier.go:143] RPC HealthChekStatus:SERVING
I0906 16:03:39.266057   15340 grpc_verifier.go:147] =============== GetPlatformCert ===============
I0906 16:03:39.286790   15340 grpc_verifier.go:156] =============== GetPlatformCert Returned from remote ===============
I0906 16:03:39.286926   15340 grpc_verifier.go:174]     Platform Cert Issuer tpm_ek_v1_cloud_host_root-signer-0-2018-04-06T10:58:26-07:00 K:1, 1:Pw003HsFYO4:0:18
I0906 16:03:39.308672   15340 grpc_verifier.go:186] =============== GetEKCert Returned from remote ===============
I0906 16:03:39.308930   15340 grpc_verifier.go:204]     EkCert Cert Issuer tpm_ek_v1_cloud_host-signer-0-2020-10-22T14:02:08-07:00 K:1, 2:HBNpA3TPAbM:0:18
I0906 16:03:39.309027   15340 grpc_verifier.go:205]     EkCert Public Key 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwsY6zrTncJqdkbccZuoe
2eyDcvd2FzsCBDCyD6E31O2vMmy0Co/w8sqDutyeTZ4N6LvirGSdQxNZ/iv5nLRB
nlUXiJi8Spxz9FvtHoNN4ptmveqDvRl2l6NkxHZBIxLxPi0k9zmpbb5iqHcDqkyz
iQlPnWZDZMBZTnY2pOHOzn7c7qR/uuwsMxIUCXH8g93YL00b7mn53GiBn9rqg2L1
GcioHkfu8dROyoTUhrRn56ap4bwI0LsoGwiMfSw2ITFsJXHFkXcshe2ev+z29jHd
LspYW5wt+FEm1c1IYS076L4dk+yEUVZZ1JQ3iaHKn3/KDb5d5/1+yz1heBEdz83e
ZwIDAQAB
-----END PUBLIC KEY-----

I0906 16:03:39.309133   15340 grpc_verifier.go:208] =============== GetAKCert ===============
I0906 16:03:39.523539   15340 grpc_verifier.go:220] =============== MakeCredential ===============
I0906 16:03:39.523775   15340 grpc_verifier.go:242]      Decoded EkPublic Key: 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwsY6zrTncJqdkbccZuoe
2eyDcvd2FzsCBDCyD6E31O2vMmy0Co/w8sqDutyeTZ4N6LvirGSdQxNZ/iv5nLRB
nlUXiJi8Spxz9FvtHoNN4ptmveqDvRl2l6NkxHZBIxLxPi0k9zmpbb5iqHcDqkyz
iQlPnWZDZMBZTnY2pOHOzn7c7qR/uuwsMxIUCXH8g93YL00b7mn53GiBn9rqg2L1
GcioHkfu8dROyoTUhrRn56ap4bwI0LsoGwiMfSw2ITFsJXHFkXcshe2ev+z29jHd
LspYW5wt+FEm1c1IYS076L4dk+yEUVZZ1JQ3iaHKn3/KDb5d5/1+yz1heBEdz83e
ZwIDAQAB
-----END PUBLIC KEY-----
I0906 16:03:39.527747   15340 grpc_verifier.go:270]      Decoded AkPub: 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuFQqmRqf4tfujeMHAd65
ZCdfa6ubKjnbqHPwIYT2z8dxGfA4im7mc6aLYShG9uesJFBh33DLg66teV6EzMYW
w16FfKRCzO5ahvOCwn4n15ZQ5qaRuLa9cc0Jh/k5fE/3oesUv/YW3c7WsDndgjhl
7sRAKxvzrY1SXekM2l35uffT3mhTEsx/Pm0w/OrNWoI6EE6L9tVAMKlfOQwLxg8l
FNcwLm358tsyUFy+EglzVSQNkeMUmD5SxJQemppnh7bLUnA4vZrzeBrRLqCJSmdL
bsDGSH1TPGNAZA29EYUw8Na0VYvF6wqj+ZP2HIaBEyakXOD1nX6etjU15ooPw5M/
bwIDAQAB
-----END PUBLIC KEY-----
I0906 16:03:39.527793   15340 grpc_verifier.go:273]      AK Default parameter match template
I0906 16:03:39.531078   15340 grpc_verifier.go:282]      Loaded AK KeyName 000b75afd591852ae04f1587cf717dfe8b61737b3550fa83e75e0e07f10eb37e970e
I0906 16:03:39.531109   15340 grpc_verifier.go:284]      MakeCredential Start
I0906 16:03:39.531143   15340 grpc_verifier.go:290]      Sending Nonce: KxISfNQJOeFCjzRFcYjypzTEtXhEJiUu
I0906 16:03:39.534599   15340 grpc_verifier.go:297]      <-- End makeCredential()
I0906 16:03:39.534645   15340 grpc_verifier.go:302] =============== ActivateCredential ===============
I0906 16:03:39.571928   15340 grpc_verifier.go:313]      Returned Secret: KxISfNQJOeFCjzRFcYjypzTEtXhEJiUu
I0906 16:03:39.571974   15340 grpc_verifier.go:318]      Attestation Complete
I0906 16:03:39.571996   15340 grpc_verifier.go:320] =============== Quote/Verify ===============
I0906 16:03:39.572017   15340 grpc_verifier.go:325]      Sending Quote with Nonce: ekQNDOmxxzbVlCGzZUbJvRTaJWXhEZVh
I0906 16:03:39.603628   15340 grpc_verifier.go:347]      Attestation ExtraData (nonce): ekQNDOmxxzbVlCGzZUbJvRTaJWXhEZVh 
I0906 16:03:39.603726   15340 grpc_verifier.go:348]      Attestation PCR#: [0] 
I0906 16:03:39.603779   15340 grpc_verifier.go:349]      Attestation Hash: 2ba7022b59f2158786ea3ea29a7ad12ff0c6c9d6682da6555d8926075b643b1f 
I0906 16:03:39.603813   15340 grpc_verifier.go:365]      Expected PCR Value:           --> 24af52a4f429b71a3184a6d64cddad17e54ea030e2aa6576bf3a5a3d8bd3328f
I0906 16:03:39.603840   15340 grpc_verifier.go:366]      sha256 of Expected PCR Value: --> 2ba7022b59f2158786ea3ea29a7ad12ff0c6c9d6682da6555d8926075b643b1f
I0906 16:03:39.603872   15340 grpc_verifier.go:372]      Decoding PublicKey for AK ========
I0906 16:03:39.604034   15340 grpc_verifier.go:386]      Attestation Signature Verified 
I0906 16:03:39.604065   15340 grpc_verifier.go:388]      Reading EventLog
I0906 16:03:39.604183   15340 grpc_verifier.go:403]      Event Type EV_S_CRTM_VERSION
I0906 16:03:39.604239   15340 grpc_verifier.go:404]      PCR Index 0
I0906 16:03:39.604285   15340 grpc_verifier.go:405]      Event Data 47004300450020005600690072007400750061006c0020004600690072006d0077006100720065002000760031000000
I0906 16:03:39.604337   15340 grpc_verifier.go:406]      Event Digest 3f708bdbaff2006655b540360e16474c100c1310
I0906 16:03:39.604381   15340 grpc_verifier.go:403]      Event Type EV_NONHOST_INFO
I0906 16:03:39.604429   15340 grpc_verifier.go:404]      PCR Index 0
I0906 16:03:39.604474   15340 grpc_verifier.go:405]      Event Data 474345204e6f6e486f7374496e666f0000000000000000000000000000000000
I0906 16:03:39.604519   15340 grpc_verifier.go:406]      Event Digest 9e8af742718df04092551f27c117723769acfe7e
I0906 16:03:39.604565   15340 grpc_verifier.go:403]      Event Type EV_SEPARATOR
I0906 16:03:39.604611   15340 grpc_verifier.go:404]      PCR Index 0
I0906 16:03:39.604659   15340 grpc_verifier.go:405]      Event Data 00000000
I0906 16:03:39.604704   15340 grpc_verifier.go:406]      Event Digest 9069ca78e7450a285173431b3e52c5c25299e473
I0906 16:03:39.604731   15340 grpc_verifier.go:408]      EventLog Verified 
I0906 16:03:39.604760   15340 grpc_verifier.go:414]      Generate Test Certificate for AK 
I0906 16:03:39.609135   15340 grpc_verifier.go:483]      X509 issued by Verifier for Ak: 
-----BEGIN CERTIFICATE-----
MIID1DCCArygAwIBAgIQQjg+qH8FA9aa9aQk2gJSqzANBgkqhkiG9w0BAQsFADBv
MQswCQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTEWMBQGA1UEBxMNTW91
bnRhaW4gVmlldzEPMA0GA1UEChMGR29vZ2xlMRMwEQYDVQQLEwpFbnRlcnByaXNl
MQ0wCwYDVQQDEwRNeUNBMB4XDTIxMDkwNjE2MDMzOVoXDTIyMDkwNjE2MDMzOVow
gYIxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYwFAYDVQQHEw1N
b3VudGFpbiBWaWV3MRAwDgYDVQQKEwdBY21lIENvMRMwEQYDVQQLEwpFbnRlcnBy
aXNlMR8wHQYDVQQDExZ2ZXJpZnkuZXNvZGVtb2FwcDIuY29tMIIBIjANBgkqhkiG
9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuFQqmRqf4tfujeMHAd65ZCdfa6ubKjnbqHPw
IYT2z8dxGfA4im7mc6aLYShG9uesJFBh33DLg66teV6EzMYWw16FfKRCzO5ahvOC
wn4n15ZQ5qaRuLa9cc0Jh/k5fE/3oesUv/YW3c7WsDndgjhl7sRAKxvzrY1SXekM
2l35uffT3mhTEsx/Pm0w/OrNWoI6EE6L9tVAMKlfOQwLxg8lFNcwLm358tsyUFy+
EglzVSQNkeMUmD5SxJQemppnh7bLUnA4vZrzeBrRLqCJSmdLbsDGSH1TPGNAZA29
EYUw8Na0VYvF6wqj+ZP2HIaBEyakXOD1nX6etjU15ooPw5M/bwIDAQABo1gwVjAO
BgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwMwDAYDVR0TAQH/BAIw
ADAhBgNVHREEGjAYghZ2ZXJpZnkuZXNvZGVtb2FwcDIuY29tMA0GCSqGSIb3DQEB
CwUAA4IBAQAfnZX/QWuvFLX75jZhK0JG0KckR/6heWs2UDXAzuFfMH3Hat8MeIQ6
WsZW8sdWRbOX8ALa92jl5DGd462ix6gYYXemr7nYN5F7FkRMGuvtqW8Thm/z4J1b
rNklfRXANPQ/AcvAKeUc+V9H75X1lMPTWkTmayBIGQLZqzEQ07H5Cg91cLIIeaW5
Qg5SRZhxuiZENJ50U07Nw7TFStYBIXuEb38pq0rSuYqPeunL02YlDfpeRG3NR2uL
/V0Tpw9z3bOyYPCxO8KlFXa7xI1J1I7klKnJyln50Ip+Bi+ht1s+d33HpZ8/N9qP
UxfVkcVq43PJ9FxyXMsBs+BH1VlOKuPv
-----END CERTIFICATE-----
I0906 16:03:39.609251   15340 grpc_verifier.go:485]      <-- End verifyQuote()
I0906 16:03:39.609296   15340 grpc_verifier.go:487] =============== PushSecret ===============
I0906 16:03:39.609330   15340 grpc_verifier.go:489]      Pushing RSA
I0906 16:03:39.609565   15340 grpc_verifier.go:542]      Loaded x509 CN=Enterprise Subordinate CA,OU=Enterprise,O=Google,C=US
I0906 16:03:39.609740   15340 grpc_verifier.go:558]      Data to sign: 369c327d-ad1f-401c-aa91-d9b0e69bft67
I0906 16:03:39.612380   15340 grpc_verifier.go:566]      Test signature data:  FBdOOCvkAdCPxuxXSzomtLx5ayURHGEsWMIiP90ve4zqvLGDOLH9mE5MGbPbdpYF2HUxwh4r1ISVbYCdZV7O/1CI68LN1uDLjaMNwOaQAs1FMoeLdGfD04mLVBQ/i67hLBEZj3WY0m0mwo1W7anyKYyav1L/rAWB0W+guT02zibxhaI+CemixLAXObthWHFsfipmmZNJPvApNP8Ro4MtBbla4S3UYi1HCEHlLOpmvFHvPwoG1WBr529CltzQ5xf/NfBpQ/nhlDTNkpgka40uEX5qoW1uRYIZOtbmTZcgb1FPqEEW2+GUH7TvVNFhTdL6lSLstVNfnokGPHWoDiErqw
I0906 16:03:39.612425   15340 grpc_verifier.go:567]      <-- End generateCertificate()
I0906 16:03:39.676909   15340 grpc_verifier.go:589]      Verification FBdOOCvkAdCPxuxXSzomtLx5ayURHGEsWMIiP90ve4zqvLGDOLH9mE5MGbPbdpYF2HUxwh4r1ISVbYCdZV7O/1CI68LN1uDLjaMNwOaQAs1FMoeLdGfD04mLVBQ/i67hLBEZj3WY0m0mwo1W7anyKYyav1L/rAWB0W+guT02zibxhaI+CemixLAXObthWHFsfipmmZNJPvApNP8Ro4MtBbla4S3UYi1HCEHlLOpmvFHvPwoG1WBr529CltzQ5xf/NfBpQ/nhlDTNkpgka40uEX5qoW1uRYIZOtbmTZcgb1FPqEEW2+GUH7TvVNFhTdL6lSLstVNfnokGPHWoDiErqw
I0906 16:03:39.676975   15340 grpc_verifier.go:594] =============== PullRSAKey ===============
I0906 16:03:39.873070   15340 grpc_verifier.go:625]      Attestation of Unrestricted Signing Key Verified
I0906 16:03:39.873302   15340 grpc_verifier.go:646]      uakPub PEM 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwB/ERFgyUVLKG8pzjOEJ
N5xi2qL56BWQrA1zRMi4t+U/Zlja5EaWbgjpoBurkiOZJMVvn5RF3Th0FGgM9idp
9CnFk1lG0srLhLHd8mC07JEtO3eUidhTBnVYhikeer9lhwBELBWD6LfDKyj7Ge39
gjUET5k548H5oW/T+MvPe6jbh2Jpx6cmKrMHkZztxiM3Lq0qFEmlnCo6t85vfM8S
HkjKlCxJqfcmHm1TW8KpQ+baSmyhza3UGknxAUeqF8/FdkTDjaaqpwHtKmtoPLgw
REp4Q6BAOu1jdm9V8zZywE9+J5dr7qLdxdaFfk+4y3PmiiOpJwW32q/yv9Tz5NMk
IwIDAQAB
-----END PUBLIC KEY-----
I0906 16:03:39.873458   15340 grpc_verifier.go:651]      SigningKey Test Signature Jta/Js2ixcNNbFN78CV9wVourU/1gzi2wyWh+uf+UGYuTYqxSCsaojFt1+2X63Q5BJMqXCkTgf3rqewmlEAq7EJ7Ny0VrVjFacps4vgyrQ+FMn0EvJfz6PlD8Mv4h6VB0UfEf8SA9JPnJiW1CRmVSJzT5ulxxeK9pjuq+OUMhrl4oOeX2yMsT/b6fmUQo2cvmmmnrW8GSkCTXG2pxrfUEXXeiO/Da7IoeVVsgJnZnZ77JsspfsTZtfrkDOlcTqshhbNYoc9vgG23THf6UXq6TAhMHN3+hrIS7cGfZWSsymlhI7xQq+gMljX1nWcuZMsux8DhgqiF29pZgqSWlV856w==
I0906 16:03:39.873547   15340 grpc_verifier.go:652]      Data to verify signature with: 369c327d-ad1f-401c-aa91-d9b0e69bft67
I0906 16:03:39.873772   15340 grpc_verifier.go:659]      Test Signature Verified
I0906 16:03:39.873885   15340 grpc_verifier.go:680]      Unrestricted RSA Public key parameters matches AttestedCertifyInfo  true
I0906 16:03:39.878263   15340 grpc_verifier.go:718]      X509 issued by Verifier for unrestricted Key: 
-----BEGIN CERTIFICATE-----
MIID0DCCArigAwIBAgIQQjg+qH8FA9aa9aQk2gJSqzANBgkqhkiG9w0BAQsFADBv
MQswCQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTEWMBQGA1UEBxMNTW91
bnRhaW4gVmlldzEPMA0GA1UEChMGR29vZ2xlMRMwEQYDVQQLEwpFbnRlcnByaXNl
MQ0wCwYDVQQDEwRNeUNBMB4XDTIxMDkwNjE2MDMzOVoXDTIyMDkwNjE2MDMzOVow
gYIxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYwFAYDVQQHEw1N
b3VudGFpbiBWaWV3MRAwDgYDVQQKEwdBY21lIENvMRMwEQYDVQQLEwpFbnRlcnBy
aXNlMR8wHQYDVQQDExZ2ZXJpZnkuZXNvZGVtb2FwcDIuY29tMIIBIjANBgkqhkiG
9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwB/ERFgyUVLKG8pzjOEJN5xi2qL56BWQrA1z
RMi4t+U/Zlja5EaWbgjpoBurkiOZJMVvn5RF3Th0FGgM9idp9CnFk1lG0srLhLHd
8mC07JEtO3eUidhTBnVYhikeer9lhwBELBWD6LfDKyj7Ge39gjUET5k548H5oW/T
+MvPe6jbh2Jpx6cmKrMHkZztxiM3Lq0qFEmlnCo6t85vfM8SHkjKlCxJqfcmHm1T
W8KpQ+baSmyhza3UGknxAUeqF8/FdkTDjaaqpwHtKmtoPLgwREp4Q6BAOu1jdm9V
8zZywE9+J5dr7qLdxdaFfk+4y3PmiiOpJwW32q/yv9Tz5NMkIwIDAQABo1QwUjAO
BgNVHQ8BAf8EBAMCB4AwDwYDVR0lBAgwBgYEVR0lADAMBgNVHRMBAf8EAjAAMCEG
A1UdEQQaMBiCFnZlcmlmeS5lc29kZW1vYXBwMi5jb20wDQYJKoZIhvcNAQELBQAD
ggEBAC/qGT+/ugU01p/SelUlhFYYYBtiykr6vT4bojqzdPvoifJGnU1QjIMNfwHC
tsRMf6VZHya4axbHUXCz7hrti48C71mYRRtFg3glbBTmfW8J47/uHr7uv4w2ozKX
8noI4aDaFTbptai6xH8fI0061RNdlCDQ5mhZRxu2HmwbfJDRrSPjI3yJPYV8jkTP
jAsSO5R+wywFs0UCFZCabDZlrbq/9z4g9pfiwaA9s6J57jWrrupXbnuX5xAnVgKV
7UvH5xiBKDfkuAXvNq09X3XJ1/27RoPyHG/rQKVOrVTYKXRZ3QhYz5UxjUVfeDIf
wx2YTR9kcNB6HeRX479/MI0nH0M=
-----END CERTIFICATE-----
I0906 16:03:39.878458   15340 grpc_verifier.go:720]      Pulled Signing Key  complete 369c327d-ad1f-401c-aa91-d9b0e69bft67

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

which you can specify with arguments

`--pcr=0 --expectedPCRSHA1 0f2d3a2a1adaa479aeeca8f5df76aadc41b862ea --expectedPCRValue 24af52a4f429b71a3184a6d64cddad17e54ea030e2aa6576bf3a5a3d8bd3328f`

We're using PCR0 for the [TPM EventLog](https://www.kernel.org/doc/html/latest/security/tpm/tpm_event_log.html) that is returned during quote/verify.

see [go-tpm-tools/server/eventlog_test.go](https://github.com/google/go-tpm-tools/blob/master/server/eventlog_test.go#L226)

for debian10 on GCE with secureboot: `0f2d3a2a1adaa479aeeca8f5df76aadc41b862ea`:


```
# tpm2_eventlog /sys/kernel/security/tpm0/binary_bios_measurements
---
version: 1
events:
  PCRIndex: 0
  EventType: EV_S_CRTM_VERSION
  DigestCount: 1
  Digests:
  - AlgorithmId: sha1
    Digest: "3f708bdbaff2006655b540360e16474c100c1310"
  EventSize: 48
  Event: "47004300450020005600690072007400750061006c0020004600690072006d0077006100720065002000760031000000"
  PCRIndex: 0
  EventType: EV_NONHOST_INFO
  DigestCount: 1
  Digests:
  - AlgorithmId: sha1
    Digest: "9e8af742718df04092551f27c117723769acfe7e"
  EventSize: 32
  Event: "474345204e6f6e486f7374496e666f0000000000000000000000000000000000"
  PCRIndex: 7
  EventType: EV_EFI_VARIABLE_DRIVER_CONFIG
  DigestCount: 1
  Digests:
  - AlgorithmId: sha1
    Digest: "d4fdd1f14d4041494deb8fc990c45343d2277d08"
  EventSize: 53
  Event:
    VariableName: 8be4df61-93ca-11d2-aa0d-00e098032b8c
    UnicodeNameLength: 10
    VariableDataLength: 1
    UnicodeName: SecureBoot
    VariableData: "01"
  PCRIndex: 7
  EventType: EV_EFI_VARIABLE_DRIVER_CONFIG
  DigestCount: 1
  Digests:
  - AlgorithmId: sha1
    Digest: "5abd9412abf33e34a79b3d1a93d350e742d8ecd8"
  EventSize: 842
  Event:
    VariableName: 8be4df61-93ca-11d2-aa0d-00e098032b8c
    UnicodeNameLength: 2
    VariableDataLength: 806
    UnicodeName: PK
    VariableData: "a159c0a5e494a74a87b5ab155c2bf07226030000000000000a030000d2fa81d2888da44797925baa47bb1b89308202f6308201dea003020102020900d54a14e867835dea300d06092a864886f70d01010b05003010310e300c06035504030c056e6577706b301e170d3138303832313231353131355a170d3138303932303231353131355a3010310e300c06035504030c056e6577706b30820122300d06092a864886f70d01010105000382010f003082010a0282010100ccb9d5087cf86d6b63ea1702c962f40b93c9fe90e39d7c2c45ce85015252487cfb4326bf0da589b0f2dd13c736e87f6995aa8c6fd0a2236f34c24fb19e6bc6fa151bb894c19c8e70879142ce69210f937dda759fbf31172050c1ef8023fbbe3b56e30ad747ea9d30afd45da9036389a2fc39e196a187c33d0326b2d3a26cecc897d7ceda18eab2953cb3040707ce028acfda3a5110883f25b04b3eccddf9dadb51d591169a1da107bd88e2f112b4f1b30092b7e367e6ad8c6adc273f1ddcd44e6cc116bdefde562ada1359600979d3a97c578dfd519061379d7f7de4b76e95f0529b439edc483c1dcdbc399f12a3e8470d46b836dc92b395a8ce4ae34623584b0203010001a3533051301d0603551d0e041604149850840342f32fdb97822728977431465e60cbc5301f0603551d230418301680149850840342f32fdb97822728977431465e60cbc5300f0603551d130101ff040530030101ff300d06092a864886f70d01010b050003820101008aa11e52113f17aae7bdb024ab8bad32b049fd7b34cb3b8076603d8edcca6b69c25b94e8b8139c8c2cd7bcac7d8259c3b511c42ea26c16a5ec981df003312336f8cb3083673a3a1f2b622117602cbaf52ef9286eca6670582886678f69846c002758259c501405e970b8606e54854aaf086d8f451ba65b34fc264d1c3c81e1bb242e79e013d1c8ac7cd97f3847114381196b335057e3739ea67f87ddc3e24afc737b4b070987c78309365aea698740840c2c94802f3dae3dcb70c40335c2b93e7108b2a3c6add8243f7d60ab186fa0ee7a1b9acf759fe84cabcd5187685833b2d901bc04021038252a984b1d45fb67339b259c3fac1ba44344cccdd3c80b6ee1"
  PCRIndex: 7
  EventType: EV_EFI_VARIABLE_DRIVER_CONFIG
  DigestCount: 1
  Digests:
  - AlgorithmId: sha1
    Digest: "f0501c79b607cc42e9142ee85a74d9c27669c0e2"
  EventSize: 1598
  Event:
    VariableName: 8be4df61-93ca-11d2-aa0d-00e098032b8c
    UnicodeNameLength: 3
    VariableDataLength: 1560
    UnicodeName: KEK
    VariableData: "a159c0a5e494a74a87b5ab155c2bf0721806000000000000fc050000d2fa81d2888da44797925baa47bb1b89308205e8308203d0a003020102020a610ad188000000000003300d06092a864886f70d01010b0500308191310b3009060355040613025553311330110603550408130a57617368696e67746f6e3110300e060355040713075265646d6f6e64311e301c060355040a13154d6963726f736f667420436f72706f726174696f6e313b3039060355040313324d6963726f736f667420436f72706f726174696f6e205468697264205061727479204d61726b6574706c61636520526f6f74301e170d3131303632343230343132395a170d3236303632343230353132395a308180310b3009060355040613025553311330110603550408130a57617368696e67746f6e3110300e060355040713075265646d6f6e64311e301c060355040a13154d6963726f736f667420436f72706f726174696f6e312a3028060355040313214d6963726f736f667420436f72706f726174696f6e204b454b204341203230313130820122300d06092a864886f70d01010105000382010f003082010a0282010100c4e8b58abfad5726b026c3eae7fb577a44025d070dda4ae5742ae6b00fec6debec7fb9e35a63327c11174f0ee30ba73815938ec6f5e084b19a9b2ce7f5b791d609e1e2c004a8ac301cdf48f306509a64a7517fc8854f8f2086cefe2fe19fff82c0ede9cdcef4536a623a0b43b9e225fdfe05f9d4c414ab11e223898d70b7a41d4decaee59cfa16c2d7c1cbd4e8c42fe599ee248b03ec8df28beac34afb4311120b7eb547926cdce60489ebf53304eb10012a71e5f983133cff25092f687646ffba4fbedcad712a58aafb0ed2793de49b653bcc292a9ffc7259a2ebae92eff6351380c602ece45fcc9d76cdef6392c1af79408479877fe352a8e89d7b07698f150203010001a382014f3082014b301006092b06010401823715010403020100301d0603551d0e0416041462fc43cda03ea4cb6712d25bd955ac7bccb68a5f301906092b0601040182371402040c1e0a00530075006200430041300b0603551d0f040403020186300f0603551d130101ff040530030101ff301f0603551d2304183016801445665243e17e5811bfd64e9e2355083b3a226aa8305c0603551d1f045530533051a04fa04d864b687474703a2f2f63726c2e6d6963726f736f66742e636f6d2f706b692f63726c2f70726f64756374732f4d6963436f725468695061724d6172526f6f5f323031302d31302d30352e63726c306006082b0601050507010104543052305006082b060105050730028644687474703a2f2f7777772e6d6963726f736f66742e636f6d2f706b692f63657274732f4d6963436f725468695061724d6172526f6f5f323031302d31302d30352e637274300d06092a864886f70d01010b05000382020100d48488f514941802ca2a3cfb2a921c0cd7a0d1f1e85266a8eea2b5757a9000aa2da4765aea79b7b9376a517b1064f6e164f20267bef7a81b78bdbace8858640cd657c819a35f05d6dbc6d069ce484b32b7eb5dd230f5c0f5b8ba7807a32bfe9bdb345684ec82caae4125709c6be9fe900fd7961fe5e7941fb22a0c8d4bff2829107bf7d77ca5d176b905c879ed0f90929cc2fedf6f7e6c0f7bd4c145dd345196390fe55e56d8180596f407a642b3a077fd0819f27156cc9f8623a487cba6fd587ed4696715917e81f27f13e50d8b8a3c8784ebe3cebd43e5ad2d84938e6a2b5a7c44fa52aa81c82d1cbbe052df0011f89a3dc160b0e133b5a388d165190a1ae7ac7ca4c182874e38b12f0dc514876ffd8d2ebc39b6e7e6c3e0e4cd2784ef9442ef298b9046413b811b67d8f9435965cb0dbcfd00924ff4753ba7a924fc50414079e02d4f0a6a27766e52ed96697baf0ff78705d045c2ad5314811ffb3004aa373661da4a691b34d868edd602cf6c940cd3cf6c2279adb1f0bc03a24660a9c407c22182f1fdf2e8793260bfd8aca522144bcac1d84beb7d3f5735b2e64f75b4b060032253ae91791dd69b411f15865470b2de0d350f7cb03472ba97603bf079eba2b21c5da216b887c5e91bf6b597256f389fe391fa8a7998c3690eb7a31c200597f8ca14ae00d7c4f3c01410756b34a01bb59960f35cb0c5574e36d23284bf9e"
  PCRIndex: 7
  EventType: EV_EFI_VARIABLE_DRIVER_CONFIG
  DigestCount: 1
  Digests:
  - AlgorithmId: sha1
    Digest: "0915a210049c2781fba26180600fb32217c7c972"
  EventSize: 3179
  Event:
    VariableName: d719b2cb-3d3a-4596-a3bc-dad00e67656f
    UnicodeNameLength: 2
    VariableDataLength: 3143
    UnicodeName: db
    VariableData: "a159c0a5e494a74a87b5ab155c2bf072400600000000000024060000d2fa81d2888da44797925baa47bb1b8930820610308203f8a003020102020a6108d3c4000000000004300d06092a864886f70d01010b0500308191310b3009060355040613025553311330110603550408130a57617368696e67746f6e3110300e060355040713075265646d6f6e64311e301c060355040a13154d6963726f736f667420436f72706f726174696f6e313b3039060355040313324d6963726f736f667420436f72706f726174696f6e205468697264205061727479204d61726b6574706c61636520526f6f74301e170d3131303632373231323234355a170d3236303632373231333234355a308181310b3009060355040613025553311330110603550408130a57617368696e67746f6e3110300e060355040713075265646d6f6e64311e301c060355040a13154d6963726f736f667420436f72706f726174696f6e312b3029060355040313224d6963726f736f667420436f72706f726174696f6e2055454649204341203230313130820122300d06092a864886f70d01010105000382010f003082010a0282010100a5086c4cc745096a4b0ca4c0877f06750c43015464e0167f07ed927d0bb273bf0c0ac64a4561a0c5162d96d3f52ba0fb4d499b4180903cb954fde6bcd19dc4a4188a7f418a5c59836832bb8c47c9ee71bc214f9a8a7cff443f8d8f32b22648ae75b5eec94c1e4a197ee4829a1d78774d0cb0bdf60fd316d3bcfa2ba551385df5fbbadb7802dbffec0a1b96d583b81913e9b6c07b407be11f2827c9faef565e1ce67e947ec0f044b27939e5dab2628b4dbf3870e2682414c933a40837d558695ed37cedc1045308e74eb02a876308616f631559eab22b79d70c61678a5bfd5ead877fba86674f71581222042222ce8bef547100ce503558769508ee6ab1a201d50203010001a382017630820172301206092b060104018237150104050203010001302306092b060104018237150204160414f8c16bb77f77534af325371d4ea1267b0f207080301d0603551d0e0416041413adbf4309bd82709c8cd54f316ed522988a1bd4301906092b0601040182371402040c1e0a00530075006200430041300b0603551d0f040403020186300f0603551d130101ff040530030101ff301f0603551d2304183016801445665243e17e5811bfd64e9e2355083b3a226aa8305c0603551d1f045530533051a04fa04d864b687474703a2f2f63726c2e6d6963726f736f66742e636f6d2f706b692f63726c2f70726f64756374732f4d6963436f725468695061724d6172526f6f5f323031302d31302d30352e63726c306006082b0601050507010104543052305006082b060105050730028644687474703a2f2f7777772e6d6963726f736f66742e636f6d2f706b692f63657274732f4d6963436f725468695061724d6172526f6f5f323031302d31302d30352e637274300d06092a864886f70d01010b05000382020100350842ff30cccef7760cad1068583529463276277cef124127421b4aaa6d813848591355f3e95834a6160b82aa5dad82da808341068fb41df203b9f31a5d1bf15090f9b3558442281c20bdb2ae5114c5c0ac9795211c90db0ffc779e95739188cabdbd52b905500ddf579ea061ed0de56d25d9400f1740c8cea34ac24daf9a121d08548fbdc7bcb92b3d492b1f32fc6a21694f9bc87e4234fc3606178b8f2040c0b39a257527cdc903a3f65dd1e736547ab950b5d312d107bfbb74dfdc1e8f80d5ed18f42f14166b2fde668cb023e5c784d8edeac13382ad564b182df1689507cdcff072f0aebbdd8685982c214c332bf00f4af06887b592553275a16a826a3ca32511a4edadd704aecbd84059a084d1954c6291221a741d8c3d470e44a6e4b09b3435b1fab653a82c81eca40571c89db8bae81b4466e447540e8e567fb39f1698b286d0683e9023b52f5e8f50858dc68d825f41a1f42e0de099d26c75e4b669b52186fa07d1f6e24dd1daad2c77531e253237c76c52729586b0f135616a19f5b23b815056a6322dfea289f94286271855a182ca5a9bf830985414a64796252fc826e441941a5c023fe596e3855b3c3e3fbb47167255e22522b1d97be703062aa3f71e9046c3000dd61989e30e352762037115a6efd027a0a0593760f83894b8e07870f8ba4c868794f6e0ae0245ee65c2b6a37e69167507929bf5a6bc598358a159c0a5e494a74a87b5ab155c2bf0720706000000000000eb050000d2fa81d2888da44797925baa47bb1b89308205d7308203bfa003020102020a61077656000000000008300d06092a864886f70d01010b0500308188310b3009060355040613025553311330110603550408130a57617368696e67746f6e3110300e060355040713075265646d6f6e64311e301c060355040a13154d6963726f736f667420436f72706f726174696f6e31323030060355040313294d6963726f736f667420526f6f7420436572746966696361746520417574686f726974792032303130301e170d3131313031393138343134325a170d3236313031393138353134325a308184310b3009060355040613025553311330110603550408130a57617368696e67746f6e3110300e060355040713075265646d6f6e64311e301c060355040a13154d6963726f736f667420436f72706f726174696f6e312e302c060355040313254d6963726f736f66742057696e646f77732050726f64756374696f6e20504341203230313130820122300d06092a864886f70d01010105000382010f003082010a0282010100dd0cbba2e42e09e3e7c5f79669bc0021bd693333efad04cb5480ee0683bbc52084d9f7d28bf338b0aba4ad2d7c627905ffe34a3f04352070e3c4e76be09cc03675e98a31dd8d70e5dc37b5744696285b8760232cbfdc47a567f751279e72eb07a6c9b91e3b53357ce5d3ec27b9871cfeb9c923096fa84691c16e963c41d3cba33f5d026a4dec691f25285c36fffd43150a94e019b4cfdfc212e2c25b27ee2778308b5b2a096b22895360162cc0681d53baec49f39d618c85680973445d7da2542bdd79f715cf355d6c1c2b5ccebc9c238b6f6eb526d93613c34fd627aeb9323b41922ce1c7cd77e8aa544ef75c0b048765b44318a8b2e06d1977ec5a24fa48030203010001a38201433082013f301006092b06010401823715010403020100301d0603551d0e04160414a92902398e16c49778cd90f99e4f9ae17c55af53301906092b0601040182371402040c1e0a00530075006200430041300b0603551d0f040403020186300f0603551d130101ff040530030101ff301f0603551d23041830168014d5f656cb8fe8a25c6268d13d94905bd7ce9a18c430560603551d1f044f304d304ba049a0478645687474703a2f2f63726c2e6d6963726f736f66742e636f6d2f706b692f63726c2f70726f64756374732f4d6963526f6f4365724175745f323031302d30362d32332e63726c305a06082b06010505070101044e304c304a06082b06010505073002863e687474703a2f2f7777772e6d6963726f736f66742e636f6d2f706b692f63657274732f4d6963526f6f4365724175745f323031302d30362d32332e637274300d06092a864886f70d01010b0500038202010014fc7c7151a579c26eb2ef393ebc3c520f6e2b3f101373fea868d048a6344d8a960526ee3146906179d6ff382e456bf4c0e528b8da1d8f8adb09d71ac74c0a36666a8cec1bd70490a81817a49bb9e240323676c4c15ac6bfe404c0ea16d3acc368ef62acdd546c503058a6eb7cfe94a74e8ef4ec7c867357c2522173345af3a38a56c804da0709edf88be3cef47e8eaef0f60b8a08fb3fc91d727f53b8ebbe63e0e33d3165b081e5f2accd16a49f3da8b19bc242d090845f541dff89eaba1d47906fb0734e419f409f5fe5a12ab21191738a2128f0cede73395f3eab5c60ecdf0310a8d309e9f4f69685b67f51886647198da2b0123d812a680577bb914c627bb6c107c7ba7a8734030e4b627a99e9cafcce4a37c92da4577c1cfe3ddcb80f5afad6c4b30285023aeab3d96ee4692137de81d1f675190567d393575e291b39c8ee2de1cde445735bd0d2ce7aab1619824658d05e9d81b367af6c35f2bce53f24e235a20a7506f6185699d4782cd1051bebd088019daa10f105dfba7e2c63b7069b2321c4f9786ce2581706362b911203cca4d9f22dbaf9949d40ed1845f1ce8a5c6b3eab03d370182a0a6ae05f47d1d5630a32f2afd7361f2a705ae5425908714b57ba7e8381f0213cf41cc1c5b990930e88459386e9b12099be98cbc595a45d62d6a0630820bd7510777d3df345b99f979fcb57806f33a904cf77a4621c597e"
  PCRIndex: 7
  EventType: EV_EFI_VARIABLE_DRIVER_CONFIG
  DigestCount: 1
  Digests:
  - AlgorithmId: sha1
    Digest: "5ef71a8780668451ae0612df9ba57cfb5e9ce5b4"
  EventSize: 11974
  Event:
    VariableName: d719b2cb-3d3a-4596-a3bc-dad00e67656f
    UnicodeNameLength: 3
    VariableDataLength: 11936
    UnicodeName: dbx
    VariableData: "a159c0a5e494a74a87b5ab155c2bf072500400000000000034040000bd9afa775903324dbd6028f4e78f784b3082042030820308a003020102020101300d06092a864886f70d01010b0500308184310b30090603550406130247423114301206035504080c0b49736c65206f66204d616e3110300e06035504070c07446f75676c617331173015060355040a0c0e43616e6f6e6963616c204c74642e3134303206035504030c2b43616e6f6e6963616c204c74642e204d617374657220436572746966696361746520417574686f72697479301e170d3132303431323131333930385a170d3432303431313131333930385a307f310b30090603550406130247423114301206035504080c0b49736c65206f66204d616e31173015060355040a0c0e43616e6f6e6963616c204c74642e31143012060355040b0c0b53656375726520426f6f74312b302906035504030c2243616e6f6e6963616c204c74642e2053656375726520426f6f74205369676e696e6730820122300d06092a864886f70d01010105000382010f003082010a0282010100c95f9b628f0bb06482acbec9e262e34bd29f1e8ad5611a2b5d38f4b7ceb99ab843b8439777ab4f7f0c70460bfc7f6dc66dea805e01d2b7661e87de0d6dd04197a8a5af0c634ff77cc252cca031a9bb895d991e466f5573b97669ecd7c1fc21d6c607e74fbd22dee4a85b2ddb95341997d6284b214ccabb1d79a6177f5af967e65c78453d106db017592611c557e37f4e82baf62c4ec8374dff85158447e0ed3b7c7fbcafe90105a70c6fc3e98da3cebea6e3cd3cb5582c9ec2031c60223739ff4102c129a46551ff3334aa4215f99578fc2df5da8a857c829dfb372c6ba5a8df7c550b802e3cb063e1cd384889e814060b82bcfdd407681b0f3ed915dd94111b0203010001a381a030819d300c0603551d130101ff04023000301f0603551d250418301606082b06010505070303060a2b0601040182370a0306302c06096086480186f842010d041f161d4f70656e53534c2047656e657261746564204365727469666963617465301d0603551d0e0416041461482aa2830d0ab2ad5af10b7250da9033ddcef0301f0603551d23041830168014ad91990bc22ab1f517048c23b6655a268e345a63300d06092a864886f70d01010b050003820101008f8aa1061f29b70a4ad5c5fd81ab25eac07de2fc6a96a0799367ee050e251225e45af6aa1af112f3058d875ef15a5ccb8d2373651d15b9de226bd64967c9a3c6d7624e5cb5f903834081dc879c3c3f1c0d519f94650a844867e4a2f8a64af0e7cdcdbd94e309d25d2d161b05150bcb44b43e614222c42a5c4ec51da3e2e052b2ebf48b2bdc38395dfb88a156655f2b4f26ff06781012eb8c5d32e3c645af259ba0ff8eef4709a3e98b37929269767e343b9205674eb025edbc5e5f8fb4d6ca40ffe4e231230c8525ae0c5501ece5475edf5bbc1433e3c6f518b6d9f7ddb3b4a131d35a5c5d7d3ebf0ae4e4e8b4597d3bb48ca31bb520a3b93e846f8c2100c339a159c0a5e494a74a87b5ab155c2bf072b8040000000000009c040000bd9afa775903324dbd6028f4e78f784b3082048830820370a00302010202090d1c395ca7927a50c2300d06092a864886f70d01010b050030413110300e060355040b1307546f6c696d616e310e300c060355040a1305436973636f311d301b060355040313145669727475616c205545464920526f6f742043413020170d3138303430333137343733345a180f32303939303430333136313933305a303f310e300c060355040a0c05436973636f3110300e060355040b0c07416e7461726573311b301906035504030c125669727475616c205545464920537562434130820122300d06092a864886f70d01010105000382010f003082010a0282010100b84d86d021a22b199f900aa67798315c1a57c0eb138d3e9361f2657ed1e68822cd08a58b184f9d2ff84b1e6891ef4c51c2f77f67f41946a789fd420fe1a4ce4b6a296740c867ec8fe9e0defcf0e2ad45f0d2a857bb8b0ba38a7355e357d3fcc2c48fea50fa82494866b1782ba24755483c6463b410ca6ba63b1375285603be793424e2151eecfb47dfd354b3f9136cf4eb20df105e1461110dddea9c00f946a893576705ed52fa577392728077b08a18665f5d38aa9e0c8a94934b10da0700314b9ab640d75f2c32925cb44b28da02128f1184b245a7169d527af119d3c9879b5073caccd5f7d35c268962a4f347ebf543ab1c9c9e007040a135f1cd78eac5b10203010001a38201813082017d300e0603551d0f0101ff04040302010630120603551d130101ff040830060101ff020100307e06082b0601050507010104723070304006082b060105050730028634687474703a2f2f7777772e636973636f2e636f6d2f73656375726974792f706b692f63657274732f76756566697263612e636572302c06082b060105050730018620687474703a2f2f706b696376732e636973636f2e636f6d2f706b692f6f637370301f0603551d23041830168014e01bc7aabac7da1108e90a6f15da521e630aed4830520603551d20044b30493047060a2b060104010915012b003039303706082b06010505070201162b687474703a2f2f7777772e636973636f2e636f6d2f73656375726974792f706b692f706f6c69636965732f30430603551d1f043c303a3038a036a0348632687474703a2f2f7777772e636973636f2e636f6d2f73656375726974792f706b692f63726c2f76756566697263612e63726c301d0603551d0e0416041413df2e3f54ebf347dcaecebf21d3cbb2355a4c9a300d06092a864886f70d01010b050003820101006191c18e5d3b877604881887dc31b5812a54f3d20bd21c85b98e1671847eb7b6bed45c5f6f0b3dcbeed51811ec86f570d6f50b27940f4bd27569bacb42cfb7690654d618fe8c82acac22ee61de8ede9760194ee24fe50f9fcd609fc809c3f61f5c2409c8cf7f0174b1d81856b56dc1b0509401cd1b352bf7159dac814b2f260c15f40dbb498bae6c71a2dd2eafb04f9097daae8a68cc2026bd3148264be403a56fb1066c5b650c47c7c22b648584c9bee2a0640eba6660fd212cf841e0d74437ce725f3424ca36c80fd9f665f3565bca83cafc81f40e47f8fa89d42bf6d3178c551ed2fd732f948975acd715f5ed9014bc155bda8c640c26c7b6f4b59f9ab8d7a159c0a5e494a74a87b5ab155c2bf0722c0300000000000010030000bd9afa775903324dbd6028f4e78f784b308202fc308201e4a003020102020500a7468def300d06092a864886f70d01010b05003020311e301c0603550403131544656269616e2053656375726520426f6f74204341301e170d3136303831363138323235305a170d3236303831363138323235305a3024312230200603550403131944656269616e2053656375726520426f6f74205369676e657230820122300d06092a864886f70d01010105000382010f003082010a0282010100d3d183900fda65a22f075a6095ebf7c7867c2086da65a3a612eb5b3bcec8fb3fa1724b9edf50c50333a40c2b5fd641040db6cf9548ed8ab2add6e501374e60cdb24a3804b3448094af9f6e54dba81f3cb74b30de21816f09a366ba6a2b96d69a61770cd4ed3cd071bbad8cf0225c3e25cc6d222e619795af9b2e4d58b67e7802c30eb9fab25b27de7da2be0c14ac73ec97b0155eedede5a5753f78e071ce2fce83ed533130984ee6f901a28888a623087c0db7543a1695ed5e795e904efecdaade82fcf696714e4949b9d3e9b0ab7fd72a47b75330277cdc6698096fd17ef57f3d3ed4a26a8859022f2f3dc8c628de42fed9523d24c2fc409811f676bf8cbb650203010001a3393037301106096086480186f842010104040302041030150603551d25040e300c060a2b0601040182370a0301300b0603551d0f040403020780300d06092a864886f70d01010b05000382010100571ba4604c29e9f27d6b5c93dbcc6c9f183f69489a75de64f3834a09a92621eee9565de13ed975cbcc7fbf4de4e8893d7e11428740c3d5e07179dc006ce17162c798c2cb270b2f9fccecfa8bb2f30b9ef3f2c3c99fdb259390a4cdbb01e58ef4d755a8b4754131fd4e5d0318a0c2acc5de46e7dc1ccf12d59de8479d938c32cd44d574c7309a57a556d07ecf0511b4f4f329f9db9b53d2bd2fad6a75264564baba2896878eb7f07957fa7a0e3c4a3892bcf295f2e728d0f7d8981a5e399eb56580bdf3da123f507667299fd10b0a1e87975c72dbf301744add07ba76e96afcdd22db4602d7af0ac5ed15bc0f2ba9db8dbf7f6fada2b7c54d4a47b3c15690b6172616c4c14c509240aca941f9369343286c2200000000000030000000bd9afa775903324dbd6028f4e78f784b80b4d96931bf0d02fd91a61e19d14f1da452e66db2408ca8604d411f92659f0abd9afa775903324dbd6028f4e78f784bf52f83a3fa9cfbd6920f722824dbe4034534d25b8507246b3b957dac6e1bce7abd9afa775903324dbd6028f4e78f784bc5d9d8a186e2c82d09afaa2a6f7f2e73870d3e64f72c4e08ef67796a840f0fbdbd9afa775903324dbd6028f4e78f784b1aec84b84b6c65a51220a9be7181965230210d62d6d33c48999c6b295a2b0a06bd9afa775903324dbd6028f4e78f784bc3a99a460da464a057c3586d83cef5f4ae08b7103979ed8932742df0ed530c66bd9afa775903324dbd6028f4e78f784b58fb941aef95a25943b3fb5f2510a0df3fe44c58c95e0ab80487297568ab9771bd9afa775903324dbd6028f4e78f784b5391c3a2fb112102a6aa1edc25ae77e19f5d6f09cd09eeb2509922bfcd5992eabd9afa775903324dbd6028f4e78f784bd626157e1d6a718bc124ab8da27cbb65072ca03a7b6b257dbdcbbd60f65ef3d1bd9afa775903324dbd6028f4e78f784bd063ec28f67eba53f1642dbf7dff33c6a32add869f6013fe162e2c32f1cbe56dbd9afa775903324dbd6028f4e78f784b29c6eb52b43c3aa18b2cd8ed6ea8607cef3cfae1bafe1165755cf2e614844a44bd9afa775903324dbd6028f4e78f784b90fbe70e69d633408d3e170c6832dbb2d209e0272527dfb63d49d29572a6f44cbd9afa775903324dbd6028f4e78f784b106faceacfecfd4e303b74f480a08098e2d0802b936f8ec774ce21f31686689cbd9afa775903324dbd6028f4e78f784b174e3a0b5b43c6a607bbd3404f05341e3dcf396267ce94f8b50e2e23a9da920cbd9afa775903324dbd6028f4e78f784b2b99cf26422e92fe365fbf4bc30d27086c9ee14b7a6fff44fb2f6b9001699939bd9afa775903324dbd6028f4e78f784b2e70916786a6f773511fa7181fab0f1d70b557c6322ea923b2a8d3b92b51af7dbd9afa775903324dbd6028f4e78f784b3fce9b9fdf3ef09d5452b0f95ee481c2b7f06d743a737971558e70136ace3e73bd9afa775903324dbd6028f4e78f784b47cc086127e2069a86e03a6bef2cd410f8c55a6d6bdb362168c31b2ce32a5adfbd9afa775903324dbd6028f4e78f784b71f2906fd222497e54a34662ab2497fcc81020770ff51368e9e3d9bfcbfd6375bd9afa775903324dbd6028f4e78f784b82db3bceb4f60843ce9d97c3d187cd9b5941cd3de8100e586f2bda5637575f67bd9afa775903324dbd6028f4e78f784b8ad64859f195b5f58dafaa940b6a6167acd67a886e8f469364177221c55945b9bd9afa775903324dbd6028f4e78f784b8d8ea289cfe70a1c07ab7365cb28ee51edd33cf2506de888fbadd60ebf80481cbd9afa775903324dbd6028f4e78f784baeebae3151271273ed95aa2e671139ed31a98567303a332298f83709a9d55aa1bd9afa775903324dbd6028f4e78f784bc409bdac4775add8db92aa22b5b718fb8c94a1462c1fe9a416b95d8a3388c2fcbd9afa775903324dbd6028f4e78f784bc617c1a8b1ee2a811c28b5a81b4c83d7c98b5b0c27281d610207ebe692c2967fbd9afa775903324dbd6028f4e78f784bc90f336617b8e7f983975413c997f10b73eb267fd8a10cb9e3bdbfc667abdb8bbd9afa775903324dbd6028f4e78f784b64575bd912789a2e14ad56f6341f52af6bf80cf94400785975e9f04e2d64d745bd9afa775903324dbd6028f4e78f784b45c7c8ae750acfbb48fc37527d6412dd644daed8913ccd8a24c94d856967df8ebd9afa775903324dbd6028f4e78f784b81d8fb4c9e2e7a8225656b4b8273b7cba4b03ef2e9eb20e0a0291624eca1ba86bd9afa775903324dbd6028f4e78f784bb92af298dc08049b78c77492d6551b710cd72aada3d77be54609e43278ef6e4dbd9afa775903324dbd6028f4e78f784be19dae83c02e6f281358d4ebd11d7723b4f5ea0e357907d5443decc5f93c1e9dbd9afa775903324dbd6028f4e78f784b39dbc2288ef44b5f95332cb777e31103e840dba680634aa806f5c9b100061802bd9afa775903324dbd6028f4e78f784b32f5940ca29dd812a2c145e6fc89646628ffcc7c7a42cae512337d8d29c40bbdbd9afa775903324dbd6028f4e78f784b10d45fcba396aef3153ee8f6ecae58afe8476a280a2026fc71f6217dcf49ba2fbd9afa775903324dbd6028f4e78f784b4b8668a5d465bcdd9000aa8dfcff42044fcbd0aece32fc7011a83e9160e89f09bd9afa775903324dbd6028f4e78f784b89f3d1f6e485c334cd059d0995e3cdfdc00571b1849854847a44dc5548e2dcfbbd9afa775903324dbd6028f4e78f784bc9ec350406f26e559affb4030de2ebde5435054c35a998605b8fcf04972d8d55bd9afa775903324dbd6028f4e78f784bb3e506340fbf6b5786973393079f24b66ba46507e35e911db0362a2acde97049bd9afa775903324dbd6028f4e78f784b9f1863ed5717c394b42ef10a6607b144a65ba11fb6579df94b8eb2f0c4cd60c1bd9afa775903324dbd6028f4e78f784bdd59af56084406e38c63fbe0850f30a0cd1277462a2192590fb05bc259e61273bd9afa775903324dbd6028f4e78f784bdbaf9e056d3d5b38b68553304abc88827ebc00f80cb9c7e197cdbc5822cd316cbd9afa775903324dbd6028f4e78f784b65f3c0a01b8402d362b9722e98f75e5e991e6c186e934f7b2b2e6be6dec800ecbd9afa775903324dbd6028f4e78f784b5b248e913d71853d3da5aedd8d9a4bc57a917126573817fb5fcb2d86a2f1c886bd9afa775903324dbd6028f4e78f784b2679650fe341f2cf1ea883460b3556aaaf77a70d6b8dc484c9301d1b746cf7b5bd9afa775903324dbd6028f4e78f784bbb1dd16d530008636f232303a7a86f3dff969f848815c0574b12c2d787fec93fbd9afa775903324dbd6028f4e78f784b0ce02100f67c7ef85f4eed368f02bf7092380a3c23ca91fd7f19430d94b00c19bd9afa775903324dbd6028f4e78f784b95049f0e4137c790b0d2767195e56f73807d123adcf8f6e7bf2d4d991d305f89bd9afa775903324dbd6028f4e78f784b02e6216acaef6401401fa555ecbed940b1a5f2569aed92956137ae58482ef1b7bd9afa775903324dbd6028f4e78f784b6efefe0b5b01478b7b944c10d3a8aca2cca4208888e2059f8a06cb5824d7bab0bd9afa775903324dbd6028f4e78f784b9d00ae4cd47a41c783dc48f342c076c2c16f3413f4d2df50d181ca3bb5ad859dbd9afa775903324dbd6028f4e78f784bd8d4e6ddf6e42d74a6a536ea62fd1217e4290b145c9e5c3695a31b42efb5f5a4bd9afa775903324dbd6028f4e78f784bf277af4f9bdc918ae89fa35cc1b34e34984c04ae9765322c3cb049574d36509cbd9afa775903324dbd6028f4e78f784b0dc24c75eb1aef56b9f13ab9de60e2eca1c4510034e290bbb36cf60a549b234cbd9afa775903324dbd6028f4e78f784b835881f2a5572d7059b5c8635018552892e945626f115fc9ca07acf7bde857a4bd9afa775903324dbd6028f4e78f784bbadff5e4f0fea711701ca8fb22e4c43821e31e210cf52d1d4f74dd50f1d039bcbd9afa775903324dbd6028f4e78f784bc452ab846073df5ace25cca64d6b7a09d906308a1a65eb5240e3c4ebcaa9cc0cbd9afa775903324dbd6028f4e78f784bf1863ec8b7f43f94ad14fb0b8b4a69497a8c65ecbc2a55e0bb420e772b8cdc91bd9afa775903324dbd6028f4e78f784b7bc9cb5463ce0f011fb5085eb8ba77d1acd283c43f4a57603cc113f22cebc579bd9afa775903324dbd6028f4e78f784be800395dbe0e045781e8005178b4baf5a257f06e159121a67c595f6ae22506fdbd9afa775903324dbd6028f4e78f784b1cb4dccaf2c812cfa7b4938e1371fe2b96910fe407216fd95428672d6c7e7316bd9afa775903324dbd6028f4e78f784b3ece27cbb3ec4438cce523b927c4f05fdc5c593a3766db984c5e437a3ff6a16bbd9afa775903324dbd6028f4e78f784b68ee4632c7be1c66c83e89dd93eaee1294159abf45b4c2c72d7dc7499aa2a043bd9afa775903324dbd6028f4e78f784be24b315a551671483d8b9073b32de11b4de1eb2eab211afd2d9c319ff55e08d0bd9afa775903324dbd6028f4e78f784be7c20b3ab481ec885501eca5293781d84b5a1ac24f88266b5270e7ecb4aa2538bd9afa775903324dbd6028f4e78f784b7eac80a915c84cd4afec638904d94eb168a8557951a4d539b0713028552b6b8cbd9afa775903324dbd6028f4e78f784be7681f153121ea1e67f74bbcb0cdc5e502702c1b8cc55fb65d702dfba948b5f4bd9afa775903324dbd6028f4e78f784bdccc3ce1c00ee4b0b10487d372a0fa47f5c26f57a359be7b27801e144eacbac4bd9afa775903324dbd6028f4e78f784b0257ff710f2a16e489b37493c07604a7cda96129d8a8fd68d2b6af633904315dbd9afa775903324dbd6028f4e78f784b3a91f0f9e5287fa2994c7d930b2c1a5ee14ce8e1c8304ae495adc58cc4453c0cbd9afa775903324dbd6028f4e78f784b495300790e6c9bf2510daba59db3d57e9d2b85d7d7640434ec75baa3851c74e5bd9afa775903324dbd6028f4e78f784b81a8b2c9751aeb1faba7dbde5ee9691dc0eaee2a31c38b1491a8146756a6b770bd9afa775903324dbd6028f4e78f784b8e53efdc15f852cee5a6e92931bc42e6163cd30ff649cca7e87252c3a459960bbd9afa775903324dbd6028f4e78f784b9fa4d5023fd43ecaff4200ba7e8d4353259d2b7e5e72b5096eff8027d66d1043bd9afa775903324dbd6028f4e78f784bd372c0d0f4fdc9f52e9e1f23fc56ee72414a17f350d0cea6c26a35a6c3217a13bd9afa775903324dbd6028f4e78f784b5c5805196a85e93789457017d4f9eb6828b97c41cb9ba6d3dc1fcc115f527a55bd9afa775903324dbd6028f4e78f784b804e354c6368bb27a90fae8e498a57052b293418259a019c4f53a2007254490fbd9afa775903324dbd6028f4e78f784b03f64a29948a88beffdb035e0b09a7370ccf0cd9ce6bcf8e640c2107318fab87bd9afa775903324dbd6028f4e78f784b05d87e15713454616f5b0ed7849ab5c1712ab84f02349478ec2a38f970c01489bd9afa775903324dbd6028f4e78f784b06eb5badd26e4fae65f9a42358deef7c18e52cc05fbb7fc76776e69d1b982a14bd9afa775903324dbd6028f4e78f784b08bb2289e9e91b4d20ff3f1562516ab07e979b2c6cefe2ab70c6dfc1199f8da5bd9afa775903324dbd6028f4e78f784b0928f0408bf725e61d67d87138a8eebc52962d2847f16e3587163b160e41b6adbd9afa775903324dbd6028f4e78f784b09f98aa90f85198c0d73f89ba77e87ec6f596c491350fb8f8bba80a62fbb914bbd9afa775903324dbd6028f4e78f784b0a75ea0b1d70eaa4d3f374246db54fc7b43e7f596a353309b9c36b4fd975725ebd9afa775903324dbd6028f4e78f784b0c51d7906fc4931149765da88682426b2cfe9e6aa4f27253eab400111432e3a7bd9afa775903324dbd6028f4e78f784b0fa3a29ad05130d7fe5bf4d2596563cded1d874096aacc181069932a2e49519abd9afa775903324dbd6028f4e78f784b147730b42f11fe493fe902b6251e97cd2b6f34d36af59330f11d02a42f940d07bd9afa775903324dbd6028f4e78f784b148fe18f715a9fcfe1a444ce0fff7f85869eb422330dc04b314c0f295d6da79ebd9afa775903324dbd6028f4e78f784b1b909115a8d473e51328a87823bd621ce655dfae54fa2bfa72fdc0298611d6b8bd9afa775903324dbd6028f4e78f784b1d8b58c1fdb8da8b33ccee1e5f973af734d90ef317e33f5db1573c2ba088a80cbd9afa775903324dbd6028f4e78f784b1f179186efdf5ef2de018245ba0eae8134868601ba0d35ff3d9865c1537ced93bd9afa775903324dbd6028f4e78f784b270c84b29d86f16312b06aaae4ebb8dff8de7d080d825b8839ff1766274eff47bd9afa775903324dbd6028f4e78f784b29cca4544ea330d61591c784695c149c6b040022ac7b5b89cbd72800d10840eabd9afa775903324dbd6028f4e78f784b2b2298eaa26b9dc4a4558ae92e7bb0e4f85cf34bf848fdf636c0c11fbec49897bd9afa775903324dbd6028f4e78f784b2dcf8e8d817023d1e8e1451a3d68d6ec30d9bed94cbcb87f19ddc1cc0116ac1abd9afa775903324dbd6028f4e78f784b311a2ac55b50c09b30b3cc93b994a119153eeeac54ef892fc447bbbd96101aa1bd9afa775903324dbd6028f4e78f784b32ad3296829bc46dcfac5eddcb9dbf2c1eed5c11f83b2210cf9c6e60c798d4a7bd9afa775903324dbd6028f4e78f784b340da32b58331c8e2b561baf300ca9dfd6b91cd2270ee0e2a34958b1c6259e85bd9afa775903324dbd6028f4e78f784b362ed31d20b1e00392281231a96f0a0acfde02618953e695c9ef2eb0bac37550bd9afa775903324dbd6028f4e78f784b367a31e5838831ad2c074647886a6cdff217e6b1ba910bff85dc7a87ae9b5e98bd9afa775903324dbd6028f4e78f784b3765d769c05bf98b427b3511903b2137e8a49b6f859d0af159ed6a86786aa634bd9afa775903324dbd6028f4e78f784b386d695cdf2d4576e01bcaccf5e49e78da51af9955c0b8fa7606373b007994b3bd9afa775903324dbd6028f4e78f784b3a4f74beafae2b9383ad8215d233a6cf3d057fb3c7e213e897beef4255faee9dbd9afa775903324dbd6028f4e78f784b3ae76c45ca70e9180c1559981f42622dd251bca1fbe6b901c52ec11673b03514bd9afa775903324dbd6028f4e78f784b3be8e7eb348d35c1928f19c769846788991641d1f6cf09514ca10269934f7359bd9afa775903324dbd6028f4e78f784b3e3926f0b8a15ad5a14167bb647a843c3d4321e35dbc44dce8c837417f2d28b0bd9afa775903324dbd6028f4e78f784b400ac66d59b7b094a9e30b01a6bd013aff1d30570f83e7592f421dbe5ff4ba8fbd9afa775903324dbd6028f4e78f784b4185821f6dab5ba8347b78a22b5f9a0a7570ca5c93a74d478a793d83bac49805bd9afa775903324dbd6028f4e78f784b41d1eeb177c0324e17dd6557f384e532de0cf51a019a446b01efb351bc259d77bd9afa775903324dbd6028f4e78f784b45876b4dd861d45b3a94800774027a5db45a48b2a729410908b6412f8a87e95dbd9afa775903324dbd6028f4e78f784b4667bf250cd7c1a06b8474c613cdb1df648a7f58736fbf57d05d6f755dab67f4bd9afa775903324dbd6028f4e78f784b47ff1b63b140b6fc04ed79131331e651da5b2e2f170f5daef4153dc2fbc532b1bd9afa775903324dbd6028f4e78f784b57e6913afacc5222bd76cdaf31f8ed88895464255374ef097a82d7f59ad39596bd9afa775903324dbd6028f4e78f784b5890fa227121c76d90ed9e63c87e3a6533eea0f6f0a1a23f1fc445139bc6bcdfbd9afa775903324dbd6028f4e78f784b5d1e9acbbb4a7d024b6852df025970e2ced66ff622ee019cd0ed7fd841ccad02bd9afa775903324dbd6028f4e78f784b61cec4a377bf5902c0feaee37034bf97d5bc6e0615e23a1cdfbae6e3f5fb3cfdbd9afa775903324dbd6028f4e78f784b631f0857b41845362c90c6980b4b10c4b628e23dbe24b6e96c128ae3dcb0d5acbd9afa775903324dbd6028f4e78f784b65b2e7cc18d903c331df1152df73ca0dc932d29f17997481c56f3087b2dd3147bd9afa775903324dbd6028f4e78f784b66aa13a0edc219384d9c425d3927e6ed4a5d1940c5e7cd4dac88f5770103f2f1bd9afa775903324dbd6028f4e78f784b6873d2f61c29bd52e954eeff5977aa8367439997811a62ff212c948133c68d97bd9afa775903324dbd6028f4e78f784b6dbbead23e8c860cf8b47f74fbfca5204de3e28b881313bb1d1eccdc4747934ebd9afa775903324dbd6028f4e78f784b6dead13257dfc3ccc6a4b37016ba91755fe9e0ec1f415030942e5abc47f07c88bd9afa775903324dbd6028f4e78f784b70a1450af2ad395569ad0afeb1d9c125324ee90aec39c258880134d4892d51abbd9afa775903324dbd6028f4e78f784b72c26f827ceb92989798961bc6ae748d141e05d3ebcfb65d9041b266c920be82bd9afa775903324dbd6028f4e78f784b781764102188a8b4b173d4a8f5ec94d828647156097f99357a581e624b377509bd9afa775903324dbd6028f4e78f784b788383a4c733bb87d2bf51673dc73e92df15ab7d51dc715627ae77686d8d23bcbd9afa775903324dbd6028f4e78f784b78b4edcaabc8d9093e20e217802caeb4f09e23a3394c4acc6e87e8f35395310fbd9afa775903324dbd6028f4e78f784b7f49ccb309323b1c7ab11c93c955b8c744f0a2b75c311f495e18906070500027bd9afa775903324dbd6028f4e78f784b82acba48d5236ccff7659afc14594dee902bd6082ef1a30a0b9b508628cf34f4bd9afa775903324dbd6028f4e78f784b894d7839368f3298cc915ae8742ef330d7a26699f459478cf22c2b6bb2850166bd9afa775903324dbd6028f4e78f784b8c0349d708571ae5aa21c11363482332073297d868f29058916529efc520ef70bd9afa775903324dbd6028f4e78f784b8d93d60c691959651476e5dc464be12a85fa5280b6f524d4a1c3fcc9d048cfadbd9afa775903324dbd6028f4e78f784b9063f5fbc5e57ab6de6c9488146020e172b176d5ab57d4c89f0f600e17fe2de2bd9afa775903324dbd6028f4e78f784b91656aa4ef493b3824a0b7263248e4e2d657a5c8488d880cb65b01730932fb53bd9afa775903324dbd6028f4e78f784b91971c1497bf8e5bc68439acc48d63ebb8faabfd764dcbe82f3ba977cac8cf6abd9afa775903324dbd6028f4e78f784b947078f97c6196968c3ae99c9a5d58667e86882cf6c8c9d58967a496bb7af43cbd9afa775903324dbd6028f4e78f784b96e4509450d380dac362ff8e295589128a1f1ce55885d20d89c27ba2a9d00909bd9afa775903324dbd6028f4e78f784b9783b5ee4492e9e891c655f1f48035959dad453c0e623af0fe7bf2c0a57885e3bd9afa775903324dbd6028f4e78f784b97a51a094444620df38cd8c6512cac909a75fd437ae1e4d22929807661238127bd9afa775903324dbd6028f4e78f784b97a8c5ba11d61fefbb5d6a05da4e15ba472dc4c6cd4972fc1a035de321342fe4bd9afa775903324dbd6028f4e78f784b992820e6ec8c41daae4bd8ab48f58268e943a670d35ca5e2bdcd3e7c4c94a072bd9afa775903324dbd6028f4e78f784b992d359aa7a5f789d268b94c11b9485a6b1ce64362b0edb4441ccc187c39647bbd9afa775903324dbd6028f4e78f784b9954a1a99d55e8b189ab1bca414b91f6a017191f6c40a86b6f3ef368dd860031bd9afa775903324dbd6028f4e78f784b9baf4f76d76bf5d6a897bfbd5f429ba14d04e08b48c3ee8d76930a828fff3891bd9afa775903324dbd6028f4e78f784b9c259fcb301d5fc7397ed5759963e0ef6b36e42057fd73046e6bd08b149f751cbd9afa775903324dbd6028f4e78f784b9dd2dcb72f5e741627f2e9e03ab18503a3403cf6a904a479a4db05d97e2250a9bd9afa775903324dbd6028f4e78f784b9ed33f0fbc180bc032f8909ca2c4ab3418edc33a45a50d2521a3b5876aa3ea2cbd9afa775903324dbd6028f4e78f784ba4d978b7c4bda15435d508f8b9592ec2a5adfb12ea7bad146a35ecb53094642fbd9afa775903324dbd6028f4e78f784ba924d3cad6da42b7399b96a095a06f18f6b1aba5b873b0d5f3a0ee2173b48b6cbd9afa775903324dbd6028f4e78f784bad3be589c0474e97de5bb2bf33534948b76bb80376dfdc58b1fed767b5a15bfcbd9afa775903324dbd6028f4e78f784bb8d6b5e7857b45830e017c7be3d856adeb97c7290eb0665a3d473a4beb51dcf3bd9afa775903324dbd6028f4e78f784bb93f0699598f8b20fa0dacc12cfcfc1f2568793f6e779e04795e6d7c22530f75bd9afa775903324dbd6028f4e78f784bbb01da0333bb639c7e1c806db0561dc98a5316f22fef1090fb8d0be46dae499abd9afa775903324dbd6028f4e78f784bbc75f910ff320f5cb5999e66bbd4034f4ae537a42fdfef35161c5348e366e216bd9afa775903324dbd6028f4e78f784bbdd01126e9d85710d3fe75af1cc1702a29f081b4f6fdf6a2b2135c0297a9cec5bd9afa775903324dbd6028f4e78f784bbe435df7cd28aa2a7c8db4fc8173475b77e5abf392f76b7c76fa3f698cb71a9abd9afa775903324dbd6028f4e78f784bbef7663be5ea4dbfd8686e24701e036f4c03fb7fcd67a6c566ed94ce09c44470bd9afa775903324dbd6028f4e78f784bc2469759c1947e14f4b65f72a9f5b3af8b6f6e727b68bb0d91385cbf42176a8abd9afa775903324dbd6028f4e78f784bc3505bf3ec10a51dace417c76b8bd10939a065d1f34e75b8a3065ee31cc69b96bd9afa775903324dbd6028f4e78f784bc42d11c70ccf5e8cf3fb91fdf21d884021ad836ca68adf2cbb7995c10bf588d4bd9afa775903324dbd6028f4e78f784bc69d64a5b839e41ba16742527e17056a18ce3c276fd26e34901a1bc7d0e32219bd9afa775903324dbd6028f4e78f784bcb340011afeb0d74c4a588b36ebaa441961608e8d2fa80dca8c13872c850796bbd9afa775903324dbd6028f4e78f784bcc8eec6eb9212cbf897a5ace7e8abeece1079f1a6def0a789591cb1547f1f084bd9afa775903324dbd6028f4e78f784bcf13a243c1cd2e3c8ceb7e70100387cecbfb830525bbf9d0b70c79adf3e84128bd9afa775903324dbd6028f4e78f784bd89a11d16c488dd4fbbc541d4b07faf8670d660994488fe54b1fbff2704e4288bd9afa775903324dbd6028f4e78f784bd9668ab52785086786c134b5e4bddbf72452813b6973229ab92aa1a54d201bf5bd9afa775903324dbd6028f4e78f784bda3560fd0c32b54c83d4f2ff869003d2089369acf2c89608f8afa7436bfa4655bd9afa775903324dbd6028f4e78f784bdf02aab48387a9e1d4c65228089cb6abe196c8f4b396c7e4bbc395de136977f6bd9afa775903324dbd6028f4e78f784bdf91ac85a94fcd0cfb8155bd7cbefaac14b8c5ee7397fe2cc85984459e2ea14ebd9afa775903324dbd6028f4e78f784be051b788ecbaeda53046c70e6af6058f95222c046157b8c4c1b9c2cfc65f46e5bd9afa775903324dbd6028f4e78f784be36dfc719d2114c2e39aea88849e2845ab326f6f7fe74e0e539b7e54d81f3631bd9afa775903324dbd6028f4e78f784be39891f48bbcc593b8ed86ce82ce666fc1145b9fcbfd2b07bad0a89bf4c7bfbfbd9afa775903324dbd6028f4e78f784be6856f137f79992dc94fa2f43297ec32d2d9a76f7be66114c6a13efc3bcdf5c8bd9afa775903324dbd6028f4e78f784beaff8c85c208ba4d5b6b8046f5d6081747d779bada7768e649d047ff9b1f660cbd9afa775903324dbd6028f4e78f784bee83a566496109a74f6ac6e410df00bb29a290e0021516ae3b8a23288e7e2e72bd9afa775903324dbd6028f4e78f784beed7e0eff2ed559e2a79ee361f9962af3b1e999131e30bb7fd07546fae0a7267bd9afa775903324dbd6028f4e78f784bf1b4f6513b0d544a688d13adc291efa8c59f420ca5dcb23e0b5a06fa7e0d083dbd9afa775903324dbd6028f4e78f784bf2a16d35b554694187a70d40ca682959f4f35c2ce0eab8fd64f7ac2ab9f5c24abd9afa775903324dbd6028f4e78f784bf31fd461c5e99510403fc97c1da2d8a9cbe270597d32badf8fd66b77495f8d94bd9afa775903324dbd6028f4e78f784bf48e6dd8718e953b60a24f2cbea60a9521deae67db25425b7d3ace3c517dd9b7bd9afa775903324dbd6028f4e78f784bc805603c4fa038776e42f263c604b49d96840322e1922d5606a9b0bbb5bffe6fbd9afa775903324dbd6028f4e78f784b1f16078cce009df62edb9e7170e66caae670bce71b8f92d38280c56aa372031dbd9afa775903324dbd6028f4e78f784b37a480374daf6202ce790c318a2bb8aa3797311261160a8e30558b7dea78c7a6bd9afa775903324dbd6028f4e78f784b408b8b3df5abb043521a493525023175ab1261b1de21064d6bf247ce142153b9bd9afa775903324dbd6028f4e78f784b540801dd345dc1c33ef431b35bf4c0e68bd319b577b9abe1a9cff1cbc39f548f"
  PCRIndex: 7
  EventType: EV_SEPARATOR
  DigestCount: 1
  Digests:
  - AlgorithmId: sha1
    Digest: "9069ca78e7450a285173431b3e52c5c25299e473"
  EventSize: 4
  Event: "00000000"
  PCRIndex: 1
  EventType: EV_EFI_VARIABLE_BOOT
  DigestCount: 1
  Digests:
  - AlgorithmId: sha1
    Digest: "a33f5b5fd6b1caddf4a4adee107a3cc91d2d14d2"
  EventSize: 54
  Event:
    VariableName: 8be4df61-93ca-11d2-aa0d-00e098032b8c
    UnicodeNameLength: 9
    VariableDataLength: 4
    UnicodeName: BootOrder
    VariableData: "00000100"
  PCRIndex: 1
  EventType: EV_EFI_VARIABLE_BOOT
  DigestCount: 1
  Digests:
  - AlgorithmId: sha1
    Digest: "22a4f6ee9af6dba01d3528deb64b74b582fc182b"
  EventSize: 110
  Event:
    VariableName: 8be4df61-93ca-11d2-aa0d-00e098032b8c
    UnicodeNameLength: 8
    VariableDataLength: 62
    UnicodeName: Boot0000
    VariableData: "090100002c0055006900410070007000000004071400c9bdb87cebf8344faaea3ee4af6516a10406140021aa2c4614760345836e8ab6f46623317fff0400"
  PCRIndex: 1
  EventType: EV_EFI_VARIABLE_BOOT
  DigestCount: 1
  Digests:
  - AlgorithmId: sha1
    Digest: "1deddbe8c4412b10f998870099d4067be3da37f4"
  EventSize: 156
  Event:
    VariableName: 8be4df61-93ca-11d2-aa0d-00e098032b8c
    UnicodeNameLength: 8
    VariableDataLength: 108
    UnicodeName: Boot0001
    VariableData: "010000001e005500450046004900200047006f006f0067006c0065002000500065007200730069007300740065006e0074004400690073006b002000000002010c00d041030a0000000001010600000303020800010000007fff04004eac0881119f594d850ee21a522c59b2"
  PCRIndex: 4
  EventType: EV_EFI_ACTION
  DigestCount: 1
  Digests:
  - AlgorithmId: sha1
    Digest: "cd0fdb4531a6ec41be2753ba042637d6e5f7f256"
  EventSize: 40
  Event: |-
    Calling EFI Application from Boot Option
  PCRIndex: 0
  EventType: EV_SEPARATOR
  DigestCount: 1
  Digests:
  - AlgorithmId: sha1
    Digest: "9069ca78e7450a285173431b3e52c5c25299e473"
  EventSize: 4
  Event: "00000000"
  PCRIndex: 1
  EventType: EV_SEPARATOR
  DigestCount: 1
  Digests:
  - AlgorithmId: sha1
    Digest: "9069ca78e7450a285173431b3e52c5c25299e473"
  EventSize: 4
  Event: "00000000"
  PCRIndex: 2
  EventType: EV_SEPARATOR
  DigestCount: 1
  Digests:
  - AlgorithmId: sha1
    Digest: "9069ca78e7450a285173431b3e52c5c25299e473"
  EventSize: 4
  Event: "00000000"
  PCRIndex: 3
  EventType: EV_SEPARATOR
  DigestCount: 1
  Digests:
  - AlgorithmId: sha1
    Digest: "9069ca78e7450a285173431b3e52c5c25299e473"
  EventSize: 4
  Event: "00000000"
  PCRIndex: 4
  EventType: EV_SEPARATOR
  DigestCount: 1
  Digests:
  - AlgorithmId: sha1
    Digest: "9069ca78e7450a285173431b3e52c5c25299e473"
  EventSize: 4
  Event: "00000000"
  PCRIndex: 5
  EventType: EV_SEPARATOR
  DigestCount: 1
  Digests:
  - AlgorithmId: sha1
    Digest: "9069ca78e7450a285173431b3e52c5c25299e473"
  EventSize: 4
  Event: "00000000"
  PCRIndex: 6
  EventType: EV_SEPARATOR
  DigestCount: 1
  Digests:
  - AlgorithmId: sha1
    Digest: "9069ca78e7450a285173431b3e52c5c25299e473"
  EventSize: 4
  Event: "00000000"
  PCRIndex: 7
  EventType: EV_EFI_VARIABLE_AUTHORITY
  DigestCount: 1
  Digests:
  - AlgorithmId: sha1
    Digest: "0c0f8c56e09277accd603aa3cb961a2b4b81595c"
  EventSize: 1608
  Event:
    VariableName: d719b2cb-3d3a-4596-a3bc-dad00e67656f
    UnicodeNameLength: 2
    VariableDataLength: 1572
    UnicodeName: db
    VariableData: "d2fa81d2888da44797925baa47bb1b8930820610308203f8a003020102020a6108d3c4000000000004300d06092a864886f70d01010b0500308191310b3009060355040613025553311330110603550408130a57617368696e67746f6e3110300e060355040713075265646d6f6e64311e301c060355040a13154d6963726f736f667420436f72706f726174696f6e313b3039060355040313324d6963726f736f667420436f72706f726174696f6e205468697264205061727479204d61726b6574706c61636520526f6f74301e170d3131303632373231323234355a170d3236303632373231333234355a308181310b3009060355040613025553311330110603550408130a57617368696e67746f6e3110300e060355040713075265646d6f6e64311e301c060355040a13154d6963726f736f667420436f72706f726174696f6e312b3029060355040313224d6963726f736f667420436f72706f726174696f6e2055454649204341203230313130820122300d06092a864886f70d01010105000382010f003082010a0282010100a5086c4cc745096a4b0ca4c0877f06750c43015464e0167f07ed927d0bb273bf0c0ac64a4561a0c5162d96d3f52ba0fb4d499b4180903cb954fde6bcd19dc4a4188a7f418a5c59836832bb8c47c9ee71bc214f9a8a7cff443f8d8f32b22648ae75b5eec94c1e4a197ee4829a1d78774d0cb0bdf60fd316d3bcfa2ba551385df5fbbadb7802dbffec0a1b96d583b81913e9b6c07b407be11f2827c9faef565e1ce67e947ec0f044b27939e5dab2628b4dbf3870e2682414c933a40837d558695ed37cedc1045308e74eb02a876308616f631559eab22b79d70c61678a5bfd5ead877fba86674f71581222042222ce8bef547100ce503558769508ee6ab1a201d50203010001a382017630820172301206092b060104018237150104050203010001302306092b060104018237150204160414f8c16bb77f77534af325371d4ea1267b0f207080301d0603551d0e0416041413adbf4309bd82709c8cd54f316ed522988a1bd4301906092b0601040182371402040c1e0a00530075006200430041300b0603551d0f040403020186300f0603551d130101ff040530030101ff301f0603551d2304183016801445665243e17e5811bfd64e9e2355083b3a226aa8305c0603551d1f045530533051a04fa04d864b687474703a2f2f63726c2e6d6963726f736f66742e636f6d2f706b692f63726c2f70726f64756374732f4d6963436f725468695061724d6172526f6f5f323031302d31302d30352e63726c306006082b0601050507010104543052305006082b060105050730028644687474703a2f2f7777772e6d6963726f736f66742e636f6d2f706b692f63657274732f4d6963436f725468695061724d6172526f6f5f323031302d31302d30352e637274300d06092a864886f70d01010b05000382020100350842ff30cccef7760cad1068583529463276277cef124127421b4aaa6d813848591355f3e95834a6160b82aa5dad82da808341068fb41df203b9f31a5d1bf15090f9b3558442281c20bdb2ae5114c5c0ac9795211c90db0ffc779e95739188cabdbd52b905500ddf579ea061ed0de56d25d9400f1740c8cea34ac24daf9a121d08548fbdc7bcb92b3d492b1f32fc6a21694f9bc87e4234fc3606178b8f2040c0b39a257527cdc903a3f65dd1e736547ab950b5d312d107bfbb74dfdc1e8f80d5ed18f42f14166b2fde668cb023e5c784d8edeac13382ad564b182df1689507cdcff072f0aebbdd8685982c214c332bf00f4af06887b592553275a16a826a3ca32511a4edadd704aecbd84059a084d1954c6291221a741d8c3d470e44a6e4b09b3435b1fab653a82c81eca40571c89db8bae81b4466e447540e8e567fb39f1698b286d0683e9023b52f5e8f50858dc68d825f41a1f42e0de099d26c75e4b669b52186fa07d1f6e24dd1daad2c77531e253237c76c52729586b0f135616a19f5b23b815056a6322dfea289f94286271855a182ca5a9bf830985414a64796252fc826e441941a5c023fe596e3855b3c3e3fbb47167255e22522b1d97be703062aa3f71e9046c3000dd61989e30e352762037115a6efd027a0a0593760f83894b8e07870f8ba4c868794f6e0ae0245ee65c2b6a37e69167507929bf5a6bc598358"
  PCRIndex: 5
  EventType: EV_EFI_GPT_EVENT
  DigestCount: 1
  Digests:
  - AlgorithmId: sha1
    Digest: "b50b5c2f83e3f2d53e02b951031e30ed5e40cbe1"
  EventSize: 484
  Event: "4546492050415254000001005c00000002becf31000000000100000000000000ffff3f01000000000008000000000000deff3f0100000000b106deba15264f758012fd64c6fa868f02000000000000008000000080000000744d6bae0300000000000000af3dc60f838472478e793d69d8477de4132f34cac58547ff91971410155298240000040000000000deff3f010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004861682149646f6e744e656564454649cff28be3d69d448a8b722c3b8173de390008000000000000ff1f000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000028732ac11ff8d211ba4b00a0c93ec93b7eeeec490d464a00b56de902f1aebb9e0020000000000000ffff0300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
  PCRIndex: 4
  EventType: EV_EFI_BOOT_SERVICES_APPLICATION
  DigestCount: 1
  Digests:
  - AlgorithmId: sha1
    Digest: "7ba9afb9a7673220a650cca9ebb0aeff683f281c"
  EventSize: 152
  Event:
    ImageLocationInMemory: 0xbd5b0018
    ImageLengthInMemory: 930016
    ImageLinkTimeAddress: 0x0
    LengthOfDevicePath: 120
    DevicePath: '02010c00d041030a00000000010106000003030208000100000004012a000f000000002000000000000000e00300000000007eeeec490d464a00b56de902f1aebb9e0202040430005c004500460049005c0042004f004f0054005c0042004f004f0054005800360034002e0045004600490000007fff0400'
  PCRIndex: 14
  EventType: EV_IPL
  DigestCount: 1
  Digests:
  - AlgorithmId: sha1
    Digest: "28a3343cce7732bfd9a36a2f56e780ddfe3736b1"
  EventSize: 8
  Event:
    String: |-
      MokList
  PCRIndex: 14
  EventType: EV_IPL
  DigestCount: 1
  Digests:
  - AlgorithmId: sha1
    Digest: "0e04412755c9737e3f66b09cb62a0afe96105882"
  EventSize: 9
  Event:
    String: |-
      MokListX
  PCRIndex: 7
  EventType: EV_EFI_VARIABLE_AUTHORITY
  DigestCount: 1
  Digests:
  - AlgorithmId: sha1
    Digest: "15875d39b8872f8aff3a92fc9f9e40ac75268e04"
  EventSize: 68
  Event:
    VariableName: 605dab50-e046-4300-abb6-3dd810dd8b23
    UnicodeNameLength: 9
    VariableDataLength: 18
    UnicodeName: SbatLevel
    VariableData: "736261742c312c323032313033303231380a"
  PCRIndex: 4
  EventType: EV_EFI_BOOT_SERVICES_APPLICATION
  DigestCount: 1
  Digests:
  - AlgorithmId: sha1
    Digest: "3fae23b18d72350207661af3875f2c492e97621c"
  EventSize: 84
  Event:
    ImageLocationInMemory: 0xbd360018
    ImageLengthInMemory: 1549696
    ImageLinkTimeAddress: 0x0
    LengthOfDevicePath: 52
    DevicePath: '040430005c004500460049005c0042004f004f0054005c0067007200750062007800360034002e0065006600690000007fff0400'
  PCRIndex: 7
  EventType: EV_EFI_VARIABLE_AUTHORITY
  DigestCount: 1
  Digests:
  - AlgorithmId: sha1
    Digest: "2b136a029d25afc5efc9d6ac0d846fd5ca26d1d9"
  EventSize: 970
  Event:
    VariableName: 605dab50-e046-4300-abb6-3dd810dd8b23
    UnicodeNameLength: 4
    VariableDataLength: 930
    UnicodeName: Shim
    VariableData: "3082039e30820286a003020102021100ed54a1d5af8748948d9f8932ee9c7c34300d06092a864886f70d01010b05003020311e301c0603550403131544656269616e2053656375726520426f6f74204341301e170d3136303831363138303931385a170d3436303830393138303931385a3020311e301c0603550403131544656269616e2053656375726520426f6f7420434130820122300d06092a864886f70d01010105000382010f003082010a02820101009d95d48b9bda10ac2eca8237c1a4cb4ac31b4293c27a29d36edd64af80afea66a21b619c830cc56bb93525ffc5fbe82943dece4b3dc6124db1ef26439568cd0411fec2249bde14d88651e83843bdb19a15e5086bf854508bb34b5ffc14e435507c0bb1e20384a83648e480e8ea9ffabfc5187b5ece1cbe2c8078493515c021cfef66d58a96082b662f4817b1e7ec828f07e6cae05f712439500a8ed1722850a59d21f4e361ba090366c8df4e26360b150f631f2bafabc428a25664858da65541ae3c8895ddd06dd929dbd8c468b5fcf457896b14dbe0efee400d621fea58d4a3d8ba03a6972ec56b13a49177a6b5ad23a7eb0a4914467c76e99e32b489af57790203010001a381d23081cf304106082b0601050507010104353033303106082b06010505073002862568747470733a2f2f6473612e64656269616e2e6f72672f7365637572652d626f6f742d6361301f0603551d230418301680146ccece7e4c6c0d1f6149f3dd27dfcc5cbb419ea1301406096086480186f84201010101ff0404030200f730130603551d25040c300a06082b06010505070303300e0603551d0f0101ff040403020186300f0603551d130101ff040530030101ff301d0603551d0e041604146ccece7e4c6c0d1f6149f3dd27dfcc5cbb419ea1300d06092a864886f70d01010b0500038201010077963e47c9ce09cf8b89ce59ed260e260bb9ada92bbda1eb887902ff31defef56a07ef611311701ebf9c4e666ce162129701576547dd4ac6f7f4dea8f11362cc8357ac3ca69115af552672692e14cddd4db3d160242d324f196c115ef2a3f2a15f620f30aeadf14866647d36440d06343d2eaf8e9dc3adc291d837e0ee7a5f823b678e008ac4a4df3516c2722b4c51d793939eba080d5997f2e229a0444deaeef83e0260ca15cf4e9a2591843fb75ac7eebc6b80a3d9fdb26d7a1e6314ebeff1b04025d5e80e81eb6bf7cbffe52100222c2e9a3560124b5b5f3846840c069ccf72936218ee5c98d6b37d06253995df4e6076b0067b08b06ee3649f2156ad390f"
pcrs:
  sha1:
    0  : 0x0f2d3a2a1adaa479aeeca8f5df76aadc41b862ea
    1  : 0xb1676439cac1531683990fefe2218a43239d6fe8
    2  : 0xb2a83b0ebf2f8374299a5b2bdfc31ea955ad7236
    3  : 0xb2a83b0ebf2f8374299a5b2bdfc31ea955ad7236
    4  : 0xb158404e279ecc61206b8625297c88c5ed9012b9
    5  : 0x15d9fbbc4be52d0f9653ea7e7105352aee7d02f1
    6  : 0xb2a83b0ebf2f8374299a5b2bdfc31ea955ad7236
    7  : 0xacfd7eaccc8f855aa27b2c05b8b1c7c982bfbbfa
    14 : 0x7c067190e738329a729aebd84709a7063de9219c
```

---


### Applications

This is just an academic exercise (so do not use the code as is).   However, some applications of this


- [TPM based Google Service Account Credentials](https://github.com/salrashid123/oauth2#usage-tpmtokensource)
- [TPM based mTLS](https://github.com/salrashid123/signer#usage-tls)
- [Trusted Platform Module (TPM) recipes with tpm2_tools and go-tpm](https://github.com/salrashid123/tpm2)


