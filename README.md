# TPM Remote Attestation protocol using go-tpm and gRPC


This repo contains a sample `gRPC` client server application that uses a Trusted Platform Module for:

* TPM [Remote Attestation](https://tpm2-software.github.io/tpm2-tss/getting-started/2019/12/18/Remote-Attestation.html)
* TPM [Quote-Verify](https://github.com/salrashid123/tpm2/tree/master/quote_verify)
* Sealed and PCR bound Transfer of RSA or AES keys.

>>> **NOTE** the code and procedure outlined here is **NOT** supported by google.  It is just something i was interested.  _caveat emptor_

This is a 'minimal' variation of [TPM based Secret Sharing with Google Compute Engine](https://github.com/salrashid123/tpm_key_distribution) without using GCE specific metadata.
You can use this standalone to setup a gRPC client/server for remote attestation.

There are two parts:

* `server`:  a `gRPC` server which accepts connections from a client, validates the client's TPM and system state, then securely distributes a key to that client.  The key is distributed such that it can _only_ get loaded or decoded on the client that has the TPM

* `client`: a `gRPC` client which connects to the corresponding server, proves it owns a specific TPM and then receives a sealed Key that can only be decoded by that client.


On startup of the client, the first step is to establish a TLS gRPC connection to the server

Once connected, the client will acquire its Endorsement key and derive Attestation Key and sent that to the gRPC server.  The client can also acquire the Endorsement Public x509 Certificate

The Server will validate **ANY** ekpublic PEM file provided and use it to perform remote attestation.  Note, the ek x509 Certificate is also sent by the client if `--readCertsFromNV` isset.  Ideally, the x509 should get validated and used for remote attestation.  For simplicity, this repo just blindly trusts the ekPublic PEM

The server will begin remote attestation with the EKPub and AKPub provided by the client and return a sealed secret (`MakeCredential`) to the client

The client will extract the sealed secret (`ActivateCredential`) and return the secret to the server as proof that the AK and EK are related.  At this point, remote attestation is done.

The client will then ask the server if it wants to begin a Quote-Verify session.

The server will encode a nonce and return that in cleartext to the client.

The client will use the AK and generate a Quote that also reflects certain PCR values. 

The client returns the quote to the server

The server will use the saved AK to validate the quote and the PCR values.

Finally, the client can also request a sealed arbitrary secret from the server. The secret can be any RSA or AES key or any other data.

The server upon getting the request, will use the EKPub to seal a secret that can only get decoded by the TPM

The server will return the sealed secret to the client

The client will unseal and see the raw secret.


---

As you can see, the whole protocol is rather complicated but hinges on being able to trust the initial Endorsement Key.   As mentioned, this is normally done by validating that the EndorsementPublic certificate is infact real and signed by a 3rd party (eg, the manufacturer of the TPM).  In the case of google's shielded vTPM, it is signed by google's subordinate CA and includes information about the VM's instance_id value.

---

also see

 - [go-attestation](https://github.com/google/go-attestation)


## Setup

We will use a GCP Shielded VM for these tests 

First create two VMs

```bash
$ gcloud compute  instances create client --image=debian-10-buster-v20210609 --image-project=debian-cloud  \
  --machine-type "n1-standard-1"  \
  --shielded-secure-boot --shielded-vtpm --shielded-integrity-monitoring  \
  --zone us-central1-a --tags=client


$ gcloud compute  instances create server --image=debian-10-buster-v20210609 --image-project=debian-cloud  \
  --machine-type "n1-standard-1" \
  --shielded-secure-boot --shielded-vtpm --shielded-integrity-monitoring  \
  --zone us-central1-a --tags=server
```

On each, install `go 1.16+` and setup `libtspi-dev`

```bash
apt-get install libtspi-dev
```

the client  VM, edit `/etc/hosts`

and set the value of `verify.esodemoapp2.com` to the IP of the server (in my case, its `10.128.0.58`)

```
10.128.0.58 verify.esodemoapp2.com
```

ofcourse you can use any hostname here but the certificated provided in this repo matches the SAN values for TLS.


## Tests

Now test the client-server by transmitting both an RSA and AES key:

Note, you can use the client flag `--readCertsFromNV` to emit the ek certificate to the server.  The sever will just log this value but ideally, it can validate the certificate from the TPM's issuer.  The server can use the RSA public key derived from this x509 to validate the AK.  Those steps are not included in this repo...the gRPC server simply accepts the provided ekPub and akPub provided by the client.  In real scenarios, you will want to cross check the ekPub


Also note, the server is using a silly nonce/uuid _provided by the client_ to uniquely identify which ekPub,AK pair is associated with that specific client.  You will ofcourse want to do something much more sophisticated (eg, use a bearer token or mTLS client, etc).  However, even if you seal some data against a different TPMs EKPub, the other TPM cannot decrypt the secret.

### AES

```bash
$ go run src/grpc_server.go    --grpcport :50051 -pcr 0    -secret bar    -aes256Key "G-KaPdSgUkXp2s5v8y/B?E(H+MbQeThW"    -expectedPCRValue 24af52a4f429b71a3184a6d64cddad17e54ea030e2aa6576bf3a5a3d8bd3328f    --importMode=AES    --cacert  certs/CA_crt.pem     --servercert certs/server_crt.pem    --serverkey certs/server_key.pem    --usemTLS    --v=10 -alsologtostderr

$ go run src/grpc_client.go     --uid 369c327d-ad1f-401c-aa91-d9b0e69bft67     --unsealPcr=0     --host verify.esodemoapp2.com:50051     --cacert certs/CA_crt.pem     --clientcert certs/client_crt.pem    --clientkey certs/client_key.pem    --usemTLS     --v=10 -alsologtostderr
```

#### Server AES

```log
# go run src/grpc_server.go    --grpcport :50051 -pcr 0    -secret bar    -aes256Key "G-KaPdSgUkXp2s5v8y/B?E(H+MbQeThW"    -expectedPCRValue 24af52a4f429b71a3184a6d64cddad17e54ea030e2aa6576bf3a5a3d8bd3328f    --importMode=AES    --cacert  certs/CA_crt.pem     --servercert certs/server_crt.pem    --serverkey certs/server_key.pem    --usemTLS    --v=10 -alsologtostderr


I0818 12:48:37.900847    3288 grpc_server.go:209] Using mTLS for initial server connection
I0818 12:48:37.901430    3288 grpc_server.go:246] Starting gRPC server on port :50051
I0818 12:48:39.966979    3288 grpc_server.go:127] >> inbound request
I0818 12:48:39.967163    3288 grpc_server.go:146] HealthCheck called for Service [verifier.VerifierServer]
I0818 12:48:40.213079    3288 grpc_server.go:127] >> inbound request
I0818 12:48:40.213245    3288 grpc_server.go:253] ======= MakeCredential ========
I0818 12:48:40.213320    3288 grpc_server.go:254]      client provided uid: 369c327d-ad1f-401c-aa91-d9b0e69bft67
I0818 12:48:40.213384    3288 grpc_server.go:255]      Got AKName 0022000b693017abd71c953da4e379fcb4e01d2805116b81e0bcd8d507752bf6191effd3
I0818 12:48:40.213440    3288 grpc_server.go:256]      Registry size 0
I0818 12:48:40.213511    3288 grpc_server.go:258]      Decoding ekPub from client
I0818 12:48:40.213625    3288 grpc_server.go:279]      EKPubPEM: 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzUPZU9BXAUFpmZRZXyfp
2+bfAfqjV3KwCRjsMQUQ9r49kA4MwZUnlih9DrTejYdca7vNvbV92SAcXVebGWWC
T9Qyk4kwXNfem1gqK+70Cfgt68OUTZm4hDIVwrpk/7OIUdhWqm3N76JDrweaBie+
16u4OF8njLdAY3FWx9JFqIjOAk0oESxKKPKYwNOBicPiha7S1jCp+CgBEwUJ3JEa
Pa23eWwZOn2TdT+m+VXvfPL5QIEaIVgS8uF8IgR1LmW2a6R4qsa1AKzDnHK4FRAt
ycE+OYlGfUDqPCUfW80ldv/FdzCyHHaM7pSXN+MDK1UMGhfN3fw+Zo55gt+E+P3d
OQIDAQAB
-----END PUBLIC KEY-----
I0818 12:48:40.214133    3288 grpc_server.go:456]      --> Starting makeCredential()
I0818 12:48:40.214180    3288 grpc_server.go:457]      Read (ekPub) from request
I0818 12:48:40.228719    3288 grpc_server.go:470]      Read (akPub) from request
I0818 12:48:40.228937    3288 grpc_server.go:492]      Decoded AkPub: 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxdINYQmCRsfz3TQdmNcF
2bPMupusfv/ZComp9PezYOX3etqt9eWgxBtXbIJB4W2PsRzllSta7mPqJBf3kOlQ
cxeAnkCFfxlmV7B5p12nouqCn4ZMIndVcakAKtaQE9Sk/+2iqdyopj22J9uTE3oa
30IGUki9DPn3y9ULPH0W1brEh1QBAZ+vsjg2fSIGyVmGLyLBNmo4xyohCNlv6UFX
HB8J/Ia2fP8K74pfE1RhuNJ3vM/i7qMub7d/lVkB3lbl0duXOiYpulcqzD/vB09E
dUd9o8WX/R/TIY7YkhQ+UMfJOeUjkJu1xAooAM5rrbSobQ5mtt1jdKsq0yFtbKIY
BwIDAQAB
-----END PUBLIC KEY-----
I0818 12:48:40.229345    3288 grpc_server.go:495]      AK Default parameter match template
I0818 12:48:40.232328    3288 grpc_server.go:504]      Loaded AK KeyName 000b693017abd71c953da4e379fcb4e01d2805116b81e0bcd8d507752bf6191effd3
I0818 12:48:40.232418    3288 grpc_server.go:506]      MakeCredential Start
I0818 12:48:40.235502    3288 grpc_server.go:512]      credBlob 00208920735598b08cd0e9daec02fe9fb2bc81503212f404c473bb41b50f65599e8534296f8958
I0818 12:48:40.235598    3288 grpc_server.go:513]      encryptedSecret0 c5f5f190ab441613368ca9a631c49aca6edb7db786d03ba5ed8d173ad158b82a411aec1a6c6ce5d4b5ca7c10977ed8b1067efe105b3f7e6a5bad9d67496ae33d8820857cd1cdb16c488c0101aea6fdec54f7ca35a664dbd321b83823a59d153fde2d7bd80d11d8d68b91306aca0328fe761da645516ae1fb4a9c96a42c74c432e549239007c3c2c19fb3d010f5df50468d45263756d75e50ec8ae8cc0b10195627bb4ccfddf090a42fae856079f50eb5f3fd4d1bd7e39529cf4fe37f5ae9830c2f653443f1cacc09ce838ae7d52baf7cd135cc6e33e5e42888bd76dd162056900c4745179816cedf5948e40a6060954052ad1bed83272c717d86ed91cce2bfea
I0818 12:48:40.235686    3288 grpc_server.go:514]      <-- End makeCredential()
I0818 12:48:40.238451    3288 grpc_server.go:287]      Returning MakeCredentialResponse ========
I0818 12:48:41.299221    3288 grpc_server.go:127] >> inbound request
I0818 12:48:41.299441    3288 grpc_server.go:297] ======= ActivateCredential ========
I0818 12:48:41.299522    3288 grpc_server.go:298]      client provided uid: 369c327d-ad1f-401c-aa91-d9b0e69bft67
I0818 12:48:41.299591    3288 grpc_server.go:299]      Secret bar
I0818 12:48:41.299649    3288 grpc_server.go:397]      --> Starting verifyQuote()
I0818 12:48:41.299712    3288 grpc_server.go:402]      Read and Decode (attestion)
I0818 12:48:41.299740    3288 grpc_server.go:408]      Attestation ExtraData (nonce): bar 
I0818 12:48:41.299806    3288 grpc_server.go:409]      Attestation PCR#: [0] 
I0818 12:48:41.299849    3288 grpc_server.go:410]      Attestation Hash: 2ba7022b59f2158786ea3ea29a7ad12ff0c6c9d6682da6555d8926075b643b1f 
I0818 12:48:41.299894    3288 grpc_server.go:427]      Expected PCR Value:           --> 24af52a4f429b71a3184a6d64cddad17e54ea030e2aa6576bf3a5a3d8bd3328f
I0818 12:48:41.299974    3288 grpc_server.go:428]      sha256 of Expected PCR Value: --> 2ba7022b59f2158786ea3ea29a7ad12ff0c6c9d6682da6555d8926075b643b1f
I0818 12:48:41.299989    3288 grpc_server.go:430]      Decoding PublicKey for AK ========
I0818 12:48:41.300100    3288 grpc_server.go:449]      Attestation Signature Verified 
I0818 12:48:41.300156    3288 grpc_server.go:450]      <-- End verifyQuote()
I0818 12:48:41.300213    3288 grpc_server.go:307]      Verified Quote
I0818 12:48:41.300744    3288 grpc_server.go:127] >> inbound request
I0818 12:48:41.300813    3288 grpc_server.go:318] ======= OfferQuote ========
I0818 12:48:41.300872    3288 grpc_server.go:319]      client provided uid: 369c327d-ad1f-401c-aa91-d9b0e69bft67
I0818 12:48:41.300991    3288 grpc_server.go:324]      Returning OfferQuoteResponse ========
I0818 12:48:41.327146    3288 grpc_server.go:127] >> inbound request
I0818 12:48:41.327272    3288 grpc_server.go:369] ======= ProvideQuote ========
I0818 12:48:41.327319    3288 grpc_server.go:370]      client provided uid: 369c327d-ad1f-401c-aa91-d9b0e69bft67
I0818 12:48:41.327378    3288 grpc_server.go:397]      --> Starting verifyQuote()
I0818 12:48:41.327449    3288 grpc_server.go:402]      Read and Decode (attestion)
I0818 12:48:41.327511    3288 grpc_server.go:408]      Attestation ExtraData (nonce): 746db34d-596e-4946-bd14-7f78d7371fc6 
I0818 12:48:41.327566    3288 grpc_server.go:409]      Attestation PCR#: [0] 
I0818 12:48:41.327626    3288 grpc_server.go:410]      Attestation Hash: 2ba7022b59f2158786ea3ea29a7ad12ff0c6c9d6682da6555d8926075b643b1f 
I0818 12:48:41.327683    3288 grpc_server.go:427]      Expected PCR Value:           --> 24af52a4f429b71a3184a6d64cddad17e54ea030e2aa6576bf3a5a3d8bd3328f
I0818 12:48:41.327730    3288 grpc_server.go:428]      sha256 of Expected PCR Value: --> 2ba7022b59f2158786ea3ea29a7ad12ff0c6c9d6682da6555d8926075b643b1f
I0818 12:48:41.327791    3288 grpc_server.go:430]      Decoding PublicKey for AK ========
I0818 12:48:41.327971    3288 grpc_server.go:449]      Attestation Signature Verified 
I0818 12:48:41.328033    3288 grpc_server.go:450]      <-- End verifyQuote()
I0818 12:48:41.328074    3288 grpc_server.go:389]      Returning ProvideQuoteResponse ========
I0818 12:48:41.328666    3288 grpc_server.go:127] >> inbound request
I0818 12:48:41.328738    3288 grpc_server.go:334] ======= OfferImport ========
I0818 12:48:41.328782    3288 grpc_server.go:335]      client provided uid: 369c327d-ad1f-401c-aa91-d9b0e69bft67
I0818 12:48:41.328853    3288 grpc_server.go:340]      Returning OfferImportResponse ========
I0818 12:48:41.328908    3288 grpc_server.go:613]      --> Start createImportBlob()
I0818 12:48:41.328952    3288 grpc_server.go:614]      Load and decode ekPub from registry
I0818 12:48:41.329109    3288 grpc_server.go:627]      Decoding sealing PCR value in hex
I0818 12:48:41.329186    3288 grpc_server.go:663]      --> createImportBlob()
I0818 12:48:41.329266    3288 grpc_server.go:664]      Generating to AES sealedFile
I0818 12:48:41.329597    3288 grpc_server.go:677]      <-- End createImportBlob()
I0818 12:48:41.329676    3288 grpc_server.go:360]      Returning OfferImportResponse ========
```

#### Client AES

```log
# go run src/grpc_client.go     --uid 369c327d-ad1f-401c-aa91-d9b0e69bft67     --unsealPcr=0     --host verify.esodemoapp2.com:50051    --importMode=AES    --cacert certs/CA_crt.pem     --clientcert certs/client_crt.pem    --clientkey certs/client_key.pem    --usemTLS     --v=10 -alsologtostderr

I0818 12:48:39.956051    3588 grpc_client.go:164] Using mTLS
I0818 12:48:39.968202    3588 grpc_client.go:193] RPC HealthChekStatus:SERVING
I0818 12:48:39.968369    3588 grpc_client.go:295] =============== MakeCredential ===============
I0818 12:48:39.968445    3588 grpc_client.go:593]      --> CreateKeys()
I0818 12:48:39.970107    3588 grpc_client.go:600]     Current PCR 0 Value %!d(string=24af52a4f429b71a3184a6d64cddad17e54ea030e2aa6576bf3a5a3d8bd3328f) 
I0818 12:48:39.970222    3588 grpc_client.go:605]      createPrimary
I0818 12:48:40.033292    3588 grpc_client.go:623]      tpmEkPub: 
&{25912310074943480149737721308652377707854331362286193336728975248218541504080645993034560950975678532399513056308880417062110199079068652544142172301399725683268294732506196458137181173829606931841286764807519567032235006983873124002844906686926862393624844965800853567065877551555305788110047793379315987357891361132820525731803348160648899878161445715059780892112579551730826413790896942672502847230969215606156056838830702783927285766757803311828211918865358810151675418391724366492168693939686462882813953515060021765009342298258356048119007954374065947131929181833428757497901831343369824695032110355878755818809 65537}
I0818 12:48:40.033572    3588 grpc_client.go:636]      ekPub Name: 000b09aa66898e4a813be929f1ad9a8e7bcf8f877656a6be91fffc138a969f7e5a58
I0818 12:48:40.033649    3588 grpc_client.go:637]      ekPubPEM: 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzUPZU9BXAUFpmZRZXyfp
2+bfAfqjV3KwCRjsMQUQ9r49kA4MwZUnlih9DrTejYdca7vNvbV92SAcXVebGWWC
T9Qyk4kwXNfem1gqK+70Cfgt68OUTZm4hDIVwrpk/7OIUdhWqm3N76JDrweaBie+
16u4OF8njLdAY3FWx9JFqIjOAk0oESxKKPKYwNOBicPiha7S1jCp+CgBEwUJ3JEa
Pa23eWwZOn2TdT+m+VXvfPL5QIEaIVgS8uF8IgR1LmW2a6R4qsa1AKzDnHK4FRAt
ycE+OYlGfUDqPCUfW80ldv/FdzCyHHaM7pSXN+MDK1UMGhfN3fw+Zo55gt+E+P3d
OQIDAQAB
-----END PUBLIC KEY-----
I0818 12:48:40.034130    3588 grpc_client.go:644]      CreateKeyUsingAuth
I0818 12:48:40.177183    3588 grpc_client.go:670]      akPub: 0001000b00050072000000100014000b0800000000000100c5d20d61098246c7f3dd341d98d705d9b3ccba9bac7effd90a89a9f4f7b360e5f77adaadf5e5a0c41b576c8241e16d8fb11ce5952b5aee63ea2417f790e9507317809e40857f196657b079a75da7a2ea829f864c22775571a9002ad69013d4a4ffeda2a9dca8a63db627db93137a1adf42065248bd0cf9f7cbd50b3c7d16d5bac4875401019fafb238367d2206c959862f22c1366a38c72a2108d96fe941571c1f09fc86b67cff0aef8a5f135461b8d277bccfe2eea32e6fb77f955901de56e5d1db973a2629ba572acc3fef074f4475477da3c597fd1fd3218ed892143e50c7c939e523909bb5c40a2800ce6badb4a86d0e66b6dd6374ab2ad3216d6ca21807,
I0818 12:48:40.177375    3588 grpc_client.go:671]      akPriv: 0020d5bcfe7acb5825181acbddb47b1b227d9f0e1a910b31420869034c252e7252a000107c7e538c201c492ca7749c4252ff442afb3b73bbe073dbb8c6b55298d8c67ca96d381446a8ddd78bcfbe4fd0220b622c4d14ee2eb8f7ca7a80aae5b6aa2d7f3439569e72fb25dc2373c27889cff61dac14801fe92927fbc8ee26828d597ed696e19bdf540983e92b098a51f95813a87b35239ed4f7792c1052ba7e8850683f26e461339c1852aed7f0ca4c1fcc49470b1576803acdef1bd609cf889630add38cdcc69729c740c006391a389b3a80d0e2827b6a274c004bff1468,
I0818 12:48:40.177470    3588 grpc_client.go:678]      CredentialData.ParentName.Digest.Value 09aa66898e4a813be929f1ad9a8e7bcf8f877656a6be91fffc138a969f7e5a58
I0818 12:48:40.177554    3588 grpc_client.go:679]      CredentialTicket 91bc809ae3bee46e58c613234a196e6edde386dc58ac2110d18cbc6677f62839
I0818 12:48:40.177638    3588 grpc_client.go:680]      CredentialHash e77321cc3f6a0c1976bb73016fa0072bd8e2742f92748ec8ff124564a50f9d37
I0818 12:48:40.177717    3588 grpc_client.go:682]      ContextSave (ek)
I0818 12:48:40.186752    3588 grpc_client.go:693]      ContextLoad (ek)
I0818 12:48:40.194435    3588 grpc_client.go:703]      LoadUsingAuth
I0818 12:48:40.201769    3588 grpc_client.go:731]      AK keyName 0022000b693017abd71c953da4e379fcb4e01d2805116b81e0bcd8d507752bf6191effd3
I0818 12:48:40.205004    3588 grpc_client.go:753]      akPubPEM: 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxdINYQmCRsfz3TQdmNcF
2bPMupusfv/ZComp9PezYOX3etqt9eWgxBtXbIJB4W2PsRzllSta7mPqJBf3kOlQ
cxeAnkCFfxlmV7B5p12nouqCn4ZMIndVcakAKtaQE9Sk/+2iqdyopj22J9uTE3oa
30IGUki9DPn3y9ULPH0W1brEh1QBAZ+vsjg2fSIGyVmGLyLBNmo4xyohCNlv6UFX
HB8J/Ia2fP8K74pfE1RhuNJ3vM/i7qMub7d/lVkB3lbl0duXOiYpulcqzD/vB09E
dUd9o8WX/R/TIY7YkhQ+UMfJOeUjkJu1xAooAM5rrbSobQ5mtt1jdKsq0yFtbKIY
BwIDAQAB
-----END PUBLIC KEY-----
I0818 12:48:40.205545    3588 grpc_client.go:755]      Write (akPub) ========
I0818 12:48:40.205740    3588 grpc_client.go:760]      Write (akPriv) ========
I0818 12:48:40.205885    3588 grpc_client.go:766]      <-- CreateKeys()
I0818 12:48:41.239140    3588 grpc_client.go:312]      MakeCredential RPC Response with provided uid [369c327d-ad1f-401c-aa91-d9b0e69bft67]
I0818 12:48:41.239189    3588 grpc_client.go:314] =============== ActivateCredential  ===============
I0818 12:48:41.239197    3588 grpc_client.go:772]      --> activateCredential()
I0818 12:48:41.239202    3588 grpc_client.go:774]      ContextLoad (ek)
I0818 12:48:41.246462    3588 grpc_client.go:785]      Read (akPub)
I0818 12:48:41.246614    3588 grpc_client.go:790]      Read (akPriv)
I0818 12:48:41.246702    3588 grpc_client.go:796]      LoadUsingAuth
I0818 12:48:41.253813    3588 grpc_client.go:823]      keyName 0022000b693017abd71c953da4e379fcb4e01d2805116b81e0bcd8d507752bf6191effd3
I0818 12:48:41.253924    3588 grpc_client.go:825]      ActivateCredentialUsingAuth
I0818 12:48:41.266096    3588 grpc_client.go:873]      <--  activateCredential()
I0818 12:48:41.272585    3588 grpc_client.go:518]      --> Start Quote
I0818 12:48:41.274235    3588 grpc_client.go:525]      PCR 0 Value 24af52a4f429b71a3184a6d64cddad17e54ea030e2aa6576bf3a5a3d8bd3328f 
I0818 12:48:41.274347    3588 grpc_client.go:530]      ContextLoad (ek) ========
I0818 12:48:41.281727    3588 grpc_client.go:540]      LoadUsingAuth ========
I0818 12:48:41.284921    3588 grpc_client.go:562]      Read (akPub) ========
I0818 12:48:41.285045    3588 grpc_client.go:567]      Read (akPriv) ========
I0818 12:48:41.289132    3588 grpc_client.go:579]      AK keyName 0022000b693017abd71c953da4e379fcb4e01d2805116b81e0bcd8d507752bf6191effd3
I0818 12:48:41.294428    3588 grpc_client.go:585]      Quote Hex ff54434780180022000bbe29ca0bbde268c766ff8ceac08d9845d7256856c9828e22f6db7a12460b30200003626172000000004a47ee9e0000000d0000000001201605110016280000000001000b0301000000202ba7022b59f2158786ea3ea29a7ad12ff0c6c9d6682da6555d8926075b643b1f
I0818 12:48:41.294538    3588 grpc_client.go:586]      Quote Sig 7ac6a7d4dbbe6419e0118c1ef1d7579f82507f877ded0f75b5574bd9dac3cb42fad82add4b92d3f03126826e2adfc2ed82d26e5d266d919e3adb0eedf9d8b09e23058a76cd1f6aaaf20bfbec8a82bd69f1e2eb7e9c0c31bd8412d6d328e1ec2571e7dc53c2c73b9ca67ba4637f69ad1912c297f7425643aecc827effb694b28a8275c88d77c1d54969ab9f450b4245b2f4a0236194b73ad3f4b887b9b2145ce8d4cef3bcc7fad33b7f53160bd64e95ce225278e6bc85395fd176126691e705c4acca9e3ff86295602849cf02730dc636d43ae973e8b31c2b4712ec596cef3ed865db7bd3b6748f8c1c1b83eca4ddba3aefadd2454dc4351ebecbababefddf539
I0818 12:48:41.294633    3588 grpc_client.go:587]      <-- End Quote
I0818 12:48:41.300527    3588 grpc_client.go:335]     Activate Credential Status true
I0818 12:48:41.300544    3588 grpc_client.go:337] =============== OfferQuote ===============
I0818 12:48:41.301301    3588 grpc_client.go:346]      Quote Requested with nonce 746db34d-596e-4946-bd14-7f78d7371fc6, pcr: 0
I0818 12:48:41.301318    3588 grpc_client.go:348] =============== Generating Quote ===============
I0818 12:48:41.301324    3588 grpc_client.go:518]      --> Start Quote
I0818 12:48:41.302964    3588 grpc_client.go:525]      PCR 0 Value 24af52a4f429b71a3184a6d64cddad17e54ea030e2aa6576bf3a5a3d8bd3328f 
I0818 12:48:41.302979    3588 grpc_client.go:530]      ContextLoad (ek) ========
I0818 12:48:41.310230    3588 grpc_client.go:540]      LoadUsingAuth ========
I0818 12:48:41.313450    3588 grpc_client.go:562]      Read (akPub) ========
I0818 12:48:41.313614    3588 grpc_client.go:567]      Read (akPriv) ========
I0818 12:48:41.317701    3588 grpc_client.go:579]      AK keyName 0022000b693017abd71c953da4e379fcb4e01d2805116b81e0bcd8d507752bf6191effd3
I0818 12:48:41.323356    3588 grpc_client.go:585]      Quote Hex ff54434780180022000bbe29ca0bbde268c766ff8ceac08d9845d7256856c9828e22f6db7a12460b3020002437343664623334642d353936652d343934362d626431342d376637386437333731666336000000004a47eebb0000000d0000000001201605110016280000000001000b0301000000202ba7022b59f2158786ea3ea29a7ad12ff0c6c9d6682da6555d8926075b643b1f
I0818 12:48:41.323467    3588 grpc_client.go:586]      Quote Sig a697b32db5781da74c6f52be98af5694f796821d0c30101334d7c75641bbab054eae3b1f647bbfba530560dba25f20d5ce1e9b93d20ef8ad34efd005c0cc88fd4b47cb7104772cef7e49c7cd9cd93ff9386a053080b64d1ec2c5aaa33a0158783ecbc46e28c87b554e10b87d3bd1132cedf0ad6819b8fb6aa8fa6ee0a6c202e5cf2a08977fe7cbcc1878e07e39ca2ed9c55c7413d358045b22eeb34f7cbaa363db6e5ff57a533053c1eb6ac975b21dece62467d1578d16d98b8b37571c48dde8a067253a2eb1598f23fdb5eac1c757941ade4de8d129ffa87cc8c85aaeee44fc68c40753a7e901952b9d870299d6fa09c77c9b5d16dbad2ec5a33e5e38fdcf62
I0818 12:48:41.323553    3588 grpc_client.go:587]      <-- End Quote
I0818 12:48:41.326543    3588 grpc_client.go:353] =============== Providing Quote ===============
I0818 12:48:41.328418    3588 grpc_client.go:363]      Provided Quote verified: true
I0818 12:48:41.328436    3588 grpc_client.go:365] =============== OfferImport ===============
I0818 12:48:41.330025    3588 grpc_client.go:374] =============== OfferImportResponse =============== 369c327d-ad1f-401c-aa91-d9b0e69bft67
I0818 12:48:41.330047    3588 grpc_client.go:382] ===============  Importing sealed AES Key ===============
I0818 12:48:41.330052    3588 grpc_client.go:394]      --> Starting importKey()
I0818 12:48:41.330057    3588 grpc_client.go:396]      Loading EndorsementKeyRSA
I0818 12:48:41.355300    3588 grpc_client.go:412]      <-- End importKey()
I0818 12:48:41.358043    3588 grpc_client.go:387]      Unsealed Secret G-KaPdSgUkXp2s5v8y/B?E(H+MbQeThW
```


### RSA
```
go run src/grpc_server.go    --grpcport :50051 -pcr 0     -expectedPCRValue 24af52a4f429b71a3184a6d64cddad17e54ea030e2aa6576bf3a5a3d8bd3328f    --importMode=RSA    --cacert  certs/CA_crt.pem --cackey certs/CA_key.pem    --servercert certs/server_crt.pem    --serverkey certs/server_key.pem    --usemTLS    --v=10 -alsologtostderr

 go run src/grpc_client.go     --uid 369c327d-ad1f-401c-aa91-d9b0e69bft67     --unsealPcr=0     --host verify.esodemoapp2.com:50051    --clientcert certs/client_crt.pem    --clientkey certs/client_key.pem   --cacert certs/CA_crt.pem --usemTLS     --v=10 -alsologtostderr
```

#### Server RSA

```log
# go run src/grpc_server.go    --grpcport :50051 -pcr 0     -expectedPCRValue 24af52a4f429b71a3184a6d64cddad17e54ea030e2aa6576bf3a5a3d8bd3328f    --importMode=RSA    --cacert  certs/CA_crt.pem --cackey certs/CA_key.pem    --servercert certs/server_crt.pem    --serverkey certs/server_key.pem    --usemTLS    --v=10 -alsologtostderr

I0818 12:44:38.093358    3190 grpc_server.go:209] Using mTLS for initial server connection
I0818 12:44:38.094000    3190 grpc_server.go:246] Starting gRPC server on port :50051
I0818 12:44:52.125356    3190 grpc_server.go:127] >> inbound request
I0818 12:44:52.125505    3190 grpc_server.go:146] HealthCheck called for Service [verifier.VerifierServer]
I0818 12:44:52.393406    3190 grpc_server.go:127] >> inbound request
I0818 12:44:52.393557    3190 grpc_server.go:253] ======= MakeCredential ========
I0818 12:44:52.393636    3190 grpc_server.go:254]      client provided uid: 369c327d-ad1f-401c-aa91-d9b0e69bft67
I0818 12:44:52.393703    3190 grpc_server.go:255]      Got AKName 0022000baf8106bccf04a85ade2068fe6c0dddca48008b74f861b92a371192cec929e91d
I0818 12:44:52.393764    3190 grpc_server.go:256]      Registry size 0
I0818 12:44:52.393819    3190 grpc_server.go:258]      Decoding ekPub from client
I0818 12:44:52.393975    3190 grpc_server.go:279]      EKPubPEM: 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzUPZU9BXAUFpmZRZXyfp
2+bfAfqjV3KwCRjsMQUQ9r49kA4MwZUnlih9DrTejYdca7vNvbV92SAcXVebGWWC
T9Qyk4kwXNfem1gqK+70Cfgt68OUTZm4hDIVwrpk/7OIUdhWqm3N76JDrweaBie+
16u4OF8njLdAY3FWx9JFqIjOAk0oESxKKPKYwNOBicPiha7S1jCp+CgBEwUJ3JEa
Pa23eWwZOn2TdT+m+VXvfPL5QIEaIVgS8uF8IgR1LmW2a6R4qsa1AKzDnHK4FRAt
ycE+OYlGfUDqPCUfW80ldv/FdzCyHHaM7pSXN+MDK1UMGhfN3fw+Zo55gt+E+P3d
OQIDAQAB
-----END PUBLIC KEY-----
I0818 12:44:52.394496    3190 grpc_server.go:456]      --> Starting makeCredential()
I0818 12:44:52.394542    3190 grpc_server.go:457]      Read (ekPub) from request
I0818 12:44:52.406168    3190 grpc_server.go:470]      Read (akPub) from request
I0818 12:44:52.406372    3190 grpc_server.go:492]      Decoded AkPub: 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsfe1I8lVULpBgOQTnapS
VFk1otsjwKFyRp2wfhB4BaQUxuAuMTs+Muei0umCvg9Yt+ytFwSf1j2Enf10Yavr
qC4GA2n8SJEs6IqG/vQgBwn+P8a+mX9K5XqptgY3nRCC994U9ErlzpGS8zjPNo7a
O7rwtKMXiJQNZwPHmZij+74BXN9EnDhJNG6zb9uhdA27pN69KcISs4eKses5YiGu
ZZucye/X3C99HqHuF9JwtOl3tbjASd61W1fpx8Rfsah16Cab+AKdVS9+s555Iu4M
PnkVaIm+XdMQL3xW3IbB4HDaEAhFYljaXySKeLJxRRd5h3DK3MD8jsTuMG3rh2vW
gQIDAQAB
-----END PUBLIC KEY-----
I0818 12:44:52.406795    3190 grpc_server.go:495]      AK Default parameter match template
I0818 12:44:52.409739    3190 grpc_server.go:504]      Loaded AK KeyName 000baf8106bccf04a85ade2068fe6c0dddca48008b74f861b92a371192cec929e91d
I0818 12:44:52.409838    3190 grpc_server.go:506]      MakeCredential Start
I0818 12:44:52.412855    3190 grpc_server.go:512]      credBlob 0020768bbdd3b77c7403e3c13dd60115dba18c53a5326cc2cb301861cef5f2c1adfc6bd7c0d263
I0818 12:44:52.412964    3190 grpc_server.go:513]      encryptedSecret0 8354c1edf5b8c4406b205f12660a3bfed5f72622df0ee1cbf19f3934986153e7dbdf7175f81fd53e7c12c7ce23d907b32145320adb08aa00a41253f3b760cfbf780007a5e0990660dc80b9bdc120fc940223be607633143723d8a74fc82a04fa66e9d3d73a363e1e6ac65d0be9484c5fb48724d749e2c1a91ad8e469aa8666d63d705320ab815e7989dded121ccf4016146ac16b99d4e95c80fa47984e0ad3cb5988a893f73c8538f077325d11d8cc4de94c6d6daecb366dbd1481aea978c265c91079b1aab4caae9f240c0bc978738296e8b1c3e49459d9e7d38b06a5c3eeb2aa7ebf994993b9f85d9f29b121aa8855f6addf9bc138505c32b342565fb01632
I0818 12:44:52.413053    3190 grpc_server.go:514]      <-- End makeCredential()
I0818 12:44:52.415678    3190 grpc_server.go:287]      Returning MakeCredentialResponse ========
I0818 12:44:53.474158    3190 grpc_server.go:127] >> inbound request
I0818 12:44:53.474303    3190 grpc_server.go:297] ======= ActivateCredential ========
I0818 12:44:53.474377    3190 grpc_server.go:298]      client provided uid: 369c327d-ad1f-401c-aa91-d9b0e69bft67
I0818 12:44:53.474442    3190 grpc_server.go:299]      Secret foo
I0818 12:44:53.474499    3190 grpc_server.go:397]      --> Starting verifyQuote()
I0818 12:44:53.474570    3190 grpc_server.go:402]      Read and Decode (attestion)
I0818 12:44:53.474644    3190 grpc_server.go:408]      Attestation ExtraData (nonce): foo 
I0818 12:44:53.474696    3190 grpc_server.go:409]      Attestation PCR#: [0] 
I0818 12:44:53.474759    3190 grpc_server.go:410]      Attestation Hash: 2ba7022b59f2158786ea3ea29a7ad12ff0c6c9d6682da6555d8926075b643b1f 
I0818 12:44:53.474819    3190 grpc_server.go:427]      Expected PCR Value:           --> 24af52a4f429b71a3184a6d64cddad17e54ea030e2aa6576bf3a5a3d8bd3328f
I0818 12:44:53.474865    3190 grpc_server.go:428]      sha256 of Expected PCR Value: --> 2ba7022b59f2158786ea3ea29a7ad12ff0c6c9d6682da6555d8926075b643b1f
I0818 12:44:53.474977    3190 grpc_server.go:430]      Decoding PublicKey for AK ========
I0818 12:44:53.475108    3190 grpc_server.go:449]      Attestation Signature Verified 
I0818 12:44:53.475159    3190 grpc_server.go:450]      <-- End verifyQuote()
I0818 12:44:53.475229    3190 grpc_server.go:307]      Verified Quote
I0818 12:44:53.475806    3190 grpc_server.go:127] >> inbound request
I0818 12:44:53.475874    3190 grpc_server.go:318] ======= OfferQuote ========
I0818 12:44:53.475958    3190 grpc_server.go:319]      client provided uid: 369c327d-ad1f-401c-aa91-d9b0e69bft67
I0818 12:44:53.476011    3190 grpc_server.go:324]      Returning OfferQuoteResponse ========
I0818 12:44:53.502740    3190 grpc_server.go:127] >> inbound request
I0818 12:44:53.502894    3190 grpc_server.go:369] ======= ProvideQuote ========
I0818 12:44:53.502987    3190 grpc_server.go:370]      client provided uid: 369c327d-ad1f-401c-aa91-d9b0e69bft67
I0818 12:44:53.503042    3190 grpc_server.go:397]      --> Starting verifyQuote()
I0818 12:44:53.503105    3190 grpc_server.go:402]      Read and Decode (attestion)
I0818 12:44:53.503178    3190 grpc_server.go:408]      Attestation ExtraData (nonce): d32685f9-2ee5-4f9f-b98f-5e2473dfc3ca 
I0818 12:44:53.503233    3190 grpc_server.go:409]      Attestation PCR#: [0] 
I0818 12:44:53.503283    3190 grpc_server.go:410]      Attestation Hash: 2ba7022b59f2158786ea3ea29a7ad12ff0c6c9d6682da6555d8926075b643b1f 
I0818 12:44:53.503347    3190 grpc_server.go:427]      Expected PCR Value:           --> 24af52a4f429b71a3184a6d64cddad17e54ea030e2aa6576bf3a5a3d8bd3328f
I0818 12:44:53.503404    3190 grpc_server.go:428]      sha256 of Expected PCR Value: --> 2ba7022b59f2158786ea3ea29a7ad12ff0c6c9d6682da6555d8926075b643b1f
I0818 12:44:53.503452    3190 grpc_server.go:430]      Decoding PublicKey for AK ========
I0818 12:44:53.503621    3190 grpc_server.go:449]      Attestation Signature Verified 
I0818 12:44:53.503698    3190 grpc_server.go:450]      <-- End verifyQuote()
I0818 12:44:53.503750    3190 grpc_server.go:389]      Returning ProvideQuoteResponse ========
I0818 12:44:53.504292    3190 grpc_server.go:127] >> inbound request
I0818 12:44:53.504363    3190 grpc_server.go:334] ======= OfferImport ========
I0818 12:44:53.504407    3190 grpc_server.go:335]      client provided uid: 369c327d-ad1f-401c-aa91-d9b0e69bft67
I0818 12:44:53.504468    3190 grpc_server.go:340]      Returning OfferImportResponse ========
I0818 12:44:53.504521    3190 grpc_server.go:519]      --> Start generateCertificate()
I0818 12:44:53.504564    3190 grpc_server.go:520]      Generating Certificate for cn=369c327d-ad1f-401c-aa91-d9b0e69bft67
I0818 12:44:53.504807    3190 grpc_server.go:535]      Generated cert with Serial 408254118850144987185943855269412930169279703308
I0818 12:44:53.753894    3190 grpc_server.go:598]      Generating Test Signature with private Key
I0818 12:44:53.756678    3190 grpc_server.go:607]      Test signature data:  NxYj2K8xpEn0Eu1JhdVPfIQ1WYAoZMW2DGy/bzeCWErtt4F23qzvNBWTSu6VMc7UyfSy3FTfkxOz1jz2P7ooTH0pXOiW+mi57dC82aLW7bYLOnR913XHIsAA5m8yAWX1hX4p6BEtEdyYG0JGaPjwH6Oo43MY1CHiRf9hskL5mrRDczfnsF0llZyJy3UA6PU/PlIg8i6NpvuWdQRGItdnY9aSGp1r6uwzXelxXvhOOwVcVJ32VxdTL50gDrf7RqdUo1d7ctF0offp+RS+9W6XuTVVHS6M7F3pz+Ya2sarZjuwtDk3Vd9Ro/UJ9ZMxIxB4KIPUDfvw1jP959WWujL7fA
I0818 12:44:53.756761    3190 grpc_server.go:608]      <-- End generateCertificate()
I0818 12:44:53.756819    3190 grpc_server.go:613]      --> Start createImportBlob()
I0818 12:44:53.756871    3190 grpc_server.go:614]      Load and decode ekPub from registry
I0818 12:44:53.756949    3190 grpc_server.go:627]      Decoding sealing PCR value in hex
I0818 12:44:53.757014    3190 grpc_server.go:640]      --> createSigningKeyImportBlob()
I0818 12:44:53.757069    3190 grpc_server.go:641]      Generating to RSA sealedFile
I0818 12:44:53.757394    3190 grpc_server.go:655]      Returning sealed key
I0818 12:44:53.757604    3190 grpc_server.go:677]      <-- End createImportBlob()
I0818 12:44:53.757686    3190 grpc_server.go:360]      Returning OfferImportResponse ========
```

#### Client RSA

```log
# go run src/grpc_client.go     --uid 369c327d-ad1f-401c-aa91-d9b0e69bft67     --unsealPcr=0     --host verify.esodemoapp2.com:50051   --clientcert certs/client_crt.pem    --clientkey certs/client_key.pem   --cacert certs/CA_crt.pem --usemTLS     --v=10 -alsologtostderr

I0818 12:44:52.113911    3520 grpc_client.go:164] Using mTLS
I0818 12:44:52.126580    3520 grpc_client.go:193] RPC HealthChekStatus:SERVING
I0818 12:44:52.126777    3520 grpc_client.go:295] =============== MakeCredential ===============
I0818 12:44:52.126856    3520 grpc_client.go:593]      --> CreateKeys()
I0818 12:44:52.127607    3520 grpc_client.go:600]     Current PCR 0 Value %!d(string=24af52a4f429b71a3184a6d64cddad17e54ea030e2aa6576bf3a5a3d8bd3328f) 
I0818 12:44:52.127705    3520 grpc_client.go:605]      createPrimary
I0818 12:44:52.193213    3520 grpc_client.go:623]      tpmEkPub: 
&{25912310074943480149737721308652377707854331362286193336728975248218541504080645993034560950975678532399513056308880417062110199079068652544142172301399725683268294732506196458137181173829606931841286764807519567032235006983873124002844906686926862393624844965800853567065877551555305788110047793379315987357891361132820525731803348160648899878161445715059780892112579551730826413790896942672502847230969215606156056838830702783927285766757803311828211918865358810151675418391724366492168693939686462882813953515060021765009342298258356048119007954374065947131929181833428757497901831343369824695032110355878755818809 65537}
I0818 12:44:52.193488    3520 grpc_client.go:636]      ekPub Name: 000b09aa66898e4a813be929f1ad9a8e7bcf8f877656a6be91fffc138a969f7e5a58
I0818 12:44:52.193548    3520 grpc_client.go:637]      ekPubPEM: 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzUPZU9BXAUFpmZRZXyfp
2+bfAfqjV3KwCRjsMQUQ9r49kA4MwZUnlih9DrTejYdca7vNvbV92SAcXVebGWWC
T9Qyk4kwXNfem1gqK+70Cfgt68OUTZm4hDIVwrpk/7OIUdhWqm3N76JDrweaBie+
16u4OF8njLdAY3FWx9JFqIjOAk0oESxKKPKYwNOBicPiha7S1jCp+CgBEwUJ3JEa
Pa23eWwZOn2TdT+m+VXvfPL5QIEaIVgS8uF8IgR1LmW2a6R4qsa1AKzDnHK4FRAt
ycE+OYlGfUDqPCUfW80ldv/FdzCyHHaM7pSXN+MDK1UMGhfN3fw+Zo55gt+E+P3d
OQIDAQAB
-----END PUBLIC KEY-----
I0818 12:44:52.194007    3520 grpc_client.go:644]      CreateKeyUsingAuth
I0818 12:44:52.349787    3520 grpc_client.go:670]      akPub: 0001000b00050072000000100014000b0800000000000100b1f7b523c95550ba4180e4139daa52545935a2db23c0a172469db07e107805a414c6e02e313b3e32e7a2d2e982be0f58b7ecad17049fd63d849dfd7461abeba82e060369fc48912ce88a86fef4200709fe3fc6be997f4ae57aa9b606379d1082f7de14f44ae5ce9192f338cf368eda3bbaf0b4a31788940d6703c79998a3fbbe015cdf449c3849346eb36fdba1740dbba4debd29c212b3878ab1eb396221ae659b9cc9efd7dc2f7d1ea1ee17d270b4e977b5b8c049deb55b57e9c7c45fb1a875e8269bf8029d552f7eb39e7922ee0c3e79156889be5dd3102f7c56dc86c1e070da1008456258da5f248a78b2714517798770cadcc0fc8ec4ee306deb876bd681,
I0818 12:44:52.349973    3520 grpc_client.go:671]      akPriv: 002034504397e06636e95a699c891b8a20e583cffaa6f8f06f14bd8630226d3849700010c682bff52b99f048fb637425aebc41e0e711f598ee72b1b6f2e2aab2421ab2b711a347af5f6f7b330fc81665c074224bded4bd5a9bc02b6709ad924e6407f057e13da3394db162c31f49213080666bccf475a9639a17c947c3702ba01ee2813ec2f0bb5e3e1e562e313b627887f9d769d7e9f8f0f90f1a6ae9e24785bba0deb63e5f6335a3754b13f51db80db3633c2eb1aee7c08a15959ff4a47da416ed95feb70ff55654d7b27c650bf0bbf755ac9bdc4f7f26c5b86a21f65e,
I0818 12:44:52.350077    3520 grpc_client.go:678]      CredentialData.ParentName.Digest.Value 09aa66898e4a813be929f1ad9a8e7bcf8f877656a6be91fffc138a969f7e5a58
I0818 12:44:52.350163    3520 grpc_client.go:679]      CredentialTicket 365f645a08e7e2e25b5a18f7cdb3d4d3bf4b39f3fbe1d2129db2fbea20d40d6a
I0818 12:44:52.350245    3520 grpc_client.go:680]      CredentialHash e77321cc3f6a0c1976bb73016fa0072bd8e2742f92748ec8ff124564a50f9d37
I0818 12:44:52.350329    3520 grpc_client.go:682]      ContextSave (ek)
I0818 12:44:52.369824    3520 grpc_client.go:693]      ContextLoad (ek)
I0818 12:44:52.376991    3520 grpc_client.go:703]      LoadUsingAuth
I0818 12:44:52.383828    3520 grpc_client.go:731]      AK keyName 0022000baf8106bccf04a85ade2068fe6c0dddca48008b74f861b92a371192cec929e91d
I0818 12:44:52.386822    3520 grpc_client.go:753]      akPubPEM: 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsfe1I8lVULpBgOQTnapS
VFk1otsjwKFyRp2wfhB4BaQUxuAuMTs+Muei0umCvg9Yt+ytFwSf1j2Enf10Yavr
qC4GA2n8SJEs6IqG/vQgBwn+P8a+mX9K5XqptgY3nRCC994U9ErlzpGS8zjPNo7a
O7rwtKMXiJQNZwPHmZij+74BXN9EnDhJNG6zb9uhdA27pN69KcISs4eKses5YiGu
ZZucye/X3C99HqHuF9JwtOl3tbjASd61W1fpx8Rfsah16Cab+AKdVS9+s555Iu4M
PnkVaIm+XdMQL3xW3IbB4HDaEAhFYljaXySKeLJxRRd5h3DK3MD8jsTuMG3rh2vW
gQIDAQAB
-----END PUBLIC KEY-----
I0818 12:44:52.387325    3520 grpc_client.go:755]      Write (akPub) ========
I0818 12:44:52.387512    3520 grpc_client.go:760]      Write (akPriv) ========
I0818 12:44:52.387702    3520 grpc_client.go:766]      <-- CreateKeys()
I0818 12:44:53.416364    3520 grpc_client.go:312]      MakeCredential RPC Response with provided uid [369c327d-ad1f-401c-aa91-d9b0e69bft67]
I0818 12:44:53.416397    3520 grpc_client.go:314] =============== ActivateCredential  ===============
I0818 12:44:53.416410    3520 grpc_client.go:772]      --> activateCredential()
I0818 12:44:53.416415    3520 grpc_client.go:774]      ContextLoad (ek)
I0818 12:44:53.423712    3520 grpc_client.go:785]      Read (akPub)
I0818 12:44:53.423878    3520 grpc_client.go:790]      Read (akPriv)
I0818 12:44:53.423981    3520 grpc_client.go:796]      LoadUsingAuth
I0818 12:44:53.431171    3520 grpc_client.go:823]      keyName 0022000baf8106bccf04a85ade2068fe6c0dddca48008b74f861b92a371192cec929e91d
I0818 12:44:53.431287    3520 grpc_client.go:825]      ActivateCredentialUsingAuth
I0818 12:44:53.442268    3520 grpc_client.go:873]      <--  activateCredential()
I0818 12:44:53.448704    3520 grpc_client.go:518]      --> Start Quote
I0818 12:44:53.450344    3520 grpc_client.go:525]      PCR 0 Value 24af52a4f429b71a3184a6d64cddad17e54ea030e2aa6576bf3a5a3d8bd3328f 
I0818 12:44:53.450422    3520 grpc_client.go:530]      ContextLoad (ek) ========
I0818 12:44:53.457584    3520 grpc_client.go:540]      LoadUsingAuth ========
I0818 12:44:53.459677    3520 grpc_client.go:562]      Read (akPub) ========
I0818 12:44:53.459782    3520 grpc_client.go:567]      Read (akPriv) ========
I0818 12:44:53.463864    3520 grpc_client.go:579]      AK keyName 0022000baf8106bccf04a85ade2068fe6c0dddca48008b74f861b92a371192cec929e91d
I0818 12:44:53.469552    3520 grpc_client.go:585]      Quote Hex ff54434780180022000b69dd0c2d9d6e7f9ae7c2bc1025c9a102255f3b522a4140fe0da3447082ae94fb0003666f6f000000004a4474ad0000000d0000000001201605110016280000000001000b0301000000202ba7022b59f2158786ea3ea29a7ad12ff0c6c9d6682da6555d8926075b643b1f
I0818 12:44:53.469643    3520 grpc_client.go:586]      Quote Sig 108e62436863efb396679afcac535d8d04b825d431043b428799a6d3d4a217df69f223c93a2b3e6de45276b4712c7742be733602465d2f1e25de91461de80ed48bdbe53d5055a3c0a813955daaf8efbf4380770c2257ed5cc2c0b293caa8cfedce73ddb19fca7fb4ce3d2c53501eed74d898048a1e22dd4ab4b626a7e5b38aad13c550e621ff755cbc967ccedde68c71c41c763a72e8199ffadc31d36902eab4289101b5ee5c24864c073fca76df581c5078a522f0977b5579f9379d874b0a33d9a0fac5ef34ba9bc51e8709df3f1a9d4057b66713e0e5579987d2036393ee6331eeb4f7e10e1dc14d094e546718a3657c87e846dcee2d04a2a28a1c8b8d3227
I0818 12:44:53.469717    3520 grpc_client.go:587]      <-- End Quote
I0818 12:44:53.475598    3520 grpc_client.go:335]     Activate Credential Status true
I0818 12:44:53.475616    3520 grpc_client.go:337] =============== OfferQuote ===============
I0818 12:44:53.476303    3520 grpc_client.go:346]      Quote Requested with nonce d32685f9-2ee5-4f9f-b98f-5e2473dfc3ca, pcr: 0
I0818 12:44:53.476320    3520 grpc_client.go:348] =============== Generating Quote ===============
I0818 12:44:53.476327    3520 grpc_client.go:518]      --> Start Quote
I0818 12:44:53.477935    3520 grpc_client.go:525]      PCR 0 Value 24af52a4f429b71a3184a6d64cddad17e54ea030e2aa6576bf3a5a3d8bd3328f 
I0818 12:44:53.477946    3520 grpc_client.go:530]      ContextLoad (ek) ========
I0818 12:44:53.484980    3520 grpc_client.go:540]      LoadUsingAuth ========
I0818 12:44:53.488004    3520 grpc_client.go:562]      Read (akPub) ========
I0818 12:44:53.488118    3520 grpc_client.go:567]      Read (akPriv) ========
I0818 12:44:53.492264    3520 grpc_client.go:579]      AK keyName 0022000baf8106bccf04a85ade2068fe6c0dddca48008b74f861b92a371192cec929e91d
I0818 12:44:53.498160    3520 grpc_client.go:585]      Quote Hex ff54434780180022000b69dd0c2d9d6e7f9ae7c2bc1025c9a102255f3b522a4140fe0da3447082ae94fb002464333236383566392d326565352d346639662d623938662d356532343733646663336361000000004a4474c90000000d0000000001201605110016280000000001000b0301000000202ba7022b59f2158786ea3ea29a7ad12ff0c6c9d6682da6555d8926075b643b1f
I0818 12:44:53.498244    3520 grpc_client.go:586]      Quote Sig a043b03347b9a008b7ae554ccc46aa6e89514ea41a6c9173479a0ea3d16bed8f1ffca83e0de52f9555751a9d42c963b79b758074417f0ee46b69384f0890b1fc445ce65275be664ac26cfd2ac8a0693062696938fa84a0bfe018be8821bf89544e93a0b51aa019c426a13d3b3703cece6c6b7b27c3107897c8a0a90e08420fd58b4b062e8d608ccfeebff5196ec2ece89d80e9be27bd15dba57de21d76c8c83080ead8b18d70fea88de81cc86d54e9be010b3c5db2cd4b026560e35bf34b5d99b7a6b93c6812c60718b70c1bc692253c8da15480e3ee91faf22f2990ff88e777a1732a6ae26cd23c56b6ced27eba0b8476866ebdaf6a81e0926eecd1745ad56c
I0818 12:44:53.498328    3520 grpc_client.go:587]      <-- End Quote
I0818 12:44:53.502184    3520 grpc_client.go:353] =============== Providing Quote ===============
I0818 12:44:53.504058    3520 grpc_client.go:363]      Provided Quote verified: true
I0818 12:44:53.504074    3520 grpc_client.go:365] =============== OfferImport ===============
I0818 12:44:53.758128    3520 grpc_client.go:374] =============== OfferImportResponse =============== 369c327d-ad1f-401c-aa91-d9b0e69bft67
I0818 12:44:53.758156    3520 grpc_client.go:376] ===============  Importing sealed RSA Key ===============
I0818 12:44:53.758162    3520 grpc_client.go:418]      --> Starting importRSAKey()
I0818 12:44:53.758167    3520 grpc_client.go:420]      Loading EndorsementKeyRSA
I0818 12:44:53.763202    3520 grpc_client.go:427]      Loading sealedkey
I0818 12:44:53.763486    3520 grpc_client.go:435]      Loading ImportSigningKey
I0818 12:44:53.785260    3520 grpc_client.go:454]      Imported keyPublic portion: 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvyBAUIS+Iku3yXvuLhe/
tCO7shf3u2PH1rWOUYTFjegpq+7AZfzCl7DfZq39A74v751qCxt1lnsRAwsSdfET
08bPbOg6JrV8HNUTGO9PyNi3bje3PfsHYPGTOw0FpxkBtVjIXmadLj/CwpMKRVCp
TbfPN6u249fJX2ebYw1CFOQl8TT8n4q9a6grxHMJnhkmmT4TC8145x/Nbewvtye5
YMa3ClNIAl1DW7NNKKIxyo8E8jVaWZvx7lQM1Qy0Wy+Vlz224+bLFuf43fGd5roc
apki6ad009xagPEtAQtkTnheN2N6VPDLUeH/tIzVQdZXSPDmAz+PmO8PxRsKZF73
CQIDAQAB
-----END PUBLIC KEY-----
I0818 12:44:53.785840    3520 grpc_client.go:456]      Saving Key Handle as importedKey.bin
I0818 12:44:53.794629    3520 grpc_client.go:469]      Loading Key Handle
I0818 12:44:53.794716    3520 grpc_client.go:471]      ContextLoad (importedKey.bin) ========
I0818 12:44:53.802006    3520 grpc_client.go:482]     Generating Test Signature ========
I0818 12:44:53.810203    3520 grpc_client.go:511]      Test Signature data:  NxYj2K8xpEn0Eu1JhdVPfIQ1WYAoZMW2DGy/bzeCWErtt4F23qzvNBWTSu6VMc7UyfSy3FTfkxOz1jz2P7ooTH0pXOiW+mi57dC82aLW7bYLOnR913XHIsAA5m8yAWX1hX4p6BEtEdyYG0JGaPjwH6Oo43MY1CHiRf9hskL5mrRDczfnsF0llZyJy3UA6PU/PlIg8i6NpvuWdQRGItdnY9aSGp1r6uwzXelxXvhOOwVcVJ32VxdTL50gDrf7RqdUo1d7ctF0offp+RS+9W6XuTVVHS6M7F3pz+Ya2sarZjuwtDk3Vd9Ro/UJ9ZMxIxB4KIPUDfvw1jP959WWujL7fA
I0818 12:44:53.810317    3520 grpc_client.go:512]      <-- End importRSAKey()
```



### Applications

This is just an academic exercise (so do not use the code as is).   However, some applications of this


- [TPM based Google Service Account Credentials](https://github.com/salrashid123/oauth2#usage-tpmtokensource)
- [TPM based mTLS](https://github.com/salrashid123/signer#usage-tls)
- [Trusted Platform Module (TPM) recipes with tpm2_tools and go-tpm](https://github.com/salrashid123/tpm2)


