# TPM Remote Attestation protocol using go-tpm and gRPC


This repo contains a sample `gRPC` client server application that uses a Trusted Platform Module for:

It basically an implementation in go of

* TPM [Remote Attestation](https://tpm2-software.github.io/tpm2-tss/getting-started/2019/12/18/Remote-Attestation.html)
* TPM [Quote-Verify](https://github.com/salrashid123/tpm2/tree/master/quote_verify)
* Sealed and PCR bound Transfer of RSA or AES keys.

Attestation:

![images/diag1.png](images/diag1.png)

Quote/Verify:

![images/diag2.png](images/diag2.png)

( Images taken from [Remote Attestation](https://tpm2-software.github.io/tpm2-tss/getting-started/2019/12/18/Remote-Attestation.html) )

>>> **NOTE** the code and procedure outlined here is **NOT** supported by google.

This is a 'minimal' variation of [TPM based Secret Sharing with Google Compute Engine](https://github.com/salrashid123/tpm_key_distribution) without using GCE specific metadata.
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


### AES

#### Attestor AES

```log
$ go run src/grpc_attestor.go --grpcport :50051 \
 --cacert certs/CA_crt.pem --servercert certs/server_crt.pem \
 --serverkey certs/server_key.pem --pcr=0 --v=10 -alsologtostderr

I0825 14:42:01.300517    1089 grpc_attestor.go:809] Starting gRPC server on port :50051
I0825 14:42:48.026467    1089 grpc_attestor.go:144] >> inbound request
I0825 14:42:48.026621    1089 grpc_attestor.go:163] HealthCheck called for Service [verifier.VerifierServer]
I0825 14:42:48.028310    1089 grpc_attestor.go:144] >> inbound request
I0825 14:42:48.028437    1089 grpc_attestor.go:177] ======= GetPlatformCert ========
I0825 14:42:48.028509    1089 grpc_attestor.go:178]      client provided uid: 369c327d-ad1f-401c-aa91-d9b0e69bft67
CERTIFICATE
I0825 14:42:48.029438    1089 grpc_attestor.go:191]      Found Platform Cert Issuer CN=tpm_ek_v1_cloud_host_root-signer-0-2018-04-06T10:58:26-07:00 K:1\, 1:Pw003HsFYO4:0:18,OU=Cloud,O=Google LLC,L=Mountain View,ST=California,C=US ========
I0825 14:42:48.029511    1089 grpc_attestor.go:192]      Returning GetPlatformCert ========
I0825 14:42:48.030509    1089 grpc_attestor.go:144] >> inbound request
I0825 14:42:48.030605    1089 grpc_attestor.go:200] ======= GetEKCert ========
I0825 14:42:48.030673    1089 grpc_attestor.go:201]      client provided uid: 369c327d-ad1f-401c-aa91-d9b0e69bft67
I0825 14:42:48.030718    1089 grpc_attestor.go:207] =============== Load EncryptionKey and Certifcate from NV ===============
I0825 14:42:48.048274    1089 grpc_attestor.go:223]      Encryption PEM 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtua2IJy72b7y54lUS6ep
20njw0bCMVLXSAjxG+FGZSd1pyjAkbGAVT1+0uRTvX6KDHJLroIVCknvyN4meZhi
22dobbrcdISXe2klXnc2pxlE78K+gGtLP4ljd1gwXJ/mCZP4G0k2uqP0l6A5LcdF
JuTqarzmEZHBi+M4xkKyucYEJAWDl71WS1Um9NEUv/Hd0NvMjUr2exRaZjQh4DwG
omZPTKcLQNuqTMlE31Wrua+FTRlbyYjWR9dfwamTbiXm6wuUAKiR0JQq4GxT3u4G
Jg/N9wyiMpoxaxb/hc7q9+TMZadt+Hkf/VqMAz4HsVEIM+TkJEe4lvoYfOIb3JUK
RwIDAQAB
-----END PUBLIC KEY-----
I0825 14:42:48.062995    1089 grpc_attestor.go:241]      Encryption Issuer x509 tpm_ek_v1_cloud_host-signer-0-2020-10-22T14:02:08-07:00 K:1, 2:HBNpA3TPAbM:0:18
I0825 14:42:48.063133    1089 grpc_attestor.go:242]      Returning GetEKCert ========
I0825 14:42:48.065143    1089 grpc_attestor.go:144] >> inbound request
I0825 14:42:48.065258    1089 grpc_attestor.go:250] ======= GetAK ========
I0825 14:42:48.065318    1089 grpc_attestor.go:251]      client provided uid: 369c327d-ad1f-401c-aa91-d9b0e69bft67
I0825 14:42:48.067044    1089 grpc_attestor.go:258]     Current PCR 0 Value %!d(string=24af52a4f429b71a3184a6d64cddad17e54ea030e2aa6576bf3a5a3d8bd3328f) 
I0825 14:42:48.067156    1089 grpc_attestor.go:263]      createPrimary
I0825 14:42:48.203082    1089 grpc_attestor.go:281]      tpmEkPub: 
&{23089139552675222780587887552299787732028585340944175742498309644508463101452659093589404677039890944554594572429795143948307682874684239173614524550479887373291894320626553725375607694178765293383169515734945455890990827306678942980888021650170549528474226066921904885138221732563417118643706260054748731352356460408385515317443375503308713349979071975711368655541252338959361261022056674667359462771495889777624159637474812642664401278952900154357047989990136692537135987531716747962452549091677455164458016113284079928348588418702477803953202522836766126159323175422207893177540913361300513665309360796450331888199 65537}
I0825 14:42:48.203438    1089 grpc_attestor.go:294]      ekPub Name: 000ba75da1afb2672451896e3cdbe718bef45ccda34b899ecff4b9a89544af122dba
I0825 14:42:48.203525    1089 grpc_attestor.go:295]      ekPubPEM: 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtua2IJy72b7y54lUS6ep
20njw0bCMVLXSAjxG+FGZSd1pyjAkbGAVT1+0uRTvX6KDHJLroIVCknvyN4meZhi
22dobbrcdISXe2klXnc2pxlE78K+gGtLP4ljd1gwXJ/mCZP4G0k2uqP0l6A5LcdF
JuTqarzmEZHBi+M4xkKyucYEJAWDl71WS1Um9NEUv/Hd0NvMjUr2exRaZjQh4DwG
omZPTKcLQNuqTMlE31Wrua+FTRlbyYjWR9dfwamTbiXm6wuUAKiR0JQq4GxT3u4G
Jg/N9wyiMpoxaxb/hc7q9+TMZadt+Hkf/VqMAz4HsVEIM+TkJEe4lvoYfOIb3JUK
RwIDAQAB
-----END PUBLIC KEY-----
I0825 14:42:48.204014    1089 grpc_attestor.go:302]      CreateKeyUsingAuth
I0825 14:42:48.337303    1089 grpc_attestor.go:328]      akPub: 0001000b00050072000000100014000b0800000000000100ccf95bf8a110aee53c267eb2d223bafcb27a8998b62b196e5f9dd79b024cc31f1b8043f8d2b65c615b07133ec38696c2a5aa9763fcf00b2f3aef889d70acdd06efa60cd1116cfde0f960b1a019dd9c1ad8ef395b08e2d5ccafdf7a908600e99e6285aedb9568b58ceac76b59dba56cc4e9db0e7cf55a5ae8cca5ca6bf0b96a3a308ddcc18b5e211bea184d21a8385047129878ad7cbfe231fbd62a0b568b5f79695aa4fe0c244fbef3c38ad6342d58008791f4aa288466b7f863b4e6b22b98b48f6195c83fa1d43bbd852c40aba45400d6a5cdef3476190abcbff5057419ba6ee227d6b3a9a069c9ed1a2684409c5dd3bc9ced565adb1b1b07e5b679e706f7e1,
I0825 14:42:48.337460    1089 grpc_attestor.go:329]      akPriv: 00202186200ff9c57f5409461c506f0ccce61d148d63a38a96d45e12ad42597ae201001036be17956bef8fa7539479faeec035117282587e350048160230de8c7b7df4b771eb5abb1617d0dc225bd90948b1cce288fc04a9c82ca8ecac2f64a051b158abe295a5cdc13e26b9b3905998f48917f7287e202dc922ec297675505acdc041f0a9b29844dff3f312c3227d5800e753846a0eb4ab6f00c8d20646d5f04f4cf81db3ca8163964e93d2215f1e827a351a1fddd93a57c47b34786597f757b7351920c75f79a83df981bbdf4233ceb28893c81762edd2e2de3bdd3900,
I0825 14:42:48.337560    1089 grpc_attestor.go:336]      CredentialData.ParentName.Digest.Value a75da1afb2672451896e3cdbe718bef45ccda34b899ecff4b9a89544af122dba
I0825 14:42:48.337647    1089 grpc_attestor.go:337]      CredentialTicket bb544e2a6a2230ebecac382969e7641ddcf97d8c715fd110b4ebb4d4a4dc263a
I0825 14:42:48.337727    1089 grpc_attestor.go:338]      CredentialHash 22bd2ad7aed1f583f13a67ecbf6c079e443be114569bdabe636c089b79ea5cd2
I0825 14:42:48.337805    1089 grpc_attestor.go:340]      ContextSave (ek)
I0825 14:42:48.346815    1089 grpc_attestor.go:351]      ContextLoad (ek)
I0825 14:42:48.354258    1089 grpc_attestor.go:362]      LoadUsingAuth
I0825 14:42:48.361963    1089 grpc_attestor.go:390]      AK keyName 0022000bf1c11acf9a80401a114a2d039c0e14e0bd3507b6934ce4580f5b3d8eca31e7f1
I0825 14:42:48.364228    1089 grpc_attestor.go:412]      akPubPEM: 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzPlb+KEQruU8Jn6y0iO6
/LJ6iZi2KxluX53XmwJMwx8bgEP40rZcYVsHEz7DhpbCpaqXY/zwCy8674idcKzd
Bu+mDNERbP3g+WCxoBndnBrY7zlbCOLVzK/fepCGAOmeYoWu25VotYzqx2tZ26Vs
xOnbDnz1WlrozKXKa/C5ajowjdzBi14hG+oYTSGoOFBHEph4rXy/4jH71ioLVotf
eWlapP4MJE++88OK1jQtWACHkfSqKIRmt/hjtOayK5i0j2GVyD+h1Du9hSxAq6RU
ANalze80dhkKvL/1BXQZum7iJ9azqaBpye0aJoRAnF3TvJztVlrbGxsH5bZ55wb3
4QIDAQAB
-----END PUBLIC KEY-----
I0825 14:42:48.364801    1089 grpc_attestor.go:414]      Write (akPub) ========
I0825 14:42:48.365054    1089 grpc_attestor.go:419]      Write (akPriv) ========
I0825 14:42:48.365200    1089 grpc_attestor.go:429]      Returning GetAK ========
I0825 14:42:48.383282    1089 grpc_attestor.go:144] >> inbound request
I0825 14:42:48.383403    1089 grpc_attestor.go:441] ======= ActivateCredential ========
I0825 14:42:48.383449    1089 grpc_attestor.go:442]      client provided uid: 369c327d-ad1f-401c-aa91-d9b0e69bft67
I0825 14:42:48.383493    1089 grpc_attestor.go:444]      ContextLoad (ek)
I0825 14:42:48.390978    1089 grpc_attestor.go:455]      Read (akPub)
I0825 14:42:48.391169    1089 grpc_attestor.go:460]      Read (akPriv)
I0825 14:42:48.398592    1089 grpc_attestor.go:491]      keyName 0022000bf1c11acf9a80401a114a2d039c0e14e0bd3507b6934ce4580f5b3d8eca31e7f1
I0825 14:42:48.398699    1089 grpc_attestor.go:493]      ActivateCredentialUsingAuth
I0825 14:42:48.410083    1089 grpc_attestor.go:541]      <--  activateCredential()
I0825 14:42:48.417366    1089 grpc_attestor.go:144] >> inbound request
I0825 14:42:48.417492    1089 grpc_attestor.go:551] ======= Quote ========
I0825 14:42:48.417565    1089 grpc_attestor.go:552]      client provided uid: 369c327d-ad1f-401c-aa91-d9b0e69bft67
I0825 14:42:48.419227    1089 grpc_attestor.go:559]      PCR 0 Value 24af52a4f429b71a3184a6d64cddad17e54ea030e2aa6576bf3a5a3d8bd3328f 
I0825 14:42:48.419341    1089 grpc_attestor.go:564]      ContextLoad (ek) ========
I0825 14:42:48.426440    1089 grpc_attestor.go:574]      LoadUsingAuth ========
I0825 14:42:48.429739    1089 grpc_attestor.go:596]      Read (akPub) ========
I0825 14:42:48.429913    1089 grpc_attestor.go:601]      Read (akPriv) ========
I0825 14:42:48.434112    1089 grpc_attestor.go:613]      AK keyName 0022000bf1c11acf9a80401a114a2d039c0e14e0bd3507b6934ce4580f5b3d8eca31e7f1
I0825 14:42:48.439868    1089 grpc_attestor.go:619]      Quote Hex ff54434780180022000b50194fab17fb7959272b03529683da2de95d0066487d8531ce76c1fa042a8004002046704c536a466263586f45466652735778504c446e4a4f6243734e566c67546500000000006c4d01000000010000000001201605110016280000000001000b0301000000202ba7022b59f2158786ea3ea29a7ad12ff0c6c9d6682da6555d8926075b643b1f
I0825 14:42:48.440020    1089 grpc_attestor.go:620]      Quote Sig a9510dae2dd7c202f91a4b7e5013177502ab923e042367b4fdca534cd7d4c38f873507fccef3240fc916c7cdc933a581023d3f2e45ade8ff24458459199f0be244197d4eb807206a3bdfd32f576cfb63f57e83d26b03bdd286a9f74e848c906a08a377e58bc22ed70f60a5af5f4158277f148dd8d764357eb7b45357a15b2f1f32ba3d3e0eeee90bbea88f18cc8a2a139460bd19f5121e3a3158095e94d1d269cf02dba905241c4f2a5ce071c5beca2d64313374a6a47e468ccbfeb8cb42c9dd5676a2641e13049551ba9b030a2e83b8a4034d3fd02219860ce4b8e2d3d216d0e87fa2375948ce840e1cfa4710bf8d47f90595a26bbb706379fc39d9e6429f6a
I0825 14:42:48.440115    1089 grpc_attestor.go:621]      <-- End Quote
I0825 14:42:48.445750    1089 grpc_attestor.go:144] >> inbound request
I0825 14:42:48.445902    1089 grpc_attestor.go:632] ======= PushSecret ========
I0825 14:42:48.445999    1089 grpc_attestor.go:633]      client provided uid: 
I0825 14:42:48.446075    1089 grpc_attestor.go:636]      Loading EndorsementKeyRSA
I0825 14:42:48.451409    1089 grpc_attestor.go:651]      Importing External Key
I0825 14:42:48.471540    1089 grpc_attestor.go:656]      <-- End importKey()
I0825 14:42:48.471713    1089 grpc_attestor.go:660]      Hash of imported Key bZeQ9G0KuKpHVwfZuobcMf7tL/ViU1maVaJCAY+QjfU=
```

#### Verifier AES

```log
$ go run src/grpc_verifier.go --importMode=AES  --uid 369c327d-ad1f-401c-aa91-d9b0e69bft67 \
   -aes256Key "G-KaPdSgUkXp2s5v8y/B?E(H+MbQeThW" \
   --host verify.esodemoapp2.com:50051 --pcr=0 \
   --v=10 -alsologtostderr 

I0825 14:42:48.027270   26411 grpc_verifier.go:176] RPC HealthChekStatus:SERVING
I0825 14:42:48.027835   26411 grpc_verifier.go:180] =============== GetPlatformCert ===============
I0825 14:42:48.029837   26411 grpc_verifier.go:189] =============== GetPlatformCert Returned from remote ===============
I0825 14:42:48.030125   26411 grpc_verifier.go:207]     Platform Cert Issuer tpm_ek_v1_cloud_host_root-signer-0-2018-04-06T10:58:26-07:00 K:1, 1:Pw003HsFYO4:0:18
I0825 14:42:48.063676   26411 grpc_verifier.go:220] =============== GetEKCert Returned from remote ===============
I0825 14:42:48.063994   26411 grpc_verifier.go:238]     EkCert Cert Issuer tpm_ek_v1_cloud_host-signer-0-2020-10-22T14:02:08-07:00 K:1, 2:HBNpA3TPAbM:0:18
I0825 14:42:48.064112   26411 grpc_verifier.go:239]     EkCert Public Key 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtua2IJy72b7y54lUS6ep
20njw0bCMVLXSAjxG+FGZSd1pyjAkbGAVT1+0uRTvX6KDHJLroIVCknvyN4meZhi
22dobbrcdISXe2klXnc2pxlE78K+gGtLP4ljd1gwXJ/mCZP4G0k2uqP0l6A5LcdF
JuTqarzmEZHBi+M4xkKyucYEJAWDl71WS1Um9NEUv/Hd0NvMjUr2exRaZjQh4DwG
omZPTKcLQNuqTMlE31Wrua+FTRlbyYjWR9dfwamTbiXm6wuUAKiR0JQq4GxT3u4G
Jg/N9wyiMpoxaxb/hc7q9+TMZadt+Hkf/VqMAz4HsVEIM+TkJEe4lvoYfOIb3JUK
RwIDAQAB
-----END PUBLIC KEY-----

I0825 14:42:48.064685   26411 grpc_verifier.go:242] =============== GetAKCert ===============
I0825 14:42:48.371972   26411 grpc_verifier.go:251]      akPub: 0001000b00050072000000100014000b0800000000000100ccf95bf8a110aee53c267eb2d223bafcb27a8998b62b196e5f9dd79b024cc31f1b8043f8d2b65c615b07133ec38696c2a5aa9763fcf00b2f3aef889d70acdd06efa60cd1116cfde0f960b1a019dd9c1ad8ef395b08e2d5ccafdf7a908600e99e6285aedb9568b58ceac76b59dba56cc4e9db0e7cf55a5ae8cca5ca6bf0b96a3a308ddcc18b5e211bea184d21a8385047129878ad7cbfe231fbd62a0b568b5f79695aa4fe0c244fbef3c38ad6342d58008791f4aa288466b7f863b4e6b22b98b48f6195c83fa1d43bbd852c40aba45400d6a5cdef3476190abcbff5057419ba6ee227d6b3a9a069c9ed1a2684409c5dd3bc9ced565adb1b1b07e5b679e706f7e1,
I0825 14:42:48.372006   26411 grpc_verifier.go:252]      akName: 000bf1c11acf9a80401a114a2d039c0e14e0bd3507b6934ce4580f5b3d8eca31e7f1,
I0825 14:42:48.372022   26411 grpc_verifier.go:254] =============== MakeCredential ===============
I0825 14:42:48.372083   26411 grpc_verifier.go:276]      Decoded EkPublic Key: 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtua2IJy72b7y54lUS6ep
20njw0bCMVLXSAjxG+FGZSd1pyjAkbGAVT1+0uRTvX6KDHJLroIVCknvyN4meZhi
22dobbrcdISXe2klXnc2pxlE78K+gGtLP4ljd1gwXJ/mCZP4G0k2uqP0l6A5LcdF
JuTqarzmEZHBi+M4xkKyucYEJAWDl71WS1Um9NEUv/Hd0NvMjUr2exRaZjQh4DwG
omZPTKcLQNuqTMlE31Wrua+FTRlbyYjWR9dfwamTbiXm6wuUAKiR0JQq4GxT3u4G
Jg/N9wyiMpoxaxb/hc7q9+TMZadt+Hkf/VqMAz4HsVEIM+TkJEe4lvoYfOIb3JUK
RwIDAQAB
-----END PUBLIC KEY-----
I0825 14:42:48.375297   26411 grpc_verifier.go:284]      Read (akPub) from registry
I0825 14:42:48.375478   26411 grpc_verifier.go:306]      Decoded AkPub: 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzPlb+KEQruU8Jn6y0iO6
/LJ6iZi2KxluX53XmwJMwx8bgEP40rZcYVsHEz7DhpbCpaqXY/zwCy8674idcKzd
Bu+mDNERbP3g+WCxoBndnBrY7zlbCOLVzK/fepCGAOmeYoWu25VotYzqx2tZ26Vs
xOnbDnz1WlrozKXKa/C5ajowjdzBi14hG+oYTSGoOFBHEph4rXy/4jH71ioLVotf
eWlapP4MJE++88OK1jQtWACHkfSqKIRmt/hjtOayK5i0j2GVyD+h1Du9hSxAq6RU
ANalze80dhkKvL/1BXQZum7iJ9azqaBpye0aJoRAnF3TvJztVlrbGxsH5bZ55wb3
4QIDAQAB
-----END PUBLIC KEY-----
I0825 14:42:48.375973   26411 grpc_verifier.go:309]      AK Default parameter match template
I0825 14:42:48.378897   26411 grpc_verifier.go:318]      Loaded AK KeyName 000bf1c11acf9a80401a114a2d039c0e14e0bd3507b6934ce4580f5b3d8eca31e7f1
I0825 14:42:48.378988   26411 grpc_verifier.go:320]      MakeCredential Start
I0825 14:42:48.382242   26411 grpc_verifier.go:330]      credBlob 0020d1a564cd8c6135410a3ba8e072e195ea6d9c9b09bd937f63733d458d89c9900806255813a199a9a65ada0a8136fb45950e4a4d86324ead21e334f86f962d53263715
I0825 14:42:48.382341   26411 grpc_verifier.go:331]      encryptedSecret0 1465e8d02bd2845318129d4b0b60b3f15233ed339773ebf2d3d2568fbbed4ec01d64564e87aa3e10a9fa7af243c781d1e945ae59aa85e1b7eb1484ee8cdcc041276a3cd2893721ef9ae1003053c2bf4373a1c73470a5ca1a8bff48d902a1bd0c46134bccb30d7c809d244ec3c22afe61b5b44c2439f6f56ca64a26bf132dac978698d6c1b30422f03c57270e4f5cdfd681b9b3ec05904dcce0676b0e139d25d36c6772feb422651fa0688d34230fc2a041dd67113027683a4c61e76acae5186d5730d4861036c5003d403706c4f16f71c3c954f5da086f8022d5d821f736c4988dbe290203fce354468923e86f9194fed61db61d3fb02794734cff3113eea390
I0825 14:42:48.382450   26411 grpc_verifier.go:332]      <-- End makeCredential()
I0825 14:42:48.382521   26411 grpc_verifier.go:334]      EncryptedSecret: 1465e8d02bd2845318129d4b0b60b3f15233ed339773ebf2d3d2568fbbed4ec01d64564e87aa3e10a9fa7af243c781d1e945ae59aa85e1b7eb1484ee8cdcc041276a3cd2893721ef9ae1003053c2bf4373a1c73470a5ca1a8bff48d902a1bd0c46134bccb30d7c809d244ec3c22afe61b5b44c2439f6f56ca64a26bf132dac978698d6c1b30422f03c57270e4f5cdfd681b9b3ec05904dcce0676b0e139d25d36c6772feb422651fa0688d34230fc2a041dd67113027683a4c61e76acae5186d5730d4861036c5003d403706c4f16f71c3c954f5da086f8022d5d821f736c4988dbe290203fce354468923e86f9194fed61db61d3fb02794734cff3113eea390,
I0825 14:42:48.382595   26411 grpc_verifier.go:335]      CredentialBlob: 0020d1a564cd8c6135410a3ba8e072e195ea6d9c9b09bd937f63733d458d89c9900806255813a199a9a65ada0a8136fb45950e4a4d86324ead21e334f86f962d53263715,
I0825 14:42:48.382666   26411 grpc_verifier.go:337] =============== ActivateCredential ===============
I0825 14:42:48.417021   26411 grpc_verifier.go:348]      Secret: XVlBzgbaiCMRAjWwhTHctcuAxhxKQFDa
I0825 14:42:48.417055   26411 grpc_verifier.go:349]      Nonce: XVlBzgbaiCMRAjWwhTHctcuAxhxKQFDa
I0825 14:42:48.417072   26411 grpc_verifier.go:351] =============== Quote/Verify ===============
I0825 14:42:48.444585   26411 grpc_verifier.go:366]      Attestation: ff54434780180022000b50194fab17fb7959272b03529683da2de95d0066487d8531ce76c1fa042a8004002046704c536a466263586f45466652735778504c446e4a4f6243734e566c67546500000000006c4d01000000010000000001201605110016280000000001000b0301000000202ba7022b59f2158786ea3ea29a7ad12ff0c6c9d6682da6555d8926075b643b1f
I0825 14:42:48.444621   26411 grpc_verifier.go:367]      Signature: a9510dae2dd7c202f91a4b7e5013177502ab923e042367b4fdca534cd7d4c38f873507fccef3240fc916c7cdc933a581023d3f2e45ade8ff24458459199f0be244197d4eb807206a3bdfd32f576cfb63f57e83d26b03bdd286a9f74e848c906a08a377e58bc22ed70f60a5af5f4158277f148dd8d764357eb7b45357a15b2f1f32ba3d3e0eeee90bbea88f18cc8a2a139460bd19f5121e3a3158095e94d1d269cf02dba905241c4f2a5ce071c5beca2d64313374a6a47e468ccbfeb8cb42c9dd5676a2641e13049551ba9b030a2e83b8a4034d3fd02219860ce4b8e2d3d216d0e87fa2375948ce840e1cfa4710bf8d47f90595a26bbb706379fc39d9e6429f6a
I0825 14:42:48.444670   26411 grpc_verifier.go:377]      Attestation ExtraData (nonce): FpLSjFbcXoEFfRsWxPLDnJObCsNVlgTe 
I0825 14:42:48.444702   26411 grpc_verifier.go:378]      Attestation PCR#: [0] 
I0825 14:42:48.444725   26411 grpc_verifier.go:379]      Attestation Hash: 2ba7022b59f2158786ea3ea29a7ad12ff0c6c9d6682da6555d8926075b643b1f 
I0825 14:42:48.444748   26411 grpc_verifier.go:395]      Expected PCR Value:           --> 24af52a4f429b71a3184a6d64cddad17e54ea030e2aa6576bf3a5a3d8bd3328f
I0825 14:42:48.444766   26411 grpc_verifier.go:396]      sha256 of Expected PCR Value: --> 2ba7022b59f2158786ea3ea29a7ad12ff0c6c9d6682da6555d8926075b643b1f
I0825 14:42:48.444786   26411 grpc_verifier.go:398]      Decoding PublicKey for AK ========
I0825 14:42:48.444922   26411 grpc_verifier.go:415]      Attestation Signature Verified 
I0825 14:42:48.444944   26411 grpc_verifier.go:416]      <-- End verifyQuote()
I0825 14:42:48.444964   26411 grpc_verifier.go:418] =============== PushSecret ===============
I0825 14:42:48.444985   26411 grpc_verifier.go:420]      Pushing AES
I0825 14:42:48.445265   26411 grpc_verifier.go:444]      Hash of AES Key:  bZeQ9G0KuKpHVwfZuobcMf7tL/ViU1maVaJCAY+QjfU
I0825 14:42:48.474930   26411 grpc_verifier.go:506]      Verification Pushed bZeQ9G0KuKpHVwfZuobcMf7tL/ViU1maVaJCAY+QjfU=
```


### RSA

#### Attestor RSA

```log
$ go run src/grpc_attestor.go --grpcport :50051 --cacert certs/CA_crt.pem \
  --servercert certs/server_crt.pem \
  --serverkey certs/server_key.pem --pcr=0 \
  --v=10 -alsologtostderr

I0825 14:45:28.625275    1132 grpc_attestor.go:809] Starting gRPC server on port :50051
I0825 14:48:57.689027    1132 grpc_attestor.go:144] >> inbound request
I0825 14:48:57.689351    1132 grpc_attestor.go:163] HealthCheck called for Service [verifier.VerifierServer]
I0825 14:48:57.691408    1132 grpc_attestor.go:144] >> inbound request
I0825 14:48:57.691549    1132 grpc_attestor.go:177] ======= GetPlatformCert ========
I0825 14:48:57.691623    1132 grpc_attestor.go:178]      client provided uid: 369c327d-ad1f-401c-aa91-d9b0e69bft67
CERTIFICATE
I0825 14:48:57.692651    1132 grpc_attestor.go:191]      Found Platform Cert Issuer CN=tpm_ek_v1_cloud_host_root-signer-0-2018-04-06T10:58:26-07:00 K:1\, 1:Pw003HsFYO4:0:18,OU=Cloud,O=Google LLC,L=Mountain View,ST=California,C=US ========
I0825 14:48:57.692723    1132 grpc_attestor.go:192]      Returning GetPlatformCert ========
I0825 14:48:57.693792    1132 grpc_attestor.go:144] >> inbound request
I0825 14:48:57.693870    1132 grpc_attestor.go:200] ======= GetEKCert ========
I0825 14:48:57.693920    1132 grpc_attestor.go:201]      client provided uid: 369c327d-ad1f-401c-aa91-d9b0e69bft67
I0825 14:48:57.693972    1132 grpc_attestor.go:207] =============== Load EncryptionKey and Certifcate from NV ===============
I0825 14:48:57.706848    1132 grpc_attestor.go:223]      Encryption PEM 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtua2IJy72b7y54lUS6ep
20njw0bCMVLXSAjxG+FGZSd1pyjAkbGAVT1+0uRTvX6KDHJLroIVCknvyN4meZhi
22dobbrcdISXe2klXnc2pxlE78K+gGtLP4ljd1gwXJ/mCZP4G0k2uqP0l6A5LcdF
JuTqarzmEZHBi+M4xkKyucYEJAWDl71WS1Um9NEUv/Hd0NvMjUr2exRaZjQh4DwG
omZPTKcLQNuqTMlE31Wrua+FTRlbyYjWR9dfwamTbiXm6wuUAKiR0JQq4GxT3u4G
Jg/N9wyiMpoxaxb/hc7q9+TMZadt+Hkf/VqMAz4HsVEIM+TkJEe4lvoYfOIb3JUK
RwIDAQAB
-----END PUBLIC KEY-----
I0825 14:48:57.721463    1132 grpc_attestor.go:241]      Encryption Issuer x509 tpm_ek_v1_cloud_host-signer-0-2020-10-22T14:02:08-07:00 K:1, 2:HBNpA3TPAbM:0:18
I0825 14:48:57.721616    1132 grpc_attestor.go:242]      Returning GetEKCert ========
I0825 14:48:57.723507    1132 grpc_attestor.go:144] >> inbound request
I0825 14:48:57.723596    1132 grpc_attestor.go:250] ======= GetAK ========
I0825 14:48:57.723652    1132 grpc_attestor.go:251]      client provided uid: 369c327d-ad1f-401c-aa91-d9b0e69bft67
I0825 14:48:57.725326    1132 grpc_attestor.go:258]     Current PCR 0 Value %!d(string=24af52a4f429b71a3184a6d64cddad17e54ea030e2aa6576bf3a5a3d8bd3328f) 
I0825 14:48:57.725401    1132 grpc_attestor.go:263]      createPrimary
I0825 14:48:57.877237    1132 grpc_attestor.go:281]      tpmEkPub: 
&{23089139552675222780587887552299787732028585340944175742498309644508463101452659093589404677039890944554594572429795143948307682874684239173614524550479887373291894320626553725375607694178765293383169515734945455890990827306678942980888021650170549528474226066921904885138221732563417118643706260054748731352356460408385515317443375503308713349979071975711368655541252338959361261022056674667359462771495889777624159637474812642664401278952900154357047989990136692537135987531716747962452549091677455164458016113284079928348588418702477803953202522836766126159323175422207893177540913361300513665309360796450331888199 65537}
I0825 14:48:57.877607    1132 grpc_attestor.go:294]      ekPub Name: 000ba75da1afb2672451896e3cdbe718bef45ccda34b899ecff4b9a89544af122dba
I0825 14:48:57.877686    1132 grpc_attestor.go:295]      ekPubPEM: 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtua2IJy72b7y54lUS6ep
20njw0bCMVLXSAjxG+FGZSd1pyjAkbGAVT1+0uRTvX6KDHJLroIVCknvyN4meZhi
22dobbrcdISXe2klXnc2pxlE78K+gGtLP4ljd1gwXJ/mCZP4G0k2uqP0l6A5LcdF
JuTqarzmEZHBi+M4xkKyucYEJAWDl71WS1Um9NEUv/Hd0NvMjUr2exRaZjQh4DwG
omZPTKcLQNuqTMlE31Wrua+FTRlbyYjWR9dfwamTbiXm6wuUAKiR0JQq4GxT3u4G
Jg/N9wyiMpoxaxb/hc7q9+TMZadt+Hkf/VqMAz4HsVEIM+TkJEe4lvoYfOIb3JUK
RwIDAQAB
-----END PUBLIC KEY-----
I0825 14:48:57.878174    1132 grpc_attestor.go:302]      CreateKeyUsingAuth
I0825 14:48:58.006743    1132 grpc_attestor.go:328]      akPub: 0001000b00050072000000100014000b0800000000000100e4e35296302daf1334c187e781342e7b865ffec7fd5f7437744f670cd5afa8202c6cbf949dade8ea49230ee14a3cdf295e5f0828be9135705916c71a6ea02a71cd503e96897cc72622ae109496fbbfe112c0135c8301e07d8afbd6f4906531df19ac37bbe684c9594565efb725bfe3d672201a9a3eb38583ead7909859a9e009d99d517bc8f94f3cc099a9a087b1b042168f3085f5db54d971d1b88bdcff8d3422b2251156b8e6fe1aaa5f0d63d3fa1ddb17b4877ba9be560a316283bb89981c7ae448bfb700b45be765032ded9eb8ccabf70abe9df55c61af6f2c757ed044a6b1439ca437d0240022b508266b23662c2ec6810fc198bbf24af6a75b9076d4b5,
I0825 14:48:58.006894    1132 grpc_attestor.go:329]      akPriv: 0020c43cc37bdeae4d7786b8cc36b29e23a5526cc855055120ecbb7d585e14c345050010176cc2d6dff2581ca22a5c4d07f0b098fdacd43a5c8d0b9a6a1484919b5775113777138e974565e3dddbcb26545849303c5286c7bb3f40a35e0f8482ee57329c55ec380d2d02911aaa04bdc878e1e3c2a153f7d2425d25673a73f6675f05f89b9ba736850f79b8647345eaa37549ec286d4ca119428f27f2c577ca813f0c00352610a7b86a8dd98f0d0b65be41cc12e5b281492d3788a6b6d6699539f31caba2cb78142816eed6a535d80a537f577d313c630c46c3aaa5510c8c,
I0825 14:48:58.006992    1132 grpc_attestor.go:336]      CredentialData.ParentName.Digest.Value a75da1afb2672451896e3cdbe718bef45ccda34b899ecff4b9a89544af122dba
I0825 14:48:58.007083    1132 grpc_attestor.go:337]      CredentialTicket a2a651080d6562fb7b294d0eb13b80313789390be512d26d2db0891189f56e75
I0825 14:48:58.007163    1132 grpc_attestor.go:338]      CredentialHash 22bd2ad7aed1f583f13a67ecbf6c079e443be114569bdabe636c089b79ea5cd2
I0825 14:48:58.007243    1132 grpc_attestor.go:340]      ContextSave (ek)
I0825 14:48:58.016274    1132 grpc_attestor.go:351]      ContextLoad (ek)
I0825 14:48:58.023700    1132 grpc_attestor.go:362]      LoadUsingAuth
I0825 14:48:58.030737    1132 grpc_attestor.go:390]      AK keyName 0022000b039ae7a7cb780bf12cf10341f732ee10cca42c0e5f5ca7be4db1d68a13d96a40
I0825 14:48:58.034029    1132 grpc_attestor.go:412]      akPubPEM: 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5ONSljAtrxM0wYfngTQu
e4Zf/sf9X3Q3dE9nDNWvqCAsbL+Una3o6kkjDuFKPN8pXl8IKL6RNXBZFscabqAq
cc1QPpaJfMcmIq4QlJb7v+ESwBNcgwHgfYr71vSQZTHfGaw3u+aEyVlFZe+3Jb/j
1nIgGpo+s4WD6teQmFmp4AnZnVF7yPlPPMCZqaCHsbBCFo8whfXbVNlx0biL3P+N
NCKyJRFWuOb+GqpfDWPT+h3bF7SHe6m+VgoxYoO7iZgceuRIv7cAtFvnZQMt7Z64
zKv3Cr6d9Vxhr28sdX7QRKaxQ5ykN9AkACK1CCZrI2YsLsaBD8GYu/JK9qdbkHbU
tQIDAQAB
-----END PUBLIC KEY-----
I0825 14:48:58.034603    1132 grpc_attestor.go:414]      Write (akPub) ========
I0825 14:48:58.034826    1132 grpc_attestor.go:419]      Write (akPriv) ========
I0825 14:48:58.034959    1132 grpc_attestor.go:429]      Returning GetAK ========
I0825 14:48:58.062518    1132 grpc_attestor.go:144] >> inbound request
I0825 14:48:58.062669    1132 grpc_attestor.go:441] ======= ActivateCredential ========
I0825 14:48:58.062727    1132 grpc_attestor.go:442]      client provided uid: 369c327d-ad1f-401c-aa91-d9b0e69bft67
I0825 14:48:58.062776    1132 grpc_attestor.go:444]      ContextLoad (ek)
I0825 14:48:58.070191    1132 grpc_attestor.go:455]      Read (akPub)
I0825 14:48:58.070347    1132 grpc_attestor.go:460]      Read (akPriv)
I0825 14:48:58.077650    1132 grpc_attestor.go:491]      keyName 0022000b039ae7a7cb780bf12cf10341f732ee10cca42c0e5f5ca7be4db1d68a13d96a40
I0825 14:48:58.077773    1132 grpc_attestor.go:493]      ActivateCredentialUsingAuth
I0825 14:48:58.089817    1132 grpc_attestor.go:541]      <--  activateCredential()
I0825 14:48:58.097358    1132 grpc_attestor.go:144] >> inbound request
I0825 14:48:58.097486    1132 grpc_attestor.go:551] ======= Quote ========
I0825 14:48:58.097555    1132 grpc_attestor.go:552]      client provided uid: 369c327d-ad1f-401c-aa91-d9b0e69bft67
I0825 14:48:58.099219    1132 grpc_attestor.go:559]      PCR 0 Value 24af52a4f429b71a3184a6d64cddad17e54ea030e2aa6576bf3a5a3d8bd3328f 
I0825 14:48:58.099318    1132 grpc_attestor.go:564]      ContextLoad (ek) ========
I0825 14:48:58.106542    1132 grpc_attestor.go:574]      LoadUsingAuth ========
I0825 14:48:58.109887    1132 grpc_attestor.go:596]      Read (akPub) ========
I0825 14:48:58.110138    1132 grpc_attestor.go:601]      Read (akPriv) ========
I0825 14:48:58.114451    1132 grpc_attestor.go:613]      AK keyName 0022000b039ae7a7cb780bf12cf10341f732ee10cca42c0e5f5ca7be4db1d68a13d96a40
I0825 14:48:58.120685    1132 grpc_attestor.go:619]      Quote Hex ff54434780180022000bfd2e7a5cf1ec167c5a1934272c7406089a489bc338b7bff796bfeb3c2b767450002046704c536a466263586f45466652735778504c446e4a4f6243734e566c675465000000000071f112000000010000000001201605110016280000000001000b0301000000202ba7022b59f2158786ea3ea29a7ad12ff0c6c9d6682da6555d8926075b643b1f
I0825 14:48:58.120854    1132 grpc_attestor.go:620]      Quote Sig b07705028a5d5257a06a225fad1d35083723ab3195686ec4c48bebdc9dfb982cc76f26fcf5c576eb01471f4dd546b5cf2a20939b52e1e4793c860e3510f642a82eeb6184d7c5189d5a8fb6910f7995506b48f052daac0a349e5d8f88ffc73806c7260609ef92a3215dd4d79cef9ec42db17a8640ba23b230fbb8bb00ab585dbaa72e858fbbbb7aa87548fba43a6b309e9190d766af6e8149625727577f01259ce441abc9405caeb8798c4e5b33c02ba2a675cdc1b8f7db1596b11e11d7844113e738becc9edd616ea129ad1c2860333916208cf285cc16dbd6b42c3c7a8b8eb6df57718dde24b1893a9895868be5ebe52d68b034f1614c59362065bc668cfb78
I0825 14:48:58.120945    1132 grpc_attestor.go:621]      <-- End Quote
I0825 14:48:58.129641    1132 grpc_attestor.go:144] >> inbound request
I0825 14:48:58.129781    1132 grpc_attestor.go:632] ======= PushSecret ========
I0825 14:48:58.129859    1132 grpc_attestor.go:633]      client provided uid: 
I0825 14:48:58.129930    1132 grpc_attestor.go:636]      Loading EndorsementKeyRSA
I0825 14:48:58.135197    1132 grpc_attestor.go:664]      Loading ImportSigningKey
I0825 14:48:58.157931    1132 grpc_attestor.go:683]      Imported keyPublic portion: 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqwK/eG8GB9TC8adQB0ph
+R8qZPePz6bVlKE+8mk1pqVxqpOS3odGID2yCVdflMO7apOmyzs3NOrulcGqhtc6
ZF7N9utLPcpOVppTEJQP3Q2eky5I3F9x03aWmk/OpjVDVaqWNJwIPePLqnlRIIsL
DKH1IXbBQHIs/wnbDgXxw1VHkdpXUlyXdCliUvVA/YAZhIPcIBBZipNBOzJHiHTk
I97KMb1acCm9aRi0A9odZUsQLduVqhwKALw+U5+aMInT/vI4JS0KLlzZfvov3wPR
PgaZnhDCLs2gr/BDM4mJAMZ4Tp9FMdeeg8fSCVbx75cyLTPwD2RQDKNBXxI+9LIj
9QIDAQAB
-----END PUBLIC KEY-----
I0825 14:48:58.158577    1132 grpc_attestor.go:685]      Saving Key Handle as importedKey.bin
I0825 14:48:58.166327    1132 grpc_attestor.go:698]     Generating Test Signature ========
I0825 14:48:58.175233    1132 grpc_attestor.go:727]      Test Signature data:  O08hu1EBS7nZTni9aqUtRiMZaJnR6nRvMIdT2+YjRc3R3gkUIYLCpExNmlWbezKPKBr+ToT1/T+7+5YFhEpm/P89h0UQThnDzWI0G3zCDnfipMbytPGe6WY1r2q6qzVk89IlROI2Vjhp4e9ohMo7X3or2rZJFYIKZyLpG5MbdCYE38Tck8+MIzJ/+HmwBHJdw4aTIEx7RamK3UB6sqTvwWQ8JR2pC7MPLeHBVx60o2V09cDAnHxoaXnrQpOApH/t51nPiqhyxA8Jog+FbCjJxv2iXz7NTEyzAi0UZfHJd6/I5Fz/OKSF+K6DXe5Ryf6E11Iljwj51Xs0Vk2/T/kMbw
```

#### Verifier RSA

```log
$ go run src/grpc_verifier.go --importMode=RSA  --uid 369c327d-ad1f-401c-aa91-d9b0e69bft67 \
  --pcr=0  --rsaCert=certs/tpm_client.crt \
  --rsaKey=certs/tpm_client.key  --host verify.esodemoapp2.com:50051   \
  --v=10 -alsologtostderr 

I0825 14:48:57.689992   26463 grpc_verifier.go:176] RPC HealthChekStatus:SERVING
I0825 14:48:57.690801   26463 grpc_verifier.go:180] =============== GetPlatformCert ===============
I0825 14:48:57.693141   26463 grpc_verifier.go:189] =============== GetPlatformCert Returned from remote ===============
I0825 14:48:57.693439   26463 grpc_verifier.go:207]     Platform Cert Issuer tpm_ek_v1_cloud_host_root-signer-0-2018-04-06T10:58:26-07:00 K:1, 1:Pw003HsFYO4:0:18
I0825 14:48:57.722152   26463 grpc_verifier.go:220] =============== GetEKCert Returned from remote ===============
I0825 14:48:57.722495   26463 grpc_verifier.go:238]     EkCert Cert Issuer tpm_ek_v1_cloud_host-signer-0-2020-10-22T14:02:08-07:00 K:1, 2:HBNpA3TPAbM:0:18
I0825 14:48:57.722592   26463 grpc_verifier.go:239]     EkCert Public Key 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtua2IJy72b7y54lUS6ep
20njw0bCMVLXSAjxG+FGZSd1pyjAkbGAVT1+0uRTvX6KDHJLroIVCknvyN4meZhi
22dobbrcdISXe2klXnc2pxlE78K+gGtLP4ljd1gwXJ/mCZP4G0k2uqP0l6A5LcdF
JuTqarzmEZHBi+M4xkKyucYEJAWDl71WS1Um9NEUv/Hd0NvMjUr2exRaZjQh4DwG
omZPTKcLQNuqTMlE31Wrua+FTRlbyYjWR9dfwamTbiXm6wuUAKiR0JQq4GxT3u4G
Jg/N9wyiMpoxaxb/hc7q9+TMZadt+Hkf/VqMAz4HsVEIM+TkJEe4lvoYfOIb3JUK
RwIDAQAB
-----END PUBLIC KEY-----

I0825 14:48:57.723151   26463 grpc_verifier.go:242] =============== GetAKCert ===============
I0825 14:48:58.042163   26463 grpc_verifier.go:251]      akPub: 0001000b00050072000000100014000b0800000000000100e4e35296302daf1334c187e781342e7b865ffec7fd5f7437744f670cd5afa8202c6cbf949dade8ea49230ee14a3cdf295e5f0828be9135705916c71a6ea02a71cd503e96897cc72622ae109496fbbfe112c0135c8301e07d8afbd6f4906531df19ac37bbe684c9594565efb725bfe3d672201a9a3eb38583ead7909859a9e009d99d517bc8f94f3cc099a9a087b1b042168f3085f5db54d971d1b88bdcff8d3422b2251156b8e6fe1aaa5f0d63d3fa1ddb17b4877ba9be560a316283bb89981c7ae448bfb700b45be765032ded9eb8ccabf70abe9df55c61af6f2c757ed044a6b1439ca437d0240022b508266b23662c2ec6810fc198bbf24af6a75b9076d4b5,
I0825 14:48:58.042198   26463 grpc_verifier.go:252]      akName: 000b039ae7a7cb780bf12cf10341f732ee10cca42c0e5f5ca7be4db1d68a13d96a40,
I0825 14:48:58.042212   26463 grpc_verifier.go:254] =============== MakeCredential ===============
I0825 14:48:58.042265   26463 grpc_verifier.go:276]      Decoded EkPublic Key: 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtua2IJy72b7y54lUS6ep
20njw0bCMVLXSAjxG+FGZSd1pyjAkbGAVT1+0uRTvX6KDHJLroIVCknvyN4meZhi
22dobbrcdISXe2klXnc2pxlE78K+gGtLP4ljd1gwXJ/mCZP4G0k2uqP0l6A5LcdF
JuTqarzmEZHBi+M4xkKyucYEJAWDl71WS1Um9NEUv/Hd0NvMjUr2exRaZjQh4DwG
omZPTKcLQNuqTMlE31Wrua+FTRlbyYjWR9dfwamTbiXm6wuUAKiR0JQq4GxT3u4G
Jg/N9wyiMpoxaxb/hc7q9+TMZadt+Hkf/VqMAz4HsVEIM+TkJEe4lvoYfOIb3JUK
RwIDAQAB
-----END PUBLIC KEY-----
I0825 14:48:58.054294   26463 grpc_verifier.go:284]      Read (akPub) from registry
I0825 14:48:58.054546   26463 grpc_verifier.go:306]      Decoded AkPub: 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5ONSljAtrxM0wYfngTQu
e4Zf/sf9X3Q3dE9nDNWvqCAsbL+Una3o6kkjDuFKPN8pXl8IKL6RNXBZFscabqAq
cc1QPpaJfMcmIq4QlJb7v+ESwBNcgwHgfYr71vSQZTHfGaw3u+aEyVlFZe+3Jb/j
1nIgGpo+s4WD6teQmFmp4AnZnVF7yPlPPMCZqaCHsbBCFo8whfXbVNlx0biL3P+N
NCKyJRFWuOb+GqpfDWPT+h3bF7SHe6m+VgoxYoO7iZgceuRIv7cAtFvnZQMt7Z64
zKv3Cr6d9Vxhr28sdX7QRKaxQ5ykN9AkACK1CCZrI2YsLsaBD8GYu/JK9qdbkHbU
tQIDAQAB
-----END PUBLIC KEY-----
I0825 14:48:58.055071   26463 grpc_verifier.go:309]      AK Default parameter match template
I0825 14:48:58.057993   26463 grpc_verifier.go:318]      Loaded AK KeyName 000b039ae7a7cb780bf12cf10341f732ee10cca42c0e5f5ca7be4db1d68a13d96a40
I0825 14:48:58.058105   26463 grpc_verifier.go:320]      MakeCredential Start
I0825 14:48:58.061489   26463 grpc_verifier.go:330]      credBlob 00207e07ebcca83cb226c94c35d30bd8aa3eb0f7756f3212a3287ada4db2d09d310c180c6842853181bc6fd424532ca1814b5091b2bdee38df569cf29425a7a8c9b5888a
I0825 14:48:58.061585   26463 grpc_verifier.go:331]      encryptedSecret0 5484359d8da02d757f85b56e7dfe475b3355941902377c0da1de72e8fcc33ffdea1fc2c57836169f9da7bf6ea87746c54b66bd88838a30118a119d6a74f746aaaa17816b8a1be388f7f45e1d32ecb67bf5fabf31ab9c5745f65fb647a3fc48fc99c5762f0a36d7be52b2783ec172e731662239fd914c9eb18cb9b381b44964199932fc09d247f0476b17fd50d2acdad345a13ac81f5ff1d3b84666d4200dd14a5f18a81706c2da29fdf4040fba43f4824988b850fee45ccc77babb6df03e7c5ef0ac93bf5ad42d20dcad80e4503f8cffe48eb45f6e50b0db82257464dce4e3e305ee06d2b2df344d8f76c75d833392fe3bc548a3bf325fcce504a1cabc8e7052
I0825 14:48:58.061665   26463 grpc_verifier.go:332]      <-- End makeCredential()
I0825 14:48:58.061739   26463 grpc_verifier.go:334]      EncryptedSecret: 5484359d8da02d757f85b56e7dfe475b3355941902377c0da1de72e8fcc33ffdea1fc2c57836169f9da7bf6ea87746c54b66bd88838a30118a119d6a74f746aaaa17816b8a1be388f7f45e1d32ecb67bf5fabf31ab9c5745f65fb647a3fc48fc99c5762f0a36d7be52b2783ec172e731662239fd914c9eb18cb9b381b44964199932fc09d247f0476b17fd50d2acdad345a13ac81f5ff1d3b84666d4200dd14a5f18a81706c2da29fdf4040fba43f4824988b850fee45ccc77babb6df03e7c5ef0ac93bf5ad42d20dcad80e4503f8cffe48eb45f6e50b0db82257464dce4e3e305ee06d2b2df344d8f76c75d833392fe3bc548a3bf325fcce504a1cabc8e7052,
I0825 14:48:58.061815   26463 grpc_verifier.go:335]      CredentialBlob: 00207e07ebcca83cb226c94c35d30bd8aa3eb0f7756f3212a3287ada4db2d09d310c180c6842853181bc6fd424532ca1814b5091b2bdee38df569cf29425a7a8c9b5888a,
I0825 14:48:58.061886   26463 grpc_verifier.go:337] =============== ActivateCredential ===============
I0825 14:48:58.096981   26463 grpc_verifier.go:348]      Secret: XVlBzgbaiCMRAjWwhTHctcuAxhxKQFDa
I0825 14:48:58.097015   26463 grpc_verifier.go:349]      Nonce: XVlBzgbaiCMRAjWwhTHctcuAxhxKQFDa
I0825 14:48:58.097032   26463 grpc_verifier.go:351] =============== Quote/Verify ===============
I0825 14:48:58.125446   26463 grpc_verifier.go:366]      Attestation: ff54434780180022000bfd2e7a5cf1ec167c5a1934272c7406089a489bc338b7bff796bfeb3c2b767450002046704c536a466263586f45466652735778504c446e4a4f6243734e566c675465000000000071f112000000010000000001201605110016280000000001000b0301000000202ba7022b59f2158786ea3ea29a7ad12ff0c6c9d6682da6555d8926075b643b1f
I0825 14:48:58.125483   26463 grpc_verifier.go:367]      Signature: b07705028a5d5257a06a225fad1d35083723ab3195686ec4c48bebdc9dfb982cc76f26fcf5c576eb01471f4dd546b5cf2a20939b52e1e4793c860e3510f642a82eeb6184d7c5189d5a8fb6910f7995506b48f052daac0a349e5d8f88ffc73806c7260609ef92a3215dd4d79cef9ec42db17a8640ba23b230fbb8bb00ab585dbaa72e858fbbbb7aa87548fba43a6b309e9190d766af6e8149625727577f01259ce441abc9405caeb8798c4e5b33c02ba2a675cdc1b8f7db1596b11e11d7844113e738becc9edd616ea129ad1c2860333916208cf285cc16dbd6b42c3c7a8b8eb6df57718dde24b1893a9895868be5ebe52d68b034f1614c59362065bc668cfb78
I0825 14:48:58.125523   26463 grpc_verifier.go:377]      Attestation ExtraData (nonce): FpLSjFbcXoEFfRsWxPLDnJObCsNVlgTe 
I0825 14:48:58.125553   26463 grpc_verifier.go:378]      Attestation PCR#: [0] 
I0825 14:48:58.125584   26463 grpc_verifier.go:379]      Attestation Hash: 2ba7022b59f2158786ea3ea29a7ad12ff0c6c9d6682da6555d8926075b643b1f 
I0825 14:48:58.125607   26463 grpc_verifier.go:395]      Expected PCR Value:           --> 24af52a4f429b71a3184a6d64cddad17e54ea030e2aa6576bf3a5a3d8bd3328f
I0825 14:48:58.125625   26463 grpc_verifier.go:396]      sha256 of Expected PCR Value: --> 2ba7022b59f2158786ea3ea29a7ad12ff0c6c9d6682da6555d8926075b643b1f
I0825 14:48:58.125646   26463 grpc_verifier.go:398]      Decoding PublicKey for AK ========
I0825 14:48:58.125771   26463 grpc_verifier.go:415]      Attestation Signature Verified 
I0825 14:48:58.125794   26463 grpc_verifier.go:416]      <-- End verifyQuote()
I0825 14:48:58.125817   26463 grpc_verifier.go:418] =============== PushSecret ===============
I0825 14:48:58.125837   26463 grpc_verifier.go:420]      Pushing RSA
I0825 14:48:58.126031   26463 grpc_verifier.go:464]      Loaded x509 CN=Enterprise Subordinate CA,OU=Enterprise,O=Google,C=US
I0825 14:48:58.128746   26463 grpc_verifier.go:484]      Test signature data:  O08hu1EBS7nZTni9aqUtRiMZaJnR6nRvMIdT2+YjRc3R3gkUIYLCpExNmlWbezKPKBr+ToT1/T+7+5YFhEpm/P89h0UQThnDzWI0G3zCDnfipMbytPGe6WY1r2q6qzVk89IlROI2Vjhp4e9ohMo7X3or2rZJFYIKZyLpG5MbdCYE38Tck8+MIzJ/+HmwBHJdw4aTIEx7RamK3UB6sqTvwWQ8JR2pC7MPLeHBVx60o2V09cDAnHxoaXnrQpOApH/t51nPiqhyxA8Jog+FbCjJxv2iXz7NTEyzAi0UZfHJd6/I5Fz/OKSF+K6DXe5Ryf6E11Iljwj51Xs0Vk2/T/kMbw==
I0825 14:48:58.128775   26463 grpc_verifier.go:485]      <-- End generateCertificate()
I0825 14:48:58.186508   26463 grpc_verifier.go:506]      Verification Pushed O08hu1EBS7nZTni9aqUtRiMZaJnR6nRvMIdT2+YjRc3R3gkUIYLCpExNmlWbezKPKBr+ToT1/T+7+5YFhEpm/P89h0UQThnDzWI0G3zCDnfipMbytPGe6WY1r2q6qzVk89IlROI2Vjhp4e9ohMo7X3or2rZJFYIKZyLpG5MbdCYE38Tck8+MIzJ/+HmwBHJdw4aTIEx7RamK3UB6sqTvwWQ8JR2pC7MPLeHBVx60o2V09cDAnHxoaXnrQpOApH/t51nPiqhyxA8Jog+FbCjJxv2iXz7NTEyzAi0UZfHJd6/I5Fz/OKSF+K6DXe5Ryf6E11Iljwj51Xs0Vk2/T/kMbw==
```



### Applications

This is just an academic exercise (so do not use the code as is).   However, some applications of this


- [TPM based Google Service Account Credentials](https://github.com/salrashid123/oauth2#usage-tpmtokensource)
- [TPM based mTLS](https://github.com/salrashid123/signer#usage-tls)
- [Trusted Platform Module (TPM) recipes with tpm2_tools and go-tpm](https://github.com/salrashid123/tpm2)


