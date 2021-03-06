
?%
verifier/verifier.protoverifier"*
GetPlatformCertRequest
uid (	Ruid"O
GetPlatformCertResponse
uid (	Ruid"
platformCert (RplatformCert"$
GetEKCertRequest
uid (	Ruid"=
GetEKCertResponse
uid (	Ruid
ekCert (RekCert" 
GetAKRequest
uid (	Ruid"e
GetAKResponse
uid (	Ruid
ekPub (RekPub
akName (RakName
akPub (RakPub"s
ActivateCredentialRequest
uid (	Ruid
credBlob (RcredBlob(
encryptedSecret (RencryptedSecret"F
ActivateCredentialResponse
uid (	Ruid
secret (Rsecret"J
QuoteRequest
uid (	Ruid
pcr (Rpcr
secret (	Rsecret"}
QuoteResponse
uid (	Ruid 
attestation (Rattestation
	signature (R	signature
eventlog (Reventlog"|
PushSecretRequest
uid (	Ruid5
secret_type (2.verifier.SecretTypeR
secretType

importBlob (R
importBlob"J
PushSecretResponse
uid (	Ruid"
verification (Rverification"7
PullRSAKeyRequest
uid (	Ruid
pcr (Rpcr"?
PullRSAKeyResponse
uid (	Ruid$
tpm_public_key (RtpmPublicKey%
test_signature (RtestSignature3
attestation_signature (RattestationSignature 
attestation (Rattestation*'

SecretType
RAW 
RSA
AES2?
VerifierX
GetPlatformCert .verifier.GetPlatformCertRequest!.verifier.GetPlatformCertResponse" F
	GetEKCert.verifier.GetEKCertRequest.verifier.GetEKCertResponse" :
GetAK.verifier.GetAKRequest.verifier.GetAKResponse" a
ActivateCredential#.verifier.ActivateCredentialRequest$.verifier.ActivateCredentialResponse" :
Quote.verifier.QuoteRequest.verifier.QuoteResponse" I

PushSecret.verifier.PushSecretRequest.verifier.PushSecretResponse" I

PullRSAKey.verifier.PullRSAKeyRequest.verifier.PullRSAKeyResponse" B?Z=github.com/salrashid123/rungo_tpm_remote_attestation/verifierJ?
  a

  

 

 T
	
 T


  


 

  T

  

  -

  8O

 B

 

 !

 ,=

 	6

 	

 	

 	$1

 
]

 


 
3

 
>X

 6

 

 

 $1

 E

 

 #

 .@

 E

 

 #

 .@


  


 

  


  

  	

 


 

 	

 


 

 	


  


 

  

  

  	

  


 




 

 

 	

 










 !




  

  

  	

  


# &


#

 $

 $

 $	

 $

%

%

%

%


( *


(

 )

 )

 )	

 )


, 1


,

 -

 -

 -	

 -

.

.

.

.

/

/

/

/

0

0

0

0


3 7


3!

 4

 4

 4	

 4

5

5

5

5

6

6

6

6


9 <


9"

 :

 :

 :	

 :

;

;

;

;


> B


>

 ?

 ?

 ?	

 ?

@

@

@

@

A

A

A	

A


	D I


	D

	 E

	 E

	 E	

	 E

	F

	F

	F

	F

	G

	G

	G

	G

	H

	H

	H

	H



K O



K


 L


 L


 L	


 L


M


M


M


M


N


N


N


N


Q T


Q

 R

 R

 R	

 R

S

S

S

S


V Y


V

 W

 W

 W	

 W

X

X

X

X


[ a


[

 \

 \

 \	

 \

]

]

]

]

^

^

^

^

_"

_

_

_ !

`

`

`

`bproto3