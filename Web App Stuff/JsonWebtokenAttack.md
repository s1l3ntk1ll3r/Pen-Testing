# JWT

## Base64 vs Base64URL encoding

## Base64 of JWT begins with eyJ0eXAi or eyJhbGci

## Base64 is not encryption, it makes it "URL SAFE", transport mechanism doesn't mess up characters.

## JWT = Header + payload + Signature

- Header = check rfc
- Payload are sometimes with a lot of stuff passwords, roles etc!
- Signature

## Common use : Federated Authentication and Authorization

- Often used in HTTP "Authorization" Header:Bearer

- JSON object may have new lines and if you put that raw in the requests then HTTP might get confused!

## Most JWTs are JSON Web Signatures
- Encoded not encrypted. ALWAYS! JWT's

## Digital Signature allows for tampering to be detected.
## Signing algorithm is part of the header and is controllable by the attacker.
## Set algorithm to NONE and bypass checks!!!!

## Every JWT has an exp timestamp.

# Using the algorithm "none" is optional lol.


Attack paths
1. Disclosure - Decode the payload
2. Potential for forgery (if the "none" algorithm is supported)
3. Cracking (guessing the secret!)

2. Basically send to repeater and use JSON Web token attacker plugin in Burp but also go ahead modify the token by removing the signature at the end and add alg="none" in base64 at the start.
