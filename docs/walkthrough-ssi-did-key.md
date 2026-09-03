# Walkthrough: a self-signed `did:key` LWS identity

The [`did:key` suite](https://w3c.github.io/lws-protocol/lws10-authn-ssi-did-key/) is the most
self-contained of the four: the subject is a `did:key` identifier that **embeds the public key**, so a
verifier decodes the key straight from the identifier — there is nothing to host and nothing to
dereference. Keycloak's only role is to verify.

## The cast

| Party | Role |
|-------|------|
| **The agent** | Holds a private key and a `did:key` identifier derived from its public key; signs its own JWTs. |
| **Keycloak + `lws-authn`** | A verifier. It hosts nothing and needs no realm/user setup for this suite. |
| **An LWS server** | The verifier — decodes the key from the credential's `sub` `did:key` and validates the signature. |

**The idea:** a `did:key` is `did:key:z<multibase-base58btc(<multicodec><public-key>)>`. The key type
and the key bytes are inside the identifier, so trust needs no third party — `sub == iss ==
client_id ==` the `did:key`, and the verifier reconstructs the public key from it.

---

## Prerequisites

- Keycloak **26.7.0** with the `lws-authn` provider deployed — see the [README](../README.md).
- `curl`, `jq`, and `node` (Node is used to mint the key/JWT; base58btc is impractical in pure shell).

---

## Fast path — one script

```bash
bash scripts/ssi-did-key-demo.sh            # P-256 (zDn…, ES256)
KEYTYPE=ed25519 bash scripts/ssi-did-key-demo.sh   # Ed25519 (z6Mk…, EdDSA)
```

It mints a keypair, derives the `did:key`, self-signs a JWT, and posts it to
`/realms/master/lws-ssi-did-key/verify`, ending in `valid: true`. No realm, user, or hosting is
involved — the key travels inside the identifier.

---

## How a `did:key` is built (manual reference)

Supported key types: **Ed25519** (`did:key:z6Mk…`, alg `EdDSA`) and **P-256** (`did:key:zDn…`, alg
`ES256`). To construct one:

1. Take the raw public key — Ed25519: the 32-byte key; P-256: the 33-byte SEC1 **compressed** point
   (`0x02`/`0x03` ‖ X).
2. Prepend the multicodec varint prefix — Ed25519: `0xed 0x01`; P-256: `0x80 0x24` (i.e. `0x1200`).
3. base58btc-encode the result and prepend the multibase prefix `z`.
4. `did:key:` + that string.

The agent self-signs a JWT with all of `sub`, `iss`, `client_id` set to this `did:key`:

```
header  = {"alg":"ES256","typ":"JWT"}            # or {"alg":"EdDSA",...} for Ed25519
payload = {"sub":"<did:key>","iss":"<did:key>","client_id":"<did:key>",
           "aud":["https://as.example"],"iat":<now>,"exp":<now+300>}
```

## Verify

```bash
curl -s -X POST "$KC/realms/$REALM/lws-ssi-did-key/verify" \
  -H "Authorization: Bearer $CALLER_ACCESS_TOKEN" \
  --data-urlencode "credential=$JWT" | jq
```

> `Authorization` identifies **you**, the caller: the `…/verify` endpoints are authenticated by
> default. The credential being checked always travels in the request body. See
> [Securing the verify endpoints](../README.md#securing-the-verify-endpoints).


```json
{
  "valid": true,
  "subject": "did:key:zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv",
  "keyType": "P-256",
  "checks": {
    "signingAlgorithmNotNone": true,
    "selfIssued": true,
    "subjectIsDidKey": true,
    "keyDecodedFromDid": true,
    "algorithmMatchesKey": true,
    "signatureValid": true,
    "notExpired": true,
    "audiencePresent": true
  }
}
```

The verifier decodes the key from `sub`, confirms the JWT `alg` matches the key type, validates the
signature, and checks expiry and audience.

## Present it to an LWS server

```bash
curl https://pod.example/ -H "Authorization: Bearer $JWT"
```

Because the key is carried in the identifier, **any** LWS server can verify the credential with no
prior relationship and no lookups.

---

## Notes

- **Supported key types:** Ed25519 (`z6Mk…`, EdDSA), P-256 (`zDn…`, ES256), P-384 (ES384) and P-521
  (ES512). secp256k1 and RSA are rejected with a clear error — the JDK cannot do secp256k1 without
  BouncyCastle, and this codec stays pure JDK so it works under default and FIPS Keycloak.
- **The encoding must be canonical.** A decoded key is re-encoded and must reproduce the identifier
  byte for byte, so one key can never have two `did:key` spellings.
- **No hosting, no rotation endpoint.** A new key means a new `did:key` (a new identifier). There is
  nothing to publish or update.
- **Audience / token type.** The credential carries token type `urn:ietf:params:oauth:token-type:jwt`
  when exchanged, and the result reports it. The verifier requires `aud` and `iat`; pass
  `audience=<authorization server>` to require that `aud` actually names the server doing the checking,
  which is what the suite means by "the `aud` claim MUST include the target authorization server".
