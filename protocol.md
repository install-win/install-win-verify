# install.win Signature Protocol

This document describes the signature scheme embedded in every install.win
publish body (the script you fetch from `https://install.win/@<handle>`).
It covers only what is observable from the published artifacts and the
public RFC 8017 specification. Implementation internals, key management,
and pipeline structure are out of scope and intentionally not documented
here.

## 1. The Digest Contract

Every publish body is signed over an exact canonical byte string:

```
digest = SHA-256( body || 0x00 || handle )
```

- `body`  — the script bytes as served, with the signature block stripped
  and CRLF line endings normalized to LF.
- `0x00`  — a single NUL separator byte between the body and the handle.
- `handle` — the ASCII handle name (the text after `@` in the URL).

The signed input is the canonical byte string itself, not a pre-hashed
digest. This matters: under RSA-PSS (RFC 8017), the verifier recovers
`mHash = SHA-256(body || 0x00 || handle)` during EMSA-PSS-VERIFY and
compares it against the `sha256` field carried in the block. Signing the
canonical bytes — so that the hash applied by the signer is exactly the
recorded digest — is what makes that equality hold.

## 2. The Signature Block

Each signed script ends with a signature block appended to the body —
a header line, seven fields, and a footer line (9 lines total):

```
# --- install.win SIGNATURE ---
# key-id: <32 lowercase hex chars>
# alg: RSA-PSS/SHA-256/salt=32
# salt: 32
# handle: <handle>
# sha256: <64 lowercase hex chars>
# signed-at: <ISO 8601 UTC timestamp>
# signature: <base64 RSA-PSS signature>
# --- END SIGNATURE ---
```

| Line | Field | Meaning |
|---|---|---|
| header | `# --- install.win SIGNATURE ---` | Marks the start of the block. Everything before this line is the signed body. |
| 1 | `key-id` | First 32 hex chars of `SHA-256(SPKI DER)` of the signing public key. Lets a verifier pin or reject an unexpected key. |
| 2 | `alg` | Algorithm identifier. Only `RSA-PSS/SHA-256/salt=32` is accepted. |
| 3 | `salt` | The PSS salt length declared by the signer, as a decimal integer. Published bodies use `32`. The verifier treats this as an explicit, mandatory value and cross-checks the recovered salt length against it (see SALT_MISMATCH below). |
| 4 | `handle` | The handle this body serves under; it is bound into the digest via the `0x00` separator, so the same script under a different handle produces a different signature. |
| 5 | `sha256` | Hex digest as defined in section 1, recomputed by the verifier from the actual bytes received. |
| 6 | `signed-at` | Signing timestamp (informational; not part of the digest). |
| 7 | `signature` | Base64-encoded RSA-PSS signature over the canonical byte string. |
| footer | `# --- END SIGNATURE ---` | Marks the end of the block. |

A block with a missing or empty required field, a duplicate field, an
unexpected line, an unknown `alg`, an out-of-range or non-numeric `salt`,
or a malformed hex/base64 value is rejected as `MALFORMED_BLOCK` before
any cryptographic work happens.

## 3. Verification Algorithm (Overview)

The verifier implements EMSA-PSS-VERIFY as specified in RFC 8017,
section 9.1.2, using only platform-neutral primitives (SHA-256 and a big
integer modular exponentiation):

1. Normalize line endings (CRLF to LF) and locate the signature header.
   Everything before it is the body; its absence is `NO_SIGNATURE_BLOCK`.
2. Parse and validate the block fields (section 2).
3. Load the public key JSON (section 5), decode `n` (modulus) and `e`
   (exponent) from base64, and check `key-id` matches
   (`KEY_ID_MISMATCH` on disagreement).
4. Recompute `mHash = SHA-256(body || 0x00 || handle)` and compare it to
   the block's `sha256` field (`BODY_DIGEST_MISMATCH` on disagreement).
5. Perform the RSA public-key operation: `em = s^e mod n`, then
   I2OSP `em` to `k` bytes (`k` = modulus length).
6. EMSA-PSS-VERIFY on `em` with `hLen = 32` (SHA-256):
   - the rightmost byte of `em` must be `0xbc`;
   - split `em` into `maskedDB || H`, clear the leftmost
     `8k - emBits` bits of `maskedDB` (`emBits = modBits - 1`);
   - `dbMask = MGF1(H, dbLen)` (RFC 8017 B.2.1 with SHA-256),
     `DB = maskedDB XOR dbMask`;
   - `DB` must be `PS || 0x01 || salt` where `PS` is all zero bytes;
   - the recovered salt length is `dbLen - separatorIndex - 1` and must
     equal the block's declared `salt` value exactly — a mismatch is
     `SALT_MISMATCH`, which is what makes the salt length a binding
     property of the signature rather than an assumption;
   - `H' = SHA-256(0x00 * 8 || mHash || salt)` must equal `H`
     (`SIGNATURE_INVALID` otherwise).

## 4. Failure Codes

The verifier prints exactly one line, `PASS <handle>` or
`FAIL <CODE> <detail>`, and exits 0 or nonzero respectively.

| Code | Meaning |
|---|---|
| `FILE_NOT_FOUND` | The publish-body file argument does not exist on disk. |
| `KEY_FILE_NOT_FOUND` | The public-key JSON argument does not exist on disk. |
| `NO_SIGNATURE_BLOCK` | No `# --- install.win SIGNATURE ---` header in the body. |
| `MALFORMED_BLOCK` | The block is structurally invalid: missing/empty/duplicate field, unexpected line, unknown `alg`, invalid `salt` or hex/base64 field, bad key/key JSON shape (`PLATFORM_UNSUPPORTED` covers undecodable key material). |
| `KEY_ID_MISMATCH` | The block's `key-id` does not match the key-id of the supplied public key. |
| `BODY_DIGEST_MISMATCH` | `SHA-256(body || 0x00 || handle)` over the received bytes does not equal the block's `sha256` field — the body was altered after signing. |
| `SIGNATURE_INVALID` | The RSA-PSS verification failed: trailer byte, padding structure, or `H'` comparison. The signature does not match the body under the supplied key with the declared salt length. |
| `SALT_MISMATCH` | The salt length recovered from the padding structure differs from the block's declared `salt` value. Catches signatures produced with a different (implicit-default) salt length. |
| `PLATFORM_UNSUPPORTED` | A runtime prerequisite is unavailable on the current platform (SHA-256, BigInteger arithmetic, or undecodable key material). Verification is aborted rather than skipped. |

All failures are terminal: the verifier exits nonzero on any of them and
never falls through to PASS.

## 5. Public Key

The install.win root public key is published at:

```
https://install.win/keys/root-public.json
```

The JSON carries `keyId`, `spkiSha256`, `modulus`, and `exponent`:

- `modulus` / `exponent` — base64-encoded big-endian `n` and `e` of the
  RSA key (sufficient to rebuild the public key on any platform).
- `keyId` — first 32 hex chars of `SHA-256(SPKI DER)`. Compare it with
  the block's `key-id` field before trusting a verification result.
- The same key is additionally served as SPKI PEM for tooling that
  prefers PEM over raw modulus/exponent.

Download the JSON once, keep it locally, and pass its path to the
verifier via `-KeyJson`. A mirror of the key pinned by `keyId` is the
correct defense against a compromised distribution channel.
