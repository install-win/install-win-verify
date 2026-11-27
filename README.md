# install-win-verify

Public verification assets for install.win publish bodies. This repository
holds the verifier scripts, the signature protocol, sample publish bodies,
and hash anchors for the verifier files themselves. It is also the source
of truth for the `@origin-verify` hook: the hook's verification logic and
protocol come from this repository, and everything here is public and
auditable.

## What is in here

- `verify/verify-signature.ps1` — the standalone signature verifier.
- `verify/verify-negatives.ps1` — negative-case runner (tamper scenarios).
- `verify/verify-pipeline.sh` — bulk pipeline verification over a deploy URL.
- `protocol.md` — the signature scheme: digest contract, block format,
  verification algorithm, failure codes, public key.
- `samples/` — sample publish bodies (one good producer script, one
  deliberately tampered bad sample).
- `verify/ANCHORS.md` — sha256 anchors of the verifier files.

## Verify a publish body

Requires PowerShell 7+ (`pwsh`) on Windows.

**Step 1 — fetch the body**

```powershell
Invoke-WebRequest -Uri "https://install.win/@<handle>" -OutFile "body.ps1"
```

**Step 2 — fetch the public key**

```powershell
Invoke-WebRequest -Uri "https://install.win/keys/root-public.json" -OutFile "root-public.json"
```

**Step 3 — verify**

```powershell
pwsh -NoProfile -File verify/verify-signature.ps1 -File body.ps1 -KeyJson root-public.json
```

`PASS <handle>` means the body's bytes match the recorded digest and the
RSA-PSS signature (with the declared explicit salt length) verifies under
the supplied key. Any `FAIL <CODE> <detail>` line means the body must not
be trusted; see the failure-code table in `protocol.md` (section 4) for
the meaning of each code.

## Run the negative suite

`verify-negatives.ps1` takes a signed body as the probe and an unsigned
script as the producer, then runs five tamper scenarios and asserts the
exact failure code of each:

```powershell
pwsh -NoProfile -File verify/verify-negatives.ps1 `
    -ProbeFile <signed-body.ps1> `
    -ProducerFile samples/producers/sample.ps1 `
    -KeyJson root-public.json
```

Expected result: `verify-negatives: all scenarios PASS`, meaning all five
tamper scenarios were rejected with the precise expected failure codes
(N1 `BODY_DIGEST_MISMATCH`, N2 signature tamper, N3 `NO_SIGNATURE_BLOCK`,
N4 `MALFORMED_BLOCK`, N5 `MALFORMED_BLOCK`).

## Reproduce a signed sample locally

The samples are not shipped signed — signing keys are generated fresh and
discarded (in CI, every run; locally, on your machine). To produce a
signed sample and see the full PASS path:

```bash
# 1. throwaway test key (never use a real key for this)
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out test-private.pem

# 2. sign samples/producers/sample.ps1 and emit the public key JSON
node -e '
const fs = require("fs"), crypto = require("crypto");
const priv = crypto.createPrivateKey(fs.readFileSync("test-private.pem", "utf8"));
const pub = crypto.createPublicKey(priv);
const spki = pub.export({ type: "spki", format: "der" });
const spkiSha256 = crypto.createHash("sha256").update(spki).digest("hex");
const keyId = spkiSha256.slice(0, 32);
const jwk = pub.export({ format: "jwk" });
fs.writeFileSync("test-pub.json", JSON.stringify({
  keyId, spkiSha256,
  modulus: Buffer.from(jwk.n, "base64url").toString("base64"),
  exponent: Buffer.from(jwk.e, "base64url").toString("base64"),
}, null, 2));
const body = fs.readFileSync("samples/producers/sample.ps1");
const handle = "sample";
const input = Buffer.concat([body, Buffer.from([0x00]), Buffer.from(handle, "ascii")]);
const digest = crypto.createHash("sha256").update(input).digest();
const sig = crypto.sign("sha256", input, {
  key: priv,
  padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
  saltLength: 32,
});
const block = [
  "# --- install.win SIGNATURE ---",
  `# key-id: ${keyId}`,
  "# alg: RSA-PSS/SHA-256/salt=32",
  "# salt: 32",
  `# handle: ${handle}`,
  `# sha256: ${digest.toString("hex")}`,
  `# signed-at: ${new Date().toISOString()}`,
  `# signature: ${sig.toString("base64")}`,
  "# --- END SIGNATURE ---",
].join("\n") + "\n";
fs.writeFileSync("signed-sample.ps1", Buffer.concat([body, Buffer.from(block, "utf8")]));
console.log("signed-sample.ps1 + test-pub.json written");
'

# 3. verify the signed sample
pwsh -NoProfile -File verify/verify-signature.ps1 -File signed-sample.ps1 -KeyJson test-pub.json
# -> PASS sample
```

This is the same logic the CI in this repository runs on every push
(`.github/workflows/self-verify.yml`).

## The tampered sample

`samples/tampered/sample-tampered.ps1` is a **bad sample**: its body was
never signed, and the embedded signature block contains placeholder
values with one extra body line that breaks the digest on purpose. Use it
only to rehearse the failure path:

```powershell
pwsh -NoProfile -File verify/verify-signature.ps1 -File samples/tampered/sample-tampered.ps1 -KeyJson root-public.json
# -> FAIL BODY_DIGEST_MISMATCH ...
```

## Public key

Published at `https://install.win/keys/root-public.json`. Pin the
`keyId` value (the first 32 hex chars of the key's SPKI SHA-256) after
your first independent download; a later `key-id` change in a publish
body is a signal to stop and investigate, not to auto-accept.

## Mirroring & anchors

The verifier files under `verify/` are byte-level mirrors of the
production verifier scripts. `verify/ANCHORS.md` records the sha256 of
each mirrored file. This repository's CI recomputes those hashes on every
run and compares them against ANCHORS.md, so any accidental change to a
mirrored verifier fails the build. You can do the same check yourself:

```bash
sha256sum verify/verify-signature.ps1 verify/verify-negatives.ps1 verify/verify-pipeline.sh
# compare against verify/ANCHORS.md
```

When the production publish surface later embeds these anchors, a third
party will be able to reconcile three sources: local files, ANCHORS.md,
and the production-published anchor record.

## Boundary

This repository contains verification assets only. The production
implementation (signing service, pipeline internals, key management) is
private and is not described here. The complete observable protocol is
specified in `protocol.md`.
