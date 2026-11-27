# Verifier File Anchors

SHA-256 anchors for the mirrored verifier files in this directory. These
files are byte-level mirrors of the production verifier scripts; any
change to a file below must update its anchor here in the same change.

This repository's CI (`.github/workflows/self-verify.yml`) recomputes
these hashes on every run and fails if they disagree with this table.

| File | sha256 | Production source commit | Recorded |
|---|---|---|---|
| `verify-signature.ps1` | `1ba5ef2afb8e2251719c03d664c5888ff26836118b8b2ca76cd543377d49c42d` | `b1d2660` (2026-11-27) | 2026-11-27 |
| `verify-negatives.ps1` | `5bc15562ded982aec5f035f85f8a22cf996888d061139587f8c8d69b86c6ec86` | `b1d2660` (2026-11-27) | 2026-11-27 |
| `verify-pipeline.sh` | `77d12e93504ae5af0b5cb4c1c4349d537a15f4136e3bf4d38a5bbc54b8c9f785` | `b1d2660` (2026-11-27) | 2026-11-27 |

## How to check independently

```bash
sha256sum verify/verify-signature.ps1 verify/verify-negatives.ps1 verify/verify-pipeline.sh
```

Compare the output against the table above. In the future, the
production publish surface will also record these hashes at release
time, enabling three-way reconciliation: your local files, this table,
and the production-published anchors.
