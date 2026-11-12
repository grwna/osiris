# Test keys

Throw-away key pairs created **only for testing** (`osiris keygen`). They protect
nothing and must never be used for real services.

| Prefix | Profile | keyid |
|---|---|---|
| `test-rsa` | rsa-pss-sha256 | `f9abd441a6d76111b72ff4989d40de0b934d459010c3055fc8cf18a300851623` |
| `test-ecdsa` | ecdsa-p256-sha256 | `990c9a65aac1f5728d5333642ec6b27c211aa2f22a5a27654ed9532ff8d4408b` |
| `test-ed25519` | ed25519 | `cfdb5d3afdbc7f0a89126769789bf8ce161bc85a25b87efa5a47ecb04d16b05f` |

Regenerate: `osiris keygen --algorithm <profile> --out tests/keys/<prefix> --force`
(then update the keyids above).
