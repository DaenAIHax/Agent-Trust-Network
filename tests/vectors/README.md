# Cullis public crypto test vectors

Public, versioned test vectors for the crypto primitives used by Cullis.
They exist so that **every** SDK implementation (Python, TypeScript, the
planned Go SDK, and any future language binding) can prove bit-exact
compatibility with the Python reference before touching a real broker.

Without these vectors, every new SDK risks silent canonicalization or
signature bugs that only surface in production — the worst possible time.

## WARNING — test keys only

Every private and public key in these JSON files is marked
`DO NOT USE IN PRODUCTION`. They are committed to a public repository,
intentionally small (RSA-2048 instead of RSA-4096 for fast tests), and
generated with zero entropy guarantees. Do not import them into any
runtime that handles real traffic.

Marker used in comments and JSON `warning` fields:
`CULLIS-TEST-VECTOR-DO-NOT-USE-IN-PROD`.

## Files

| File                        | Primitive                                  | Kind          |
|-----------------------------|--------------------------------------------|---------------|
| `canonical_json.json`       | Canonical JSON (sorted keys, compact)      | Deterministic |
| `jwk_thumbprint.json`       | RFC 7638 JWK thumbprint                    | Deterministic |
| `aad_canonicalization.json` | AES-GCM AAD format (session\|sender\|seq)  | Deterministic |
| `signed_canonical.json`     | Bytes signed by message_signer / E2E       | Deterministic |
| `aes_gcm_e2e.json`          | AES-256-GCM encrypt (fixed key + nonce)    | Deterministic |
| `dpop_proof.json`           | DPoP JWT (RFC 9449) header + claims        | Structural    |
| `rsa_oaep_wrap.json`        | RSA-OAEP-SHA256 wrap                       | Verify only   |
| `rsa_pss_signature.json`    | RSA-PSS-SHA256 signature (salt MAX_LENGTH) | Verify only   |

### Deterministic vs verify-only

- **Deterministic** vectors ship an expected output. Runners must produce
  byte-for-byte equivalent output given the same inputs. Any drift means
  an SDK bug or an intentional, coordinated format change (bump `version`).
- **Structural** vectors (DPoP) pin the header + claims but not the JWT
  signature segment, because ECDSA signatures are randomized. Runners
  verify the signature is valid under the embedded JWK and that the
  claims match.
- **Verify-only** vectors (RSA-OAEP, RSA-PSS) cannot be regenerated
  bit-exact because RFCs mandate a random component (OAEP MGF salt, PSS
  salt). They ship a ciphertext/signature together with the private or
  public key required to verify it. Runners verify by
  decrypt / signature_verify.

## File format

Each file is a JSON document with this shape:

```json
{
  "$schema": "cullis-test-vectors-v1",
  "primitive": "canonical_json",
  "warning": "DO NOT USE THESE KEYS IN PRODUCTION — test vectors only",
  "header": "Short description of the primitive.",
  "vectors": [
    {
      "name": "empty_object",
      "version": 1,
      "input": { "...": "..." },
      "expected_...": "...",
      "notes": "Free-text comment."
    }
  ]
}
```

Required fields on every vector entry:

- `name` — unique within the file
- `version` — integer, starts at 1. Bump when the format changes; do not
  mutate existing entries without version bump, because older SDKs may
  still pin to the previous version
- `input` (or a combination of explicit input fields such as
  `private_key_pem`, `ciphertext_b64`, etc.)
- One or more `expected_*` fields

Byte data is encoded as **base64url without padding** (RFC 7515 §2) in
fields named `*_b64`, mirroring the Cullis on-the-wire convention.

## Versioning

- Each vector is immutable once committed at a given `version`.
- A new format → new entries with `version: 2` alongside the old
  `version: 1` entries. Both MUST keep passing until the old format is
  formally deprecated.
- Test runners iterate all versions in the file.

## How to add a new vector

1. Edit the corresponding `_gen_*` function inside
   `tests/test_vectors.py`. Add an entry to the `inputs` / `cases` list.
2. Run `python tests/test_vectors.py` — this overwrites the JSON files
   from the Python reference implementation.
3. Review the diff. The only changes should be the new entry and any
   verify-only fields (RSA-OAEP/PSS) whose randomness changed.
4. Run `python -m pytest tests/test_vectors.py -v`. All tests should be
   green.
5. Commit the generator change and the JSON diff in the same commit.

## How to add a new primitive

1. Add a new `_gen_<primitive>()` function in
   `tests/test_vectors.py` that writes `<primitive>.json` via
   `_write_bundle`.
2. Add the filename to the `VECTOR_FILES` list so the sanity test
   (`test_all_vector_files_exist`) picks it up.
3. Add a new `test_<primitive>_vectors` function that uses **only**
   stdlib, `cryptography`, and `PyJWT` — no imports from `app/` or
   `cullis_sdk/`. External SDKs must be able to reimplement the same
   runner without pulling in Cullis server code.
4. Document the new file in the table above.

## Running the runner

```bash
python -m pytest tests/test_vectors.py -v
```

## Regenerating from the Python reference

```bash
python tests/test_vectors.py
```

This is a maintainer-only action. CI must never run the generator; it
must only run the pytest runner against the committed JSON files.
