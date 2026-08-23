# Audit Log Bulk Export Design

## 1. Export goals

The export feature produces a self-contained bundle for records selected by
`resourceId` or `actorId`. The bundle must be verifiable offline, without a
connection to the source database.

The prototype must:

- preserve the existing audit record sequence and hash-chain semantics;
- represent selected records and the chain context required to verify them;
- include active and archived records in one logical chain;
- export redacted presentation payloads without original sensitive values or
  field salts;
- detect changes to bundle files after export;
- distinguish chain integrity, bundle integrity, redaction consistency, and
  optional signature validity.

**Decision:** Use a versioned ZIP bundle with canonical JSON and a full-prefix
chain proof from genesis.

**Alternatives:** Export a flat JSON list; export only selected records with
predecessor hashes; use externally anchored range proofs.

**Reason:** A full prefix is the simplest independently verifiable proof for a
linear chain and does not require external infrastructure.

**Trade-offs:** Context records may disclose unrelated events and exports may
become large.

**Prototype impact:** The exporter and offline verifier must understand the
bundle format and the complete prefix through the last selected record.

## 2. Non-goals

- External WORM storage.
- External timestamping or notarization.
- Advanced range or Merkle proofs.
- Selective-disclosure cryptography.
- Externally anchored checkpoints.
- Production key-management infrastructure.
- Proving that the source database was truthful before export.
- Proving query completeness without trusting the exporter and signed
  selection metadata.
- Recovering or proving the plaintext of an irreversibly redacted field.

**Decision:** Keep these capabilities out of the prototype.

**Alternatives:** Add a public ledger, remote object lock, external signing
service, or zero-knowledge proof system.

**Reason:** They exceed the approved assignment boundary.

**Trade-offs:** The export's strongest guarantees are internal bundle
integrity and chain consistency, not independent historical notarization.

**Prototype impact:** Documentation and verification output must avoid claims
that require these excluded capabilities.

## 3. Export versioning

Every bundle has an `exportVersion`, proposed as `1`. This version identifies
the structure and semantics of the ZIP contents.

It is independent from:

- chain hash version;
- canonicalization version;
- payload schema version;
- field commitment version;
- redaction metadata version;
- signature algorithm/version.

Unsupported versions must be rejected. The verifier must not guess how an
unknown version should be interpreted.

**Decision:** Use explicit, independent version fields.

**Alternatives:** Version only the file names; use the application version as
the export version; infer versions from available fields.

**Reason:** Independent evolution prevents a format change from silently
changing cryptographic interpretation.

**Trade-offs:** More metadata is required and compatibility testing is more
deliberate.

**Prototype impact:** `manifest.json` must declare every version needed by the
verifier.

## 4. ZIP structure

The ZIP bundle contains exactly these required files:

```text
manifest.json
records.json
proof.json
redactions.json
```

The files are UTF-8 JSON. Their byte-level digests are calculated over the
canonical serialized bytes placed in the ZIP.

The ZIP entry names are case-sensitive and must not contain paths, duplicate
entries, or unexpected required-file replacements. Optional future files must
be rejected by a version 1 verifier unless explicitly allowed.

**Decision:** Use a fixed four-file ZIP structure.

**Alternatives:** One JSON document; a directory of one file per record; a
tarball; allow arbitrary extension files.

**Reason:** Fixed entries simplify validation and make component digest
coverage unambiguous.

**Trade-offs:** Adding new data requires a format version or an explicitly
defined optional entry.

**Prototype impact:** The verifier validates entry names, parses all four
files, and checks their manifest digests.

## 5. Manifest schema

`manifest.json` is the signed and integrity-authoritative bundle descriptor.
It contains:

```json
{
  "exportVersion": 1,
  "exportId": "uuid",
  "chainId": "default",
  "createdAt": "UTC timestamp",
  "exporter": "service identifier",
  "selection": {
    "resourceId": "optional",
    "actorId": "optional"
  },
  "selectionMode": "OR",
  "selectedRecordCount": 2,
  "selectedSequences": [4, 9],
  "proofMode": "FULL_PREFIX",
  "lastProofSequence": 9,
  "hashAlgorithm": "SHA-256",
  "canonicalizationVersion": 1,
  "redactionVersion": 1,
  "componentDigests": {
    "records.json": "lowercase hex",
    "proof.json": "lowercase hex",
    "redactions.json": "lowercase hex"
  },
  "signature": {
    "present": false
  }
}
```

The actual schema must reject simultaneous absence of both selectors. The
selection operator is fixed to `OR` for the prototype unless the API contract
explicitly defines another operator.

The manifest must state whether records are selected by actor, resource, or
both, and must list selected sequences rather than relying only on a count.

**Decision:** Make the manifest self-describing and include exact selection
metadata and component digests.

**Alternatives:** Store selection criteria outside the bundle; include only a
record count; use an unsigned human-readable description.

**Reason:** Offline verification needs to know what was requested and what the
bundle claims to contain.

**Trade-offs:** The manifest reveals query criteria and sequence information.

**Prototype impact:** The exporter must generate it before signing, and the
verifier must validate its internal consistency.

## 6. Records schema

`records.json` contains a deterministic object:

```json
{
  "records": [
    {
      "recordId": "uuid",
      "chainId": "default",
      "sequence": 1,
      "selection": "CHAIN_CONTEXT",
      "eventType": "USER_LOGIN",
      "actorId": "actor-1",
      "resourceType": "CLIENT_ACCOUNT",
      "resourceId": "account-1",
      "occurredAt": "UTC timestamp or null",
      "recordedAt": "UTC timestamp",
      "payload": {},
      "payloadCommitment": "digest",
      "payloadSchemaVersion": 1,
      "canonicalizationVersion": 1,
      "contentHash": "digest",
      "previousHash": "digest",
      "presentationHash": "digest",
      "archived": false
    }
  ]
}
```

Every record through `lastProofSequence` is included. Records matching the
query are marked `SELECTED`; other records are marked `CHAIN_CONTEXT`.

The exported `payload` is always the presentation payload. It must never
silently substitute an original value for a redacted field.

**Decision:** Use one deterministic record representation for selected and
context records, with an explicit selection marker.

**Alternatives:** Omit context records; duplicate context fields in
`proof.json`; export the original payload separately.

**Reason:** A single representation makes chain traversal and offline
verification straightforward.

**Trade-offs:** Full-prefix exports disclose context records and may be much
larger than the selected result.

**Prototype impact:** The exporter must retrieve the logical chain, not only
the filtered query rows.

## 7. Proof schema

`proof.json` describes why the records are sufficient to verify the chain:

```json
{
  "proofVersion": 1,
  "mode": "FULL_PREFIX",
  "genesisHash": "digest",
  "chainId": "default",
  "firstSequence": 1,
  "lastSequence": 9,
  "recordCount": 9,
  "selectedSequences": [4, 9],
  "contiguous": true
}
```

The proof file is descriptive, not a replacement for recomputing every
record hash. Its values must agree with `records.json` and `manifest.json`.

**Decision:** Represent the full-prefix proof with genesis, range, and
selection metadata.

**Alternatives:** Include only predecessor hashes; include a trusted internal
checkpoint; use a Merkle proof.

**Reason:** The full prefix itself is the proof for a linear chain. The proof
file makes that fact explicit and machine-checkable.

**Trade-offs:** The proof file adds little cryptographic strength by itself;
its digest and the records remain the substantive evidence.

**Prototype impact:** The verifier must reject a proof that claims a
contiguous prefix while records are missing or reordered.

## 8. Redaction metadata schema

`redactions.json` contains:

```json
{
  "redactionVersion": 1,
  "operations": [
    {
      "redactionId": "uuid",
      "recordId": "uuid",
      "path": "/customer/accountNumber",
      "commitment": "v1:sha256:digest",
      "commitmentId": "uuid",
      "reason": "privacy request",
      "requestedBy": "principal",
      "createdAt": "UTC timestamp",
      "redactionSequence": 1,
      "previousRedactionHash": "digest",
      "presentationHash": "digest",
      "operationHash": "digest"
    }
  ]
}
```

Only operations for records included in the export are included. Each
operation must reference an exported record and use the same canonical path,
commitment, and presentation state as that record.

Salts and original field values are excluded.

**Decision:** Include redaction metadata separately from records and export
only public-safe metadata.

**Alternatives:** Embed operations inside each record; omit redaction metadata;
export salts for independent plaintext verification.

**Reason:** Separate metadata permits independent redaction-consistency checks
without exposing salt material.

**Trade-offs:** The verifier must correlate three files, and metadata may
reveal that a field existed and was redacted.

**Prototype impact:** Redaction operation hashes and presentation hashes must be
recomputable offline from exported data.

## 9. Canonical JSON rules

All JSON files used for hashing follow the existing canonical JSON rules:

- UTF-8 encoding;
- object keys sorted by Unicode code-point order;
- arrays retain order;
- insignificant whitespace omitted;
- JSON strings use deterministic JSON escaping;
- numbers use normalized decimal notation;
- booleans and null use standard JSON literals;
- unsupported values, including non-finite numbers, are rejected.

Timestamps use UTC with fixed nanosecond precision where the source schema
supports it. Database timestamps must be normalized before export so database
formatting does not affect verification.

JSON Pointer paths use RFC 6901 escaping. The canonical path includes decoded
tokens re-encoded as `~0` and `~1`. Ambiguous path forms are rejected.

**Decision:** Reuse one canonicalization implementation and record its version
in every cryptographic envelope.

**Alternatives:** Use database JSON text; rely on ordinary JSON serialization;
use a new exporter-only canonicalization implementation.

**Reason:** Independent verification requires byte-identical interpretation
across implementations.

**Trade-offs:** The canonicalization contract must be maintained as a
compatibility specification.

**Prototype impact:** Export and offline verification must use the same
versioned rules and reject unsupported versions.

## 10. SHA-256 digest rules

SHA-256 produces lowercase hexadecimal digests. Every digest is exactly 64
hexadecimal characters.

Component digests are computed over the canonical UTF-8 bytes of the complete
file content, excluding ZIP metadata such as compression time or entry order.

Record content hashes are recomputed using the existing audit chain contract.
Presentation hashes are computed over the canonical presentation payload.
Redaction operation hashes use the versioned redaction operation envelope.

**Decision:** Use SHA-256 consistently for record, presentation, operation, and
component digests.

**Alternatives:** SHA-512; a ZIP checksum; a digest over compressed bytes; a
different algorithm for each artifact.

**Reason:** SHA-256 is already approved and available to independent
verifiers.

**Trade-offs:** SHA-256 does not provide authenticity without a trusted
signature or trusted delivery channel.

**Prototype impact:** The verifier must report digest mismatches separately
from signature failures.

## 11. Full-prefix chain proof

For a selection containing sequences `4` and `9`, the export includes records
from sequence `1` through sequence `9`. The records at sequences `1`, `2`,
`3`, `5`, `6`, `7`, and `8` are context records.

The verifier:

1. validates the documented genesis hash;
2. requires the first record to have sequence `1`;
3. checks each record's sequence increments by one;
4. checks each `previousHash` equals the preceding `contentHash`;
5. recomputes each content hash from the exported immutable envelope;
6. verifies the selected marker and selection criteria;
7. confirms the final sequence equals `lastProofSequence`;
8. confirms the final hash and record count match the manifest/proof.

The proof establishes continuity only through the last included sequence. It
does not prove that no later records exist in the source database.

**Decision:** Use full-prefix proof rather than attempting compact proofs.

**Alternatives:** Export only selected rows; include a predecessor hash chain
without predecessor records; rely on an internal checkpoint.

**Reason:** A verifier without the database needs the full content of every
preceding record to recompute a simple hash chain.

**Trade-offs:** Privacy and size costs are accepted for prototype simplicity.

**Prototype impact:** Large exports require streaming generation and bounded
offline verification memory.

## 12. Archived-record handling

Archived records remain part of the logical chain. The exporter reads active
and archive storage as one sequence-ordered source.

Each record includes an `archived` indicator. Archive timestamps or segment
identifiers may be included if they are part of the approved record metadata,
but they must not replace the original sequence, content hash, or predecessor
hash.

Archived records needed for the prefix are included even when they do not
match the selection criteria.

**Decision:** Treat active and archived records identically for chain proof,
with archive state represented as metadata.

**Alternatives:** Exclude archived rows; export only archive segments; treat
archive boundaries as new genesis values.

**Reason:** Retention must not create a false chain break.

**Trade-offs:** Archived sensitive metadata can still be disclosed as context.

**Prototype impact:** Export queries and verifiers must not assume the active
table contains the complete chain.

## 13. Redacted-field handling

The exported record payload is the current presentation payload. A redacted
field contains the approved deterministic redaction marker, not its original
value.

The export includes:

- the immutable record envelope fields;
- the original content hash and previous hash;
- the payload commitment;
- the presentation payload and presentation hash;
- redaction operations for the record;
- field commitment identifiers/digests where approved.

The export excludes:

- original sensitive field values that are unavailable through the API;
- field salts;
- any hidden recovery material.

Offline verification can establish that:

- the immutable chain envelope is intact;
- the exported presentation hash is correct;
- redaction metadata is structurally valid;
- replaying the exported redactions produces the exported presentation state.

It cannot prove the original plaintext of a redacted field without the
original value and salt. After irreversible destruction, the permitted claim
is only:

> This field was originally committed, and the current value is intentionally
> unavailable under the recorded redaction operation.

**Decision:** Export safe presentation state and redaction evidence, never
plaintext recovery material.

**Alternatives:** Export original payloads; export salts; omit redaction
metadata and treat markers as ordinary values.

**Reason:** The approved boundary prioritizes non-disclosure while preserving
chain and projection verification.

**Trade-offs:** Independent verification cannot establish original-value
correspondence after the value is unavailable.

**Prototype impact:** Verification output must not label a redacted payload as
equivalent to the original payload.

## 14. Offline verification algorithm

The verifier produces four independent results:

```text
chainIntegrity
componentIntegrity
redactionConsistency
signatureValidity
```

### Component verification

1. Open the ZIP.
2. Validate required entries and reject duplicates.
3. Parse all four canonical JSON files.
4. Re-serialize each file canonically.
5. Compute its SHA-256 digest.
6. Compare component digests with the manifest.

### Signature verification

If a signature is present, verify it after component verification using the
configured trusted public key. If absent, return `NOT_PRESENT`, not `VALID`.

### Chain verification

1. Validate export and proof versions.
2. Validate chain ID and genesis hash.
3. Sort only after confirming the supplied order is deterministic; reject
   duplicate or missing sequences.
4. Walk the prefix from genesis.
5. Recompute every content hash and predecessor link.
6. Verify the final range and chain metadata.
7. Confirm selected records satisfy the manifest criteria.

### Redaction verification

1. Validate operation paths and versions.
2. Confirm referenced records and commitments exist in the bundle.
3. Verify operation sequence and previous operation hash.
4. Recompute each operation hash.
5. Replay redactions deterministically.
6. Recompute each presentation hash.
7. Compare the resulting presentation payload with the exported payload.

The verifier must report the first failure in each category, not collapse all
failures into one generic `invalid` result.

**Decision:** Make the four verification dimensions independent.

**Alternatives:** Return one `verified` boolean; treat projection failures as
chain failures; skip redaction verification.

**Reason:** Each artifact proves a different property.

**Trade-offs:** Consumers must understand multiple statuses.

**Prototype impact:** The offline verifier and API/reporting format need
distinct failure categories.

## 15. Verification failure cases

### Component integrity failures

- missing required ZIP entry;
- duplicate or unexpected entry;
- malformed JSON;
- non-canonical JSON;
- component digest mismatch;
- manifest count or range mismatch.

### Chain integrity failures

- wrong genesis;
- sequence gap or duplicate;
- predecessor mismatch;
- content-hash mismatch;
- chain ID mismatch;
- final proof range mismatch.

### Redaction consistency failures

- missing referenced record;
- invalid canonical path;
- missing commitment;
- operation sequence mismatch;
- operation predecessor mismatch;
- operation-hash mismatch;
- presentation-hash mismatch;
- replayed projection differs from exported payload;
- redacted marker contains prohibited sensitive material.

### Signature failures

- unsupported signature algorithm;
- unknown key ID;
- invalid signature;
- signature over different manifest bytes;
- signature present but malformed.

**Decision:** Use stable, category-specific failure codes and identify the
first affected record or file where possible.

**Alternatives:** Throw an undifferentiated parse error; report only the first
failure globally.

**Reason:** Operators and auditors need to distinguish bundle corruption from
chain tampering and redaction inconsistency.

**Trade-offs:** Failure taxonomy becomes part of the compatibility contract.

**Prototype impact:** Tests must cover each category independently.

## 16. Optional detached signature design

The signature is optional. When present, `signature.json` is not required by
the prototype ZIP structure; instead, the signature object is embedded in
`manifest.json` or supplied as a detached artifact alongside the ZIP.

The signed bytes are the canonical manifest with the signature field omitted,
including the component digests. Proposed metadata:

```json
{
  "present": true,
  "algorithm": "Ed25519",
  "keyId": "export-key-1",
  "signatureEncoding": "base64url",
  "signature": "..."
}
```

The exact algorithm is not mandated. Ed25519 is a proposed prototype option
because it provides compact signatures and straightforward public-key
verification.

If no signature is included, the verifier still performs all hash and chain
checks, but reports signature status as `NOT_PRESENT`.

**Decision:** Support signatures as an optional capability without making
them a prerequisite for parsing the prototype bundle.

**Alternatives:** Require signatures; use HMAC; sign the compressed ZIP bytes;
omit signatures entirely.

**Reason:** Independent verification benefits from authenticity, but the
approved boundary does not provide production key management.

**Trade-offs:** Unsigned bundles are vulnerable to an attacker replacing both
records and component digests. A signature improves authenticity only when
the public key is trusted and the private key is protected.

**Prototype impact:** Signature support may be feature-flagged and must not
alter unsigned verification semantics.

## 17. Signing-key assumptions

The prototype assumes that a verifier receives a trusted public key or a
trusted key-to-public-key configuration out of band.

The prototype does not define:

- key generation ceremony;
- hardware-backed storage;
- rotation;
- revocation;
- compromise recovery;
- certificate authority integration;
- timestamping of key validity.

The signature proves that the holder of the corresponding private key signed
the manifest bytes. It does not prove that the source database was honest or
that the selection was complete.

**Decision:** Treat signature trust and key distribution as deployment
responsibilities, not as application guarantees.

**Alternatives:** Embed the public key in the bundle; use an external PKI;
trust any key named in the manifest.

**Reason:** A public key supplied by the same untrusted bundle provides no
meaningful authenticity.

**Trade-offs:** Offline verification requires a trusted configuration or
manual key distribution.

**Prototype impact:** A verifier must distinguish `UNKNOWN_KEY` from
`INVALID_SIGNATURE`.

## 18. Security considerations

- Validate ZIP entry names and reject path traversal.
- Reject duplicate entries and decompression bombs using size limits.
- Limit JSON nesting, record count, and total uncompressed size.
- Avoid logging payloads, salts, signatures, or sensitive error context.
- Treat manifest selection criteria and redaction metadata as potentially
  sensitive.
- Do not trust record-provided algorithms or versions without allowlists.
- Use constant-time digest/signature comparison where applicable.
- Do not treat component hashes as authenticity without a signature or
  trusted delivery channel.
- Protect signing keys outside the bundle.
- Ensure exports are authorized before generation.

**Decision:** Apply defensive parsing and explicit algorithm/version
allowlisting.

**Alternatives:** Trust ZIP/JSON libraries to enforce all limits; accept
algorithm names from the manifest; expose detailed payload errors.

**Reason:** Export files are untrusted input to the offline verifier.

**Trade-offs:** Strict limits may reject legitimate large exports and require
configuration.

**Prototype impact:** Size and nesting limits must be documented and tested.

## 19. Privacy considerations

Full-prefix proofs disclose unrelated chain-context records. This is the main
privacy cost of the prototype proof strategy.

Additional leakage includes:

- actor and resource selection criteria;
- sequence positions;
- archive status;
- redaction paths and reasons;
- redaction timestamps and principals;
- commitment correlation;
- unredacted payloads for context records.

Exports must use the same authorization boundary as the source export API.
Redaction must not be bypassed because a record is being exported.

**Decision:** Accept full-prefix disclosure for prototype simplicity and state
the limitation in export documentation.

**Alternatives:** Omit context records; use range proofs; encrypt the bundle;
use selective-disclosure proofs.

**Reason:** Those alternatives are explicitly outside the prototype boundary.

**Trade-offs:** The export may contain more data than the query result and
must be handled as sensitive.

**Prototype impact:** Export authorization, storage, transfer, and deletion
procedures require operational review.

## 20. Compatibility/versioning strategy

Version 1 supports:

- one global chain ID per export;
- selection by `actorId` or `resourceId`;
- `FULL_PREFIX` proof mode;
- SHA-256;
- existing canonical JSON version;
- current redaction presentation and operation formats;
- optional detached signature metadata.

Future versions may add compact proofs, multiple chains, new algorithms, or
new redaction representations. They must use a new version or an explicitly
backward-compatible optional field.

Verifiers must reject unknown cryptographic algorithms, canonicalization
versions, and proof modes. Exporters should retain the ability to produce
older versions while those versions remain supported.

**Decision:** Make cryptographic and structural compatibility explicit and
fail closed on unknown interpretations.

**Alternatives:** Best-effort parsing; silently ignore unknown fields;
version only the API endpoint.

**Reason:** Silent interpretation changes can invalidate audit evidence.

**Trade-offs:** Migration requires coordinated exporter/verifier releases.

**Prototype impact:** Version vectors and unsupported-version tests are
required.

## 21. Testing strategy

### Unit tests

- canonical manifest/file serialization;
- digest generation;
- manifest consistency validation;
- selection matching;
- full-prefix proof validation;
- genesis and predecessor verification;
- redaction operation replay;
- redacted payload non-disclosure;
- version and algorithm allowlisting.

### Integration tests

- export active records;
- export actor-filtered records;
- export resource-filtered records;
- export non-contiguous selections;
- export across active/archive boundaries;
- export records with multiple redactions;
- export empty selections;
- export large result sets;
- verify a generated bundle without database access.

### Tamper tests

- alter one record field;
- alter a record hash;
- alter proof range;
- alter manifest criteria;
- alter component file contents;
- remove or duplicate a ZIP entry;
- reorder records;
- remove a context record;
- alter redaction metadata;
- alter a presentation payload;
- corrupt or remove a signature;
- replace both content and unsigned component digests.

Expected outcomes must identify the affected verification category.

**Decision:** Test each verification property and tamper class independently.

**Alternatives:** Test only successful exports; test only chain hashes;
compare exported JSON manually.

**Reason:** Export integrity, chain integrity, redaction consistency, and
signature validity fail independently.

**Trade-offs:** The test suite requires deterministic fixtures and an offline
verifier harness.

**Prototype impact:** Docker/Testcontainers coverage should include active and
archive storage; pure unit tests should cover offline verification without a
database.

## 22. Performance considerations

Full-prefix exports have cost proportional to the last selected sequence, not
just the number of selected records. The exporter should:

- stream records in sequence order;
- avoid loading the entire export into memory;
- calculate component digests while writing canonical bytes;
- enforce configurable record and uncompressed-size limits;
- use ZIP compression without making verification depend on compression;
- verify records incrementally;
- expose export counts and byte limits in the API contract.

The prototype does not promise a throughput or latency target.

**Decision:** Optimize for bounded memory and deterministic output before
optimizing proof compactness.

**Alternatives:** Load all records in memory; use database-specific dumps;
implement range proofs first.

**Reason:** Streaming is low-risk and compatible with the full-prefix model.

**Trade-offs:** Streaming complicates canonical JSON framing and failure
cleanup, and large prefixes remain expensive.

**Prototype impact:** Export limits and partial-output cleanup are required.

## 23. Limitations

- A full-prefix proof may disclose unrelated records.
- The bundle proves only the records and metadata it contains.
- It does not prove that later records do not exist.
- It does not prove query completeness against a malicious exporter.
- Unsigned bundles have no authenticity guarantee beyond trusted delivery.
- A signature authenticates the signed bundle, not the original database.
- A fixed genesis does not prevent a complete rewrite of the source chain.
- Redacted exports cannot prove original plaintext after value/salt loss.
- Commitment metadata may leak paths, equality, or low-entropy information.
- Archive status does not prove secure deletion from every copy.
- No production key management or external anchoring is provided.

**Decision:** Surface these limitations in verifier output and operator
documentation.

**Alternatives:** Return a single `VERIFIED` status; omit proof limitations
from the bundle.

**Reason:** The verifier must not overstate what offline evidence establishes.

**Trade-offs:** Consumers need a more nuanced interpretation of results.

**Prototype impact:** API and documentation must use separate integrity,
authenticity, completeness, and privacy language.

## 24. Open decisions

The following require approval before implementation:

1. Exact API path, request schema, response schema, and HTTP status codes.
2. Whether `actorId` and `resourceId` may be supplied together, and whether
   the operator is `OR` or `AND`.
3. Whether a selector must match at least one record or empty exports are
   valid.
4. Maximum record count, payload size, ZIP size, and JSON nesting depth.
5. Exact manifest schema and whether `selectedSequences` is always included.
6. Whether context records may expose fields that the requester could not
   independently query.
7. Whether a full-prefix export is acceptable despite unrelated-record
   disclosure.
8. Exact canonical timestamp precision and canonical JSON compatibility
   version.
9. Exact signature algorithm, signature placement, public-key distribution,
   and whether unsigned exports are permitted.
10. Whether component digests include `manifest.json` itself through a
    self-excluding canonicalization rule or only cover the three subordinate
    files.
11. Whether archive timestamps and segment identifiers are exportable.
12. Whether redaction metadata includes reasons and requesting principals in
    every export.
13. Whether commitment digests or only opaque commitment identifiers are
    exposed.
14. Whether exports of records with unavailable original values must include a
    formal `originalValueUnavailable` status.
15. Whether export completeness is an explicit claim or only a trusted
    exporter assertion.
16. Offline verifier resource limits and behavior for oversized bundles.
17. Signature key rotation and revocation policy, if signatures are enabled.
18. Retention and deletion policy for generated export bundles.

Until these decisions are approved, they remain prototype design proposals and
must not be treated as silently selected requirements.
