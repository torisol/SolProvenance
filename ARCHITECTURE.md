# SolProvenance Architecture

SolProvenance implements a **three-record cryptographic provenance chain** for Bluesky posts, using:

- GPG signatures (hardware-backed with YubiKey)
- OpenTimestamps stamping (Bitcoin blockchain anchoring)
- AT Protocol custom lexicons
- Local ledger audit trail

No record is *ever* updated after creation. All records are immutable.

---

# 1. Data Flow Overview

```

User writes post
↓
GPG clearsigns → (signedText, gpgFingerprint)
↓
HASH = SHA256(signedText | gpgFingerprint)
↓
OTS = OpenTimestamps(HASH)
↓
Create provenanceRoot record
↓
Post skeet (Bluesky)
↓
BIND = SHA256(signedText | gpgFingerprint | provURI | provCID | skeetURI | skeetCID)
↓
OTS2 = OpenTimestamps(BIND)
↓
Create provenanceOTS record
↓
Append to ledger.jsonl

```

---

# 2. Record Types

## provenanceKey (persistent account-level)
Stores:
- armored GPG public key
- fingerprint

## provenanceRoot (signature layer)
Immutable per-post. Stores:
- signedText (full clearsigned block)
- gpgFingerprint
- sigStampHash (SHA256)
- sigOTSProofB64 (OTS proof)

## provenanceOTS (binding layer)
Immutable. Stores:
- provenanceRoot URI/CID
- skeet URI/CID
- bindingStampHash
- bindingOTSProofB64
- stampedAt

---

# 3. Cryptographic Properties

### Signature Layer
- Authenticates content
- Timestamped by Bitcoin
- Validates authorship and ordering

### Binding Layer
- Binds signed text to ATProto records
- Detects tampering/modification
- Anchored in Bitcoin

### Ledger
- Provides local, offline, platform-independent audit

---

# 4. Why Nothing Is Ever Updated

Updating would:
- break immutability
- break CID consistency
- introduce races in ordering
- break OTS anchoring semantics

Option B (immutable) is correct cryptographic design.

---

# 5. Verification Path

A verifier checks:

1. GPG clearsign matches your public key
2. SHA256(signedText|gpgFpr) matches sigStampHash
3. OpenTimestamps proof is valid
4. provenanceRoot URI/CID matches ledger
5. Binding hash matches recomputation
6. OTS2 proof is valid

Bluesky is never trusted.