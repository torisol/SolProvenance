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

Create provenanceKey (one-time; public key + hardware/attestation metadata + keyBindingHash + OTS)
↓
(Optional) Create provenanceATT (one-time per hardware-backed key; attestation certs + attBindingHash + OTS)
↓
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
Stores: armored GPG public key + fingerprint, createdAt, hardwareBacked/hardwareType, attestationPresent/attestationRecordUri, keyBindingHash + keyOTSProofB64.
Binding string (canonical): KEY|gpg_fingerprint=…|public_key=…|created_at=…|hardware_backed=…|hardware_type=…|attestation_present=…|attestation_record_uri=…

## provenanceATT (hardware attestation, optional)
Stores: keyRecordUri, attDeviceCert (required), optional attSig/attDec/attAut certs, createdAt, attBindingHash + attOTSProofB64.
Binding string: ATT|key_record_uri=…|att_device_cert=…|att_sig_cert=…|att_dec_cert=…|att_aut_cert=…|created_at=…

## provenanceRoot (signature layer)
Immutable per-post. Stores: signedText, gpgFingerprint, sigStampHash, sigOTSProofB64.

## provenanceOTS (binding layer)
Immutable. Stores: provenanceRoot URI/CID, skeet URI/CID, bindingStampHash, bindingOTSProofB64, stampedAt.

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
