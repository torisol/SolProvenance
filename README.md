# SolProvenance

**Cryptographic Provenance for Social Media**

*Reference implementation by Victoria Loyd*

## Verification Service (Planned)

Future public API for anyone to verify posts:

```bash
curl https://verify.solframework.org/at://did:plc:.../post/3m5w2orpjcb2o
```

**Returns:**
```json
{
  "post_uri": "at://...",
  "signature_layer": {
    "gpg_signature_valid": true,
    "sig_ots_valid": true,
    "sig_ots_block_height": 924166
  },
  "binding_layer": {
    "binding_hash_matches": true,
    "binding_ots_valid": true,
    "binding_ots_block_height": 924166
  },
  "verified_at": "2025-11-18T16:00:00Z",
  "platform_accountability": {
    "all_cids_match": true,
    "provenance_records_immutable": true
  }
}
```

---

## What This Is

SolProvenance provides **unforgeable proof** that you wrote what you posted, when you posted it, and that it hasn't been altered. It works by:

1. **Signing content** with your YubiKey (hardware-backed GPG key)
2. **Creating provenance records** using AT Protocol custom lexicons
3. **Timestamping with OpenTimestamps** (Bitcoin blockchain anchoring)
4. **Binding everything cryptographically** so tampering is detectable

**Result:** Every post has independently verifiable authorship, temporal proof, and integrity guarantees—without trusting Bluesky or any third party.

---

## Why This Matters

### Current State: Authentication ≠ Integrity

- **Blue checks** only prove you control an account at login time
- **Account compromise** = total impersonation with no detection
- **Platform timestamps** are unverifiable and editable by admins
- **Content editing** leaves no cryptographic trail

### SolProvenance Solution

| Layer | Problem | Solution |
|-------|---------|----------|
| **Authentication** | "Is this their account?" | Bluesky DID system |
| **Integrity** | "Did they actually write this?" | YubiKey GPG signature |
| **Provenance** | "When, and has it been altered?" | OpenTimestamps + binding hash |

**If your account is compromised:** Attacker can post, but can't sign. Verification fails immediately.

**If your YubiKey is stolen:** Requires PIN (3 failed attempts = device locks). Even with PIN, attacker can't backdate timestamps.

**As Sol Framework architect noted:** "They don't have a time machine."

---

## Architecture

```
Create provenanceKey record (public key, account-level)
    ↓
User writes post
    ↓
GPG clearsign with YubiKey
    ↓
Compute signature hash:
  SHA-256(signedText | gpgFingerprint)
    ↓     
OpenTimestamps proof of signature hash (Bitcoin blockchain)
    ↓
Create provenanceRoot record
    ↓
Post actual skeet to Bluesky
    ↓
Compute binding hash:
  SHA-256(signedText | gpgFingerprint | provURI | provCID | skeetURI | skeetCID)
    ↓
OpenTimestamps proof of binding hash (Bitcoin blockchain)
    ↓
Create provenanceOTS record
    ↓
Append to local ledger.jsonl (audit trail)
```

### Custom AT Protocol Lexicons

**`com.SolProvenance.provenanceKey`**
- Persistent account record
- Stores GPG public key + fingerprint
- Single source of truth for verification

**`com.SolProvenance.provenanceRoot`**
- Per-post provenance record
- Anchors the plaintext to be skeeted to a cryptographic signature, OTS stamp, and uri/cid before its ever posted
- Includes OTS proof and signature hash

**`com.SolProvenance.provenanceOTS`**
- Binds provenanceRoot and skeet together through uris/cids, cryptographic signature, and OTS proofs

---

## Installation

### Prerequisites

```bash
# Python 3.11+
python3 --version

# GPG with YubiKey support
gpg --version
ykman --version  # YubiKey Manager

# OpenTimestamps client
pip install opentimestamps-client

# AT Protocol SDK
pip install atproto
```

### Setup

```bash
git clone https://github.com/torisol/SolProvenance
cd SolProvenance

# Optional: create venv
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

pip install -r requirements.txt
```

### Configuration

Edit `post_with_provenance.py`:

```python
BLUESKY_HANDLE = "your-handle.bsky.social"
BLUESKY_APP_PASSWORD = "your-app-password"
GPG_KEY_ID = "YOUR_KEY_FINGERPRINT"  # Optional, uses default key if omitted
```

**Security Note:** Use Bluesky app passwords, not your main password. Generate at: Settings → Privacy and Security → App Passwords

---

## Usage

### Posting with Provenance

```bash
python post_with_provenance.py
Enter skeet text (Ctrl+C to abort):
> This is a signed post with cryptographic provenance!
```

**What happens:**
1. Text is signed with your YubiKey (PIN required)
2. Signature hash computed and timestamped
3. provenanceRoot record created on Bluesky
4. Post published
5. Binding hash computed and timestamped
6. provenanceOTS record created on Bluesky
7. Entry appended to `ledger.jsonl`

### Exporting Complete Chain

**Full verification mode (recommended):**
```bash
python export_full_provenance_hybrid.py \
  --handle your-handle.bsky.social \
  --app-password YOUR_APP_PASSWORD \
  --ledger ledger.jsonl \
  --output provenance_export.json
```

**What it does:**
- Reads ledger for URIs and expected CIDs
- Fetches actual records from AT Protocol
- Compares expected vs actual CIDs (trust-but-verify)
- Flags any discrepancies or tampering
- Exits with error if verification fails

**Ledger-only mode (offline/fast):**
```bash
python export_full_provenance_hybrid.py \
  --ledger ledger.jsonl \
  --output provenance_export.json \
  --no-verify
```

**Output includes:**
- All posts with complete CIDs (from ledger)
- All provenance records (signature + binding layers)
- Account-level public key
- Verification status for each record
- Platform accountability audit trail
- Statistics and metadata
- Portable backup independent of Bluesky

### Verification (Manual)

```bash
# 1. Extract signed text from provenance record
echo "$SIGNED_TEXT" > post.asc

# 2. Verify GPG signature
gpg --verify post.asc
# Should show: Good signature from "Victoria Loyd ..."

# 3. Verify OpenTimestamps proof
echo "$BINDING_HASH" > binding.txt
echo "$OTS_PROOF_B64" | base64 -d > binding.txt.ots
ots verify binding.txt.ots
# Should show: Success! Bitcoin block [height]

# 4. Recompute binding hash
echo -n "${SIGNED_TEXT}|${GPG_FPR}|${PROV_URI}|${PROV_CID}|${SKEET_URI}|${SKEET_CID}" | sha256sum
# Should match stampHash in provenance record
```

---

## File Structure

```
SolProvenance/
├── README.md                              # This file
├── post_with_provenance.py                # Main posting tool
├── export_full_provenance_hybrid.py       # Trust-but-verify export
├── verify_post.py                         # Verification tool (TODO)
├── requirements.txt                       # Python dependencies
├── ledger.jsonl                           # Local audit trail
├── examples/                              # Example records
│   ├── 3m5w2orpjcb2o.json                # Skeet (post)
│   ├── 3m5w2ornkgy25.json                # provenanceRoot record
│   ├── 3m5w2ot7y6x22.json                # provenanceOTS record
│   └── 3m5uivxs3zf2d.json                # provenanceKey record
└── docs/
    ├── ARCHITECTURE.md                    # Detailed technical design
    ├── THREAT_MODEL.md                    # Security analysis
    └── STANDARDS.md                       # AT Protocol lexicon 
```

---

## Example Records

### Post
```json
{
  "text": "This is another skeet with a custom Lexicon record sidecar! One with signature, another with OTS stamp.",
  "$type": "app.bsky.feed.post",
  "createdAt": "2025-11-18T15:31:47.878864Z"
}
```

### Provenance Root (Signature Layer)
```json
{
  "$type": "com.SolProvenance.provenanceRoot",
  "signedText": "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\nThis is another skeet...\n-----BEGIN PGP SIGNATURE-----\n...",
  "gpgFingerprint": "D16AE3B579EE87DD2D8EFFF4DEBA71C643C885D3",
  "sigStampHash": "5ad94b22a411bb3ac5655cf7372c184fdc30d6d0d4d94e9a7d1d565f014c975c",
  "sigOTSProofB64": "AE9wZW5UaW1lc3RhbXBzAABQcm9vZgC/ieLohOiSlAEI..."
}
```

### Provenance OTS (Binding Layer)
```json
{
  "$type": "com.SolProvenance.provenanceOTS",
  "provenanceRootUri": "at://did:plc:.../com.SolProvenance.provenanceRoot/3m5w2ornkgy25",
  "provenanceRootCid": "bafyreif6mjr2esbppjwvhp4shja5yi7mzuq4p6nluu27c4khn7wcrocfde",
  "skeetUri": "at://did:plc:.../app.bsky.feed.post/3m5w2orpjcb2o",
  "skeetCid": "bafyreifyjhgheddfpbjikt6shzomm76ozflgtmo3ghqyc5kqgtw3zjq6ni",
  "bindingStampHash": "2d5925401e23a297a94a83037e707fa0af5a0c6376340c619ec494852ed1e3a3",
  "bindingOTSProofB64": "AE9wZW5UaW1lc3RhbXBzAABQcm9vZgC/ieLohOiSlAEI...",
  "stampedAt": "2025-11-18T15:31:49.459883Z"
}
```

### Ledger Entry
```json
{
  "created_at": "2025-11-18T15:31:49.531888Z",
  "post_text": "This is another skeet with a custom Lexicon record sidecar! One with signature, another with OTS stamp.",
  "signed_text": "-----BEGIN PGP SIGNED MESSAGE-----\n...",
  "gpg_fingerprint": "D16AE3B579EE87DD2D8EFFF4DEBA71C643C885D3",
  "provenance_root_uri": "at://did:plc:.../com.SolProvenance.provenanceRoot/3m5w2ornkgy25",
  "provenance_root_cid": "bafyreif6mjr2esbppjwvhp4shja5yi7mzuq4p6nluu27c4khn7wcrocfde",
  "skeet_uri": "at://did:plc:.../app.bsky.feed.post/3m5w2orpjcb2o",
  "skeet_cid": "bafyreifyjhgheddfpbjikt6shzomm76ozflgtmo3ghqyc5kqgtw3zjq6ni",
  "sig_stamp_hash": "5ad94b22a411bb3ac5655cf7372c184fdc30d6d0d4d94e9a7d1d565f014c975c",
  "sig_ots_proof_b64": "AE9wZW5UaW1lc3RhbXBzAABQcm9vZgC/ieLohOiSlAEI...",
  "binding_stamp_hash": "2d5925401e23a297a94a83037e707fa0af5a0c6376340c619ec494852ed1e3a3",
  "binding_ots_proof_b64": "AE9wZW5UaW1lc3RhbXBzAABQcm9vZgC/ieLohOiSlAEI...",
  "provenance_ots_uri": "at://did:plc:.../com.SolProvenance.provenanceOTS/3m5w2ot7y6x22",
  "provenance_ots_cid": "bafyreib6zl4hxppq6strsos66jzpi7wtl3q2pyualln65w2e3aexj3qrpu",
  "binding_stamped_at": "2025-11-18T15:31:49.459883Z"
}
```

---

## Threat Model

### What This Protects Against

✅ **Account compromise** - Attacker can't sign posts without YubiKey  
✅ **Backdating** - OTS proofs are blockchain-anchored  
✅ **Content tampering** - Binding hash detects any modification  
✅ **Impersonation** - GPG signature proves authorship  
✅ **Platform manipulation** - Verification is independent of Bluesky  

### What This Doesn't Protect Against

❌ **Physical coercion** - If forced to sign at under threat of life or property, signature is valid  
❌ **Compromised device before YubiKey touch** - Malware could intercept after PIN entry but before touch  
❌ **Quantum computing** - RSA/Ed25519 vulnerable to future quantum attacks  
❌ **Social engineering** - Attacker convincing you to sign malicious content  
❌ **Remote PIN compromise** - With touch policy enabled, attacker still needs physical access to device  

### Security Assumptions

1. **YubiKey is secure** - Private keys are non-exportable, hardware-protected
   - YubiKey 5 series encrypts PIN entry at USB protocol layer
   - Touch policy can require physical presence for all operations
   - Touch policy can be locked (requires key deletion to change)
   - Current implementation: cached touch policy (one touch per session)
2. **GPG is trustworthy** - Standard implementation without backdoors
3. **Bitcoin is secure** - OTS relies on blockchain immutability
4. **AT Protocol is honest** - DIDs and CIDs are correctly generated
5. **You keep your PIN secret** - 3 failed attempts locks the device permanently

---

## Verification Service (Future)

Planned public API for anyone to verify posts:

```bash
curl https://verify.solframework.org/at://did:plc:.../post/3m5uivyxlez26
```

**Returns:**
```json
{
  "post_uri": "at://...",
  "signature_valid": true,
  "ots_valid": true,
  "binding_hash_matches": true,
  "verified_at": "2025-11-18T12:00:00Z",
  "verification_chain": {
    "gpg_key": "D16AE3B579EE87DD2D8EFFF4DEBA71C643C885D3",
    "ots_block_height": 870523,
    "ots_block_time": "2025-11-18T00:45:32Z"
  }
}
```

---

## Relationship to Sol Framework

SolProvenance is a reference implementation of the **Memory Sovereignty Pattern** from [The Sol Framework](https://github.com/torisol/thesolframework):

- **External verification** ✓ (GPG signing outside platform)
- **Cryptographic lineage** ✓ (hash chains + OTS)
- **Audit trails** ✓ (ledger.jsonl)
- **Non-bypassable enforcement** ✓ (hardware-backed keys)

**Key insight:** If human-generated content needs provenance, AI-generated content needs it even more. This work demonstrates that robust verification is achievable today with commodity hardware and open standards.

---

## Contributing

This is production code solving a real problem. Contributions welcome:

- **Verification tooling** - Build automated verification scripts
- **Browser extensions** - Inline verification in Bluesky UI
- **Cross-platform support** - Extend to Twitter/X, Mastodon, etc.
- **Standards work** - Help get this adopted as official AT Protocol lexicons

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## License

**Code:** MIT License  
**Documentation:** CC BY 4.0

See [LICENSE](LICENSE) for full terms.

---

## Citation

If you use SolProvenance in research or production:

```bibtex
@software{solprovenance2024,
  author = {Loyd, Victoria},
  title = {SolProvenance: Cryptographic Provenance for Social Media},
  year = {2025},
  url = {https://github.com/torisol/SolProvenance},
  note = {Reference implementation of Memory Sovereignty Pattern}
}
```

---

## Author

**Victoria Loyd**  
*Architect, The Sol Framework*

- GitHub: [@torisol](https://github.com/torisol)
- Bluesky: [@mirainthedark.bsky.social](https://bsky.app/profile/mirainthedark.bsky.social)
- YubiKey: `D16AE3B579EE87DD2D8EFFF4DEBA71C643C885D3`

**Acknowledgments:**
- Sol (OpenAI) - Architecture and implementation design
- Claude (Anthropic) - Framework integration and documentation

---

## Status

**Version:** 1.0.0  
**Status:** Production  
**Tested:** Bluesky (AT Protocol)  
**Last Updated:** 2025-11-18

**Security Note:** This is production code handling cryptographic operations. Review the threat model before deploying. Hardware security keys (YubiKey) are strongly recommended.

---

## License

All documentation, prose, and explanatory text in this repository
is licensed under the Creative Commons Attribution 4.0 International License (CC-BY-4.0).

All source code (Python scripts, tooling, schemas, utilities) is licensed under the MIT License.

---

> "They don't have a time machine."  
> — Sol Framework, on the immutability of cryptographic provenance
