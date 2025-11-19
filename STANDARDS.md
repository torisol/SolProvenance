# SolProvenance Lexicon Standards

## Namespaces

```

com.SolProvenance.provenanceKey
com.SolProvenance.provenanceRoot
com.SolProvenance.provenanceOTS

````

---

# 1. provenanceKey Record

Stores account-level identity key.

```json
{
  "lexicon": 1,
  "id": "com.SolProvenance.provenanceKey",
  "type": "record",
  "record": {
    "key": "literal",
    "description": "GPG public key + fingerprint",
    "properties": {
      "gpgFingerprint": {"type": "string"},
      "gpgPublicKeyArmored": {"type": "string"}
    },
    "required": ["gpgFingerprint", "gpgPublicKeyArmored"]
  }
}
````

---

# 2. provenanceRoot Record

Per-post signature layer.

```json
{
  "lexicon": 1,
  "id": "com.SolProvenance.provenanceRoot",
  "type": "record",
  "record": {
    "key": "tid",
    "description": "Immutable signature proof for content.",
    "properties": {
      "signedText": {"type": "string"},
      "gpgFingerprint": {"type": "string"},
      "sigStampHash": {"type": "string"},
      "sigOTSProofB64": {"type": "string"}
    },
    "required": ["signedText", "gpgFingerprint", "sigStampHash", "sigOTSProofB64"]
  }
}
```

---

# 3. provenanceOTS Record

Binding layer connecting signature → ATProto.

```json
{
  "lexicon": 1,
  "id": "com.SolProvenance.provenanceOTS",
  "type": "record",
  "record": {
    "key": "tid",
    "description": "OTS proof binding signed text and skeet record.",
    "properties": {
      "provenanceRootUri": {"type": "string"},
      "provenanceRootCid": {"type": "string"},
      "skeetUri": {"type": "string"},
      "skeetCid": {"type": "string"},
      "bindingStampHash": {"type": "string"},
      "bindingOTSProofB64": {"type": "string"},
      "stampedAt": {"type": "string", "format": "datetime"}
    },
    "required": [
      "provenanceRootUri",
      "provenanceRootCid",
      "skeetUri",
      "skeetCid",
      "bindingStampHash",
      "bindingOTSProofB64"
    ]
  }
}