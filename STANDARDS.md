# SolProvenance Lexicon Standards

## Namespaces

```

com.SolProvenance.provenanceKey
com.SolProvenance.provenanceATT
com.SolProvenance.provenanceRoot
com.SolProvenance.provenanceOTS

````

---

# 1. provenanceKey Record

Account-level identity key with hardware/attestation metadata and immutable binding.

```json
{
  "lexicon": 1,
  "id": "com.SolProvenance.provenanceKey",
  "type": "record",
  "record": {
    "key": "literal",
    "description": "GPG public key and hardware/attestation metadata",
    "properties": {
      "gpgFingerprint": {"type": "string"},
      "gpgPublicKeyArmored": {"type": "string"},
      "createdAt": {"type": "string", "format": "datetime"},
      "hardwareBacked": {"type": "boolean"},
      "hardwareType": {"type": "string", "nullable": true},
      "attestationPresent": {"type": "boolean"},
      "attestationRecordUri": {"type": "string", "nullable": true},
      "keyBindingHash": {"type": "string"},
      "keyOTSProofB64": {"type": "string"}
    },
    "required": [
      "gpgFingerprint",
      "gpgPublicKeyArmored",
      "createdAt",
      "hardwareBacked",
      "attestationPresent",
      "keyBindingHash",
      "keyOTSProofB64"
    ]
  }
}
````

Canonical binding string:
```
KEY|gpg_fingerprint=…|public_key=…|created_at=…|hardware_backed=…|hardware_type=…|attestation_present=…|attestation_record_uri=…
```

---

# 2. provenanceATT Record

Hardware attestation for a key.

```json
{
  "lexicon": 1,
  "id": "com.SolProvenance.provenanceATT",
  "type": "record",
  "record": {
    "key": "tid",
    "description": "Attestation certificates for a hardware-backed key.",
    "properties": {
      "keyRecordUri": {"type": "string"},
      "attDeviceCert": {"type": "string"},
      "attSigCert": {"type": "string", "nullable": true},
      "attDecCert": {"type": "string", "nullable": true},
      "attAutCert": {"type": "string", "nullable": true},
      "createdAt": {"type": "string", "format": "datetime"},
      "attBindingHash": {"type": "string"},
      "attOTSProofB64": {"type": "string"}
    },
    "required": [
      "keyRecordUri",
      "attDeviceCert",
      "createdAt",
      "attBindingHash",
      "attOTSProofB64"
    ]
  }
}
```

Canonical binding string:
```
ATT|key_record_uri=…|att_device_cert=…|att_sig_cert=…|att_dec_cert=…|att_aut_cert=…|created_at=…
```

---

# 3. provenanceRoot Record

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

# 4. provenanceOTS Record

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
