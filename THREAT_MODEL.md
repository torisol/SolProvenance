# SolProvenance Threat Model

## Security Goals

- **Authenticity**: Only the true author can produce valid signed posts.
- **Integrity**: No one, including the platform, can alter a post undetectably.
- **Temporal Proof**: Creation time must be anchored outside Bluesky.
- **Immutability**: All provenance records are unchangeable.

---

# Threats and Defenses

## 1. Account Compromise
**Threat:** Attacker logs into your Bluesky account  
**Defense:** Cannot produce signedText from your YubiKey  
**Outcome:** Verification fails immediately

## 2. Platform Tampering
**Threat:** Bluesky admin alters CIDs or records  
**Defense:** Binding hash includes CID; OTS anchoring prevents reordering or backdating

## 3. Content Tampering
**Defense:** GPG clearsign + binding hash catches any modification

## 4. Backdating Attack
**Defense:**  
- YubiKey cannot backdate signatures  
- OTS anchors to Bitcoin; must rewrite blockchain (impossible)

## 5. Man-in-the-middle (MITM)
**Defense:**  
- signing happens *before* sending anything to Bluesky  
- binding hash references final CIDs  
- tampering is detectable

---

# Assumptions

1. YubiKey is physically secure  
2. User protects their PIN  
3. Bitcoin blockchain remains immutable  
4. ATProto returns cryptographically valid CIDs

---

# Residual Risks

- Coercion signing attacks  
- Malware capturing signed plaintext before touch  
- Future quantum attacks on RSA/EdDSA