### *SolProvenance — Contributor Guide*

Thank you for your interest in contributing to **SolProvenance**.
This project implements a **cryptographically strict, immutable provenance layer** for ATProto/Bluesky posts.
As such, contributions must be handled with exceptional care.

This guide outlines the standards, workflow, verification requirements, and expectations for contributors.

---

# **1. Philosophy of Contributions**

SolProvenance is built around four pillars:

1. **Immutability** — Records are never updated once created.
2. **Verifiability** — Every artifact must be independently verifiable offline.
3. **Minimalism** — No unnecessary fields, dependencies, or features.
4. **Cryptographic Predictability** — No nondeterministic or timestamp-unstable behavior.

Contributions that violate these principles will not be accepted.

Examples of unacceptable PRs:

* Adding timestamps to records without explicit justification
* Adding fields that change CID derivation
* Adding network-dependent verification steps
* Adding automatic record-editing or upsert behavior
* Modifying the canonical hash input schema

Examples of acceptable PRs:

* Improving error handling
* Improving documentation
* Adding new OTS calendar sources
* Adding optional tooling that does not modify core behavior
* Enhancing local export/verification utilities
* CI automation (linting, reproducibility, OTS availability checks)

---

# **2. What You Should Read Before Contributing**

Before opening any issue or PR, contributors **must** read:

* `README.md`
* `ARCHITECTURE.md`
* `THREAT_MODEL.md`
* `STANDARDS.md`

These documents define the invariants SolProvenance relies on.

If your contribution contradicts one of these documents, you must either:

* justify the contradiction with cryptographic reasoning,
* or propose an update to the relevant document first.

---

# **3. Code Style & Project Structure**

### Python

* Python 3.10+
* PEP8 compliant
* No wild imports (`from module import *`)
* Use `pathlib` instead of `os.path`
* All subprocess calls must use explicit `check=True` unless capturing intentional errors
* No new dependencies without discussion

### Lexicons

* Must follow ATProto Lexicon 1.0
* Namespaces MUST begin with `com.SolProvenance.*`
* No breaking changes to existing record schemas
* No field removals
* New fields must be discussed before PR submission
* All lexicon modifications require updates to `STANDARDS.md`

---

# **4. Testing Requirements**

Every PR must include:

### 4.1. Local Verification

Contributors MUST verify:

* GPG rounds trip correctly
* Hashes match known-good fixtures
* OTS stamping and verification succeed
* CAR export parsing (if touched) works on at least one real Bluesky export
* No new nondeterministic behavior is introduced

### 4.2. “No Accidental Breakage” Tests

Before submitting your PR, run:

```bash
python verify_post.py tests/fixtures/example1.json
python verify_post.py tests/fixtures/example2.json
```

Your changes must not cause:

* mismatched hashes
* mismatched fingerprints
* validation failures
* changes in expected CID ordering
* altered canonical string encoding
* differences in signedText output normalization

If your changes fail these tests, the PR will not be accepted.

---

# **5. Submitting a Pull Request**

### 5.1. Branching

Use descriptive branch names:

```
feature/add-ots-calendar
fix/ledger-newline-bug
docs/improve-threat-model
```

**Never** work directly on `main`.

### 5.2. PR Checklist

Your PR must include:

* [ ] A clear explanation of the change
* [ ] Justification if the change affects hashing, signing, or lexicons
* [ ] Updated documentation (if applicable)
* [ ] Local verification logs
* [ ] Before/after comparison for affected components

For changes touching anything cryptographic:

* [ ] A threat-model impact statement
* [ ] Proof that changes do not allow backdating
* [ ] Proof that changes maintain immutability guarantees

### 5.3. PR Review Expectations

* Reviewers may ask for cryptographic proofs, not just explanations
* You may be asked to rebase or rewrite commit history for clarity
* Expect detailed questioning about timestamping, byte encoding, and CID stability
* Reviews prioritize safety > elegance > performance

---

# **6. Reporting Security Issues**

If you discover a vulnerability, **do not post it publicly**.

Email:

```
victoriatloyd@gmail.com 
```

Your message should include:

* Steps to reproduce
* Impact assessment
* Whether the issue affects signature, binding, or OTS layers
* Whether user keys or content authenticity are at risk

You will receive a response within 72 hours.

---

# **7. Governance & Maintainer Responsibilities**

Maintainers (currently: the original author) will:

* Preserve the project's cryptographic guarantees
* Reject any change that introduces ambiguity, nondeterminism, or mutability
* Maintain a high bar for contributions
* Provide reasoning for all accepted or rejected PRs
* Ensure community safety and respectful discussion

---

# **8. Contributor Code of Conduct**

All contributors agree to:

* Respect cryptographic rigor
* Avoid dismissive or vague arguments
* Prefer evidence over assertion
* Assume good faith
* Use inclusive and professional language
* Respect the project’s architectural constraints

---

# **9. Thank You**

SolProvenance exists to give users **real, portable, platform-independent ownership** of their published words.

Every contribution — code, review, documentation, threat analysis — helps strengthen that guarantee.

Thank you for helping make this project worthy of the cryptographic trust users place in it. 🌸