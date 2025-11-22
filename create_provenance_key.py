"""Create a com.SolProvenance.provenanceKey record with binding hash + OTS.

Usage:
    python create_provenance_key.py \
      --handle YOUR_HANDLE \
      --app-password YOUR_APP_PASSWORD \
      --gpg-fpr YOUR_FPR \
      [--hardware-backed true|false] \
      [--hardware-type yubikey|none|hsm|smartcard] \
      [--attestation-present true|false] \
      [--attestation-uri at://...]

Notes:
- Defaults: hardware_backed=false, hardware_type=none, attestation_present=false, attestation_uri=None.
- Public key is exported via gpg; set GPG_KEY_ID below if you want to force a specific key id.
- Binding string: KEY|gpg_fingerprint=...|public_key=...|created_at=...|hardware_backed=...|hardware_type=...|attestation_present=...|attestation_record_uri=...
- Binding hash is SHA-256 of the UTF-8 binding string; then OTS stamped before record creation.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from atproto import Client

PROVENANCE_KEY_COLLECTION = "com.SolProvenance.provenanceKey"
GPG_KEY_ID = "GPG_KEY_ID"  # optional override for gpg export


def now_iso_utc() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def ots_stamp_hash(hash_hex: str) -> str:
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir_path = Path(tmpdir)
        hash_path = tmpdir_path / "hash.txt"
        hash_path.write_text(hash_hex, encoding="utf-8")
        subprocess.run(
            ["ots", "stamp", str(hash_path)],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        proof_path = hash_path.with_suffix(hash_path.suffix + ".ots")
        proof_bytes = proof_path.read_bytes()
        return base64.b64encode(proof_bytes).decode("ascii")


def build_key_binding_string(
    gpg_fpr: str,
    gpg_pubkey: str,
    created_at: str,
    hardware_backed: bool,
    hardware_type: Optional[str],
    attestation_present: bool,
    attestation_record_uri: Optional[str],
) -> str:
    hardware_type_val = hardware_type or "none"
    att_uri_val = attestation_record_uri or "NA"
    return "|".join(
        [
            "KEY",
            f"gpg_fingerprint={gpg_fpr}",
            f"public_key={gpg_pubkey}",
            f"created_at={created_at}",
            f"hardware_backed={str(hardware_backed).lower()}",
            f"hardware_type={hardware_type_val}",
            f"attestation_present={str(attestation_present).lower()}",
            f"attestation_record_uri={att_uri_val}",
        ]
    )


def export_gpg_public_key(key_hint: Optional[str]) -> str:
    cmd = ["gpg", "--armor", "--export"]
    if key_hint:
        cmd.append(key_hint)
    proc = subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return proc.stdout.decode("utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Create provenanceKey record")
    parser.add_argument("--handle", required=True)
    parser.add_argument("--app-password", required=True)
    parser.add_argument("--gpg-fpr", required=True, help="Fingerprint to record")
    parser.add_argument("--hardware-backed", choices=["true", "false"], default="false")
    parser.add_argument("--hardware-type", default="none")
    parser.add_argument("--attestation-present", choices=["true", "false"], default="false")
    parser.add_argument("--attestation-uri")
    parser.add_argument("--gpg-key-id", help="Optional key id/hint for gpg --export (defaults to GPG_KEY_ID or fingerprint)")
    args = parser.parse_args()

    hardware_backed = args.hardware_backed.lower() == "true"
    attestation_present = args.attestation_present.lower() == "true"
    hardware_type = args.hardware_type
    attestation_record_uri = args.attestation_uri

    key_hint = args.gpg_key_id or (GPG_KEY_ID if GPG_KEY_ID != "GPG_KEY_ID" else args.gpg_fpr)

    gpg_pubkey = export_gpg_public_key(key_hint)
    created_at = now_iso_utc()

    binding_input = build_key_binding_string(
        args.gpg_fpr,
        gpg_pubkey,
        created_at,
        hardware_backed,
        hardware_type,
        attestation_present,
        attestation_record_uri,
    )
    key_binding_hash = hashlib.sha256(binding_input.encode("utf-8")).hexdigest()
    key_ots_proof_b64 = ots_stamp_hash(key_binding_hash)

    record = {
        "gpgFingerprint": args.gpg_fpr,
        "gpgPublicKeyArmored": gpg_pubkey,
        "createdAt": created_at,
        "hardwareBacked": hardware_backed,
        "hardwareType": hardware_type,
        "attestationPresent": attestation_present,
        "attestationRecordUri": attestation_record_uri,
        "keyBindingHash": key_binding_hash,
        "keyOTSProofB64": key_ots_proof_b64,
    }

    print("About to create provenanceKey with:")
    print(json.dumps(record, indent=2))
    confirm = input("Proceed? [y/N]: ").strip().lower()
    if confirm != "y":
        print("Aborted.")
        sys.exit(0)

    client = Client()
    client.login(args.handle, args.app_password)

    res = client.com.atproto.repo.create_record(
        data={
            "repo": client.me.did,
            "collection": PROVENANCE_KEY_COLLECTION,
            "record": record,
        }
    )
    print("Created provenanceKey:")
    print(json.dumps({"uri": res["uri"], "cid": res["cid"]}, indent=2))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nAborted by user.")
        sys.exit(1)
