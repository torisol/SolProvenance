"""One-off upgrader for com.SolProvenance.provenanceKey records to the new schema.

- Finds your existing provenanceKey by fingerprint.
- Fills missing fields (createdAt, hardware/attestation flags, binding hash, OTS proof).
- Updates the record via put_record with swapRecord to preserve CID safety.

Usage:
    python update_provenance_key.py \
      --handle YOUR_HANDLE \
      --app-password YOUR_APP_PASSWORD \
      --gpg-fpr YOUR_FPR \
      [--hardware-backed true|false] \
      [--hardware-type yubikey|none|...] \
      [--attestation-present true|false] \
      [--attestation-uri at://...]

Defaults:
- If the record already has values, those are used unless overridden.
- createdAt is preserved if present, otherwise set to now.
- hardware_backed/attestation_present default to False if missing.
- gpgPublicKeyArmored is taken from the existing record if present, otherwise exported via gpg (GPG_KEY_ID placeholder).
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
from typing import Optional, Tuple

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


def export_gpg_public_key() -> str:
    cmd = ["gpg", "--armor", "--export"]
    if GPG_KEY_ID:
        cmd.append(GPG_KEY_ID)
    proc = subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return proc.stdout.decode("utf-8")


def find_key_record(client: Client, fpr: str):
    res = client.com.atproto.repo.list_records(
        params={"repo": client.me.did, "collection": PROVENANCE_KEY_COLLECTION, "limit": 10}
    )
    for rec in getattr(res, "records", []):
        val = getattr(rec, "value", {}) or {}
        current_fpr = val.get("gpgFingerprint") if isinstance(val, dict) else getattr(val, "gpgFingerprint", None)
        if current_fpr == fpr:
            return rec
    return None


def main():
    parser = argparse.ArgumentParser(description="Upgrade provenanceKey record to new schema")
    parser.add_argument("--handle", required=True, help="Bluesky handle")
    parser.add_argument("--app-password", required=True, help="Bluesky app password")
    parser.add_argument("--gpg-fpr", required=True, help="GPG fingerprint of key to upgrade")
    parser.add_argument("--hardware-backed", choices=["true", "false"], help="override hardwareBacked")
    parser.add_argument("--hardware-type", help="override hardwareType (e.g., yubikey, none)")
    parser.add_argument("--attestation-present", choices=["true", "false"], help="override attestationPresent")
    parser.add_argument("--attestation-uri", help="override attestationRecordUri")
    args = parser.parse_args()

    client = Client()
    client.login(args.handle, args.app_password)

    rec = find_key_record(client, args.gpg_fpr)
    if rec is None:
        print(f"No provenanceKey found for fingerprint {args.gpg_fpr}", file=sys.stderr)
        sys.exit(1)

    val_obj = getattr(rec, "value", None)

    def _get(field, default=None):
        if isinstance(val_obj, dict):
            return val_obj.get(field, default)
        if val_obj is not None:
            return getattr(val_obj, field, default)
        return default

    existing_created_at = _get("createdAt")
    created_at = existing_created_at or now_iso_utc()

    hardware_backed = _get("hardwareBacked", False)
    hardware_type = _get("hardwareType")
    attestation_present = _get("attestationPresent", False)
    attestation_record_uri = _get("attestationRecordUri")

    if args.hardware_backed:
        hardware_backed = args.hardware_backed.lower() == "true"
    if args.hardware_type is not None:
        hardware_type = args.hardware_type
    if args.attestation_present:
        attestation_present = args.attestation_present.lower() == "true"
    if args.attestation_uri is not None:
        attestation_record_uri = args.attestation_uri

    gpg_pubkey = _get("gpgPublicKeyArmored") or export_gpg_public_key()
    gpg_fpr = _get("gpgFingerprint") or args.gpg_fpr

    binding_input = build_key_binding_string(
        gpg_fpr,
        gpg_pubkey,
        created_at,
        hardware_backed,
        hardware_type,
        attestation_present,
        attestation_record_uri,
    )
    key_binding_hash = hashlib.sha256(binding_input.encode("utf-8")).hexdigest()
    key_ots_proof_b64 = ots_stamp_hash(key_binding_hash)

    rkey = rec.uri.rsplit("/", 1)[-1] if hasattr(rec, "uri") else getattr(rec, "rkey", None)
    if not rkey:
        print("Could not determine record key (rkey)", file=sys.stderr)
        sys.exit(1)

    new_record = {
        "gpgFingerprint": gpg_fpr,
        "gpgPublicKeyArmored": gpg_pubkey,
        "createdAt": created_at,
        "hardwareBacked": hardware_backed,
        "hardwareType": hardware_type,
        "attestationPresent": attestation_present,
        "attestationRecordUri": attestation_record_uri,
        "keyBindingHash": key_binding_hash,
        "keyOTSProofB64": key_ots_proof_b64,
    }

    print("About to update provenanceKey with:")
    print(json.dumps(new_record, indent=2))
    confirm = input("Proceed? [y/N]: ").strip().lower()
    if confirm != "y":
        print("Aborted.")
        sys.exit(0)

    client.com.atproto.repo.put_record(
        data={
            "repo": client.me.did,
            "collection": PROVENANCE_KEY_COLLECTION,
            "rkey": rkey,
            "record": new_record,
            "swapRecord": getattr(rec, "cid", None),
        }
    )
    print("provenanceKey updated.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nAborted by user.")
        sys.exit(1)
