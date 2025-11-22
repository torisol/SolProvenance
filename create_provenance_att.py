"""Create a com.SolProvenance.provenanceATT record with binding hash + OTS.

Usage:
    python create_provenance_att.py \
      --handle YOUR_HANDLE \
      --app-password YOUR_APP_PASSWORD \
      --key-record-uri at://did:.../com.SolProvenance.provenanceKey/xxx \
      --att-device-cert /path/to/att_device_cert.asc \
      [--att-sig-cert /path/to/att_sig_cert.asc] \
      [--att-dec-cert /path/to/att_dec_cert.asc] \
      [--att-aut-cert /path/to/att_aut_cert.asc]

- Reads cert files as text (ASCII armor expected).
- Computes canonical binding string: ATT|key_record_uri=...|att_device_cert=...|att_sig_cert=...|att_dec_cert=...|att_aut_cert=...|created_at=...
- Stamps binding hash with OpenTimestamps and creates provenanceATT record.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import subprocess
import sys
import tempfile
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from atproto import Client

PROVENANCE_ATT_COLLECTION = "com.SolProvenance.provenanceATT"


def now_iso_utc() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def read_file_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except Exception as e:
        raise SystemExit(f"Failed to read {path}: {e}")


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


def build_attestation_binding_string(
    key_record_uri: str,
    att_device_cert: str,
    att_sig_cert: Optional[str],
    att_dec_cert: Optional[str],
    att_aut_cert: Optional[str],
    created_at: str,
) -> str:
    def _val(v: Optional[str]) -> str:
        return v if v else "NA"

    return "|".join(
        [
            "ATT",
            f"key_record_uri={key_record_uri}",
            f"att_device_cert={att_device_cert}",
            f"att_sig_cert={_val(att_sig_cert)}",
            f"att_dec_cert={_val(att_dec_cert)}",
            f"att_aut_cert={_val(att_aut_cert)}",
            f"created_at={created_at}",
        ]
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Create provenanceATT record")
    parser.add_argument("--handle", required=True)
    parser.add_argument("--app-password", required=True)
    parser.add_argument("--key-record-uri", required=True)
    parser.add_argument("--att-device-cert", required=True, type=Path)
    parser.add_argument("--att-sig-cert", type=Path)
    parser.add_argument("--att-dec-cert", type=Path)
    parser.add_argument("--att-aut-cert", type=Path)
    args = parser.parse_args()

    key_record_uri = args.key_record_uri
    att_device_cert = read_file_text(args.att_device_cert)
    att_sig_cert = read_file_text(args.att_sig_cert) if args.att_sig_cert else None
    att_dec_cert = read_file_text(args.att_dec_cert) if args.att_dec_cert else None
    att_aut_cert = read_file_text(args.att_aut_cert) if args.att_aut_cert else None

    created_at = now_iso_utc()
    binding_input = build_attestation_binding_string(
        key_record_uri,
        att_device_cert,
        att_sig_cert,
        att_dec_cert,
        att_aut_cert,
        created_at,
    )
    att_binding_hash = hashlib.sha256(binding_input.encode("utf-8")).hexdigest()
    att_ots_proof_b64 = ots_stamp_hash(att_binding_hash)

    client = Client()
    client.login(args.handle, args.app_password)

    record = {
        "keyRecordUri": key_record_uri,
        "attDeviceCert": att_device_cert,
        "attSigCert": att_sig_cert,
        "attDecCert": att_dec_cert,
        "attAutCert": att_aut_cert,
        "createdAt": created_at,
        "attBindingHash": att_binding_hash,
        "attOTSProofB64": att_ots_proof_b64,
    }

    print("About to create provenanceATT with:")
    print(json.dumps(record, indent=2))
    confirm = input("Proceed? [y/N]: ").strip().lower()
    if confirm != "y":
        print("Aborted.")
        sys.exit(0)

    res = client.com.atproto.repo.create_record(
        data={
            "repo": client.me.did,
            "collection": PROVENANCE_ATT_COLLECTION,
            "record": record,
        }
    )
    print("Created provenanceATT:")
    print(json.dumps({"uri": res["uri"], "cid": res["cid"]}, indent=2))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nAborted by user.")
        sys.exit(1)
