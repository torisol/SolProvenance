#!/usr/bin/env python3
"""Export complete provenance chain with trust-but-verify architecture.

Uses local ledger.jsonl as primary source, but validates all CIDs against
AT Protocol records. Detects tampering, discrepancies, or missing records.

This ensures both speed (ledger lookup) and accountability (protocol verification).
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from atproto import Client


# === Models ===

@dataclass
class RecordRef:
    """Reference to an AT Protocol record with verification status."""
    uri: str = ""
    cid: str = ""
    verified: bool = False
    record: Optional[dict] = None
    verification_error: Optional[str] = None


@dataclass
class ProvenanceEntry:
    """Complete provenance chain for a single post."""
    # Post record
    skeet_uri: str = ""
    skeet_cid: str = ""
    
    skeet_verified: bool = False
    
    # Provenance root (signature layer)
    provenance_root_uri: str = ""
    provenance_root_cid: str = ""
    provenance_root_verified: bool = False
    
    # Provenance OTS (binding layer)
    provenance_ots_uri: str = ""
    provenance_ots_cid: str = ""
    provenance_ots_verified: bool = False
    
    # Cryptographic data
    signed_text: str = ""
    gpg_fingerprint: str = ""
    sig_stamp_hash: str = ""
    sig_ots_proof_b64: str = ""
    binding_stamp_hash: str = ""
    binding_ots_proof_b64: str = ""
    binding_stamped_at: str = ""
    
    # Metadata
    created_at: str = ""
    post_text: str = ""
    
    # Verification summary
    fully_verified: bool = False
    skeet_record: Optional[dict] = None
    provenance_root_record: Optional[dict] = None
    provenance_ots_record: Optional[dict] = None
    verification_errors: list[str] = None


# === Helpers ===

def now_iso_utc() -> str:
    """Return current UTC timestamp in ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def load_ledger(ledger_path: Path) -> list[dict]:
    """Load and parse ledger.jsonl."""
    entries = []
    with ledger_path.open("r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                entries.append(entry)
            except json.JSONDecodeError as e:
                print(f"[WARN] Line {line_no}: Invalid JSON - {e}", file=sys.stderr)
    return entries


def is_new_scheme_entry(entry: dict) -> bool:
    """Check if ledger entry uses the new immutable scheme."""
    required = {
        "post_text", "signed_text", "gpg_fingerprint",
        "provenance_root_uri", "provenance_root_cid",
        "skeet_uri", "skeet_cid",
        "sig_stamp_hash", "sig_ots_proof_b64",
        "binding_stamp_hash", "binding_ots_proof_b64",
        "provenance_ots_uri", "provenance_ots_cid",
        "binding_stamped_at", "created_at"
    }
    return required.issubset(entry.keys())


def fetch_and_verify_record(
    client: Client,
    uri: str,
    expected_cid: str
) -> tuple[Optional[dict], bool, Optional[str]]:
    """
    Fetch record from AT Protocol and verify CID matches.
    
    Returns: (record_dict, verified, error_message)
    """
    try:
        # Parse AT URI to get repo and rkey
        # Format: at://did:plc:xxx/collection/rkey
        parts = uri.split("/")
        if len(parts) < 5:
            return None, False, f"Invalid URI format: {uri}"
        
        repo = parts[2]
        collection = parts[3]
        rkey = parts[4]
        
        # Fetch record
        response = client.com.atproto.repo.get_record(
            params={
                "repo": repo,
                "collection": collection,
                "rkey": rkey
            }
        )
        
        actual_cid = response.cid
        record = response.value
        
        # Verify CID
        if actual_cid != expected_cid:
            return (
                record,
                False,
                f"CID mismatch: expected {expected_cid}, got {actual_cid}"
            )
        
        return record, True, None
        
    except Exception as e:
        return None, False, f"Fetch failed: {str(e)}"


def build_provenance_entry(
    entry: dict,
    client: Client,
    verify_against_protocol: bool = True
) -> ProvenanceEntry:
    """
    Build complete provenance entry from ledger, optionally verifying against AT Protocol.
    """
    # Start with ledger data
    prov = ProvenanceEntry(
        skeet_uri=entry["skeet_uri"],
        skeet_cid=entry["skeet_cid"],
        provenance_root_uri=entry["provenance_root_uri"],
        provenance_root_cid=entry["provenance_root_cid"],
        provenance_ots_uri=entry["provenance_ots_uri"],
        provenance_ots_cid=entry["provenance_ots_cid"],
        signed_text=entry["signed_text"],
        gpg_fingerprint=entry["gpg_fingerprint"],
        sig_stamp_hash=entry["sig_stamp_hash"],
        sig_ots_proof_b64=entry["sig_ots_proof_b64"],
        binding_stamp_hash=entry["binding_stamp_hash"],
        binding_ots_proof_b64=entry["binding_ots_proof_b64"],
        binding_stamped_at=entry["binding_stamped_at"],
        created_at=entry["created_at"],
        post_text=entry["post_text"],
        verification_errors=[]
    )
    
    if not verify_against_protocol:
        return prov
    
    # Verify each record against AT Protocol
    print(f"  Verifying {prov.skeet_uri}...", file=sys.stderr)
    
    # Verify skeet
    record, verified, error = fetch_and_verify_record(
        client, prov.skeet_uri, prov.skeet_cid
    )
    prov.skeet_record = record
    prov.skeet_verified = verified
    if error:
        prov.verification_errors.append(f"Skeet: {error}")
    
    # Verify provenance root
    record, verified, error = fetch_and_verify_record(
        client, prov.provenance_root_uri, prov.provenance_root_cid
    )
    prov.provenance_root_record = record
    prov.provenance_root_verified = verified
    if error:
        prov.verification_errors.append(f"ProvenanceRoot: {error}")
    
    # Verify provenance OTS
    record, verified, error = fetch_and_verify_record(
        client, prov.provenance_ots_uri, prov.provenance_ots_cid
    )
    prov.provenance_ots_record = record
    prov.provenance_ots_verified = verified
    if error:
        prov.verification_errors.append(f"ProvenanceOTS: {error}")
    
    # Set fully_verified flag
    prov.fully_verified = (
        prov.skeet_verified and
        prov.provenance_root_verified and
        prov.provenance_ots_verified
    )
    
    return prov


def export_provenance(
    handle: str,
    app_password: str,
    ledger_path: Path,
    output_path: Path,
    verify_protocol: bool = True
) -> dict:
    """
    Export complete provenance chain with verification.
    
    Returns summary statistics.
    """
    print(f"[INFO] Loading ledger from {ledger_path}", file=sys.stderr)
    ledger_entries = load_ledger(ledger_path)
    
    print(f"[INFO] Filtering new-scheme entries", file=sys.stderr)
    filtered = [e for e in ledger_entries if is_new_scheme_entry(e)]
    
    print(f"[INFO] Found {len(filtered)} new-scheme entries", file=sys.stderr)
    
    if verify_protocol:
        print(f"[INFO] Logging in to Bluesky as {handle}", file=sys.stderr)
        client = Client()
        client.login(handle, app_password)
    else:
        client = None
        print("[INFO] Skipping protocol verification (ledger-only mode)", file=sys.stderr)
    
    # Build provenance entries
    entries = []
    stats = {
        "total_entries": len(filtered),
        "fully_verified": 0,
        "partially_verified": 0,
        "verification_failed": 0,
        "not_verified": 0 if verify_protocol else len(filtered)
    }
    
    for i, ledger_entry in enumerate(filtered, 1):
        print(f"[INFO] Processing entry {i}/{len(filtered)}", file=sys.stderr)
        try:
            prov = build_provenance_entry(
                ledger_entry,
                client,
                verify_against_protocol=verify_protocol
            )
            entries.append(prov)
            
            if verify_protocol:
                if prov.fully_verified:
                    stats["fully_verified"] += 1
                elif any([prov.skeet_verified, prov.provenance_root_verified, prov.provenance_ots_verified]):
                    stats["partially_verified"] += 1
                else:
                    stats["verification_failed"] += 1
                    
        except Exception as e:
            print(f"[WARN] Failed to process entry: {e}", file=sys.stderr)
    
    # Build export document
    export_doc = {
        "schema": "com.SolProvenance.export.hybrid.v1",
        "exported_at": now_iso_utc(),
        "export_metadata": {
            "ledger_source": str(ledger_path),
            "handle": handle if verify_protocol else None,
            "verification_enabled": verify_protocol,
        },
        "statistics": stats,
        "entries": [asdict(e) for e in entries]
    }
    
    # Write export
    print(f"[INFO] Writing export to {output_path}", file=sys.stderr)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(export_doc, f, indent=2, ensure_ascii=False, default=str)
    
    return stats


def main():
    parser = argparse.ArgumentParser(
        description="Export SolProvenance chain with trust-but-verify architecture"
    )
    parser.add_argument(
        "--handle",
        help="Bluesky handle (required for verification)"
    )
    parser.add_argument(
        "--app-password",
        help="Bluesky app password (required for verification)"
    )
    parser.add_argument(
        "--ledger",
        type=Path,
        default=Path("ledger.jsonl"),
        help="Path to ledger.jsonl (default: ledger.jsonl)"
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("provenance_export.json"),
        help="Output file path (default: provenance_export.json)"
    )
    parser.add_argument(
        "--no-verify",
        action="store_true",
        help="Skip AT Protocol verification (ledger-only export)"
    )
    
    args = parser.parse_args()
    
    # Validation
    verify = not args.no_verify
    if verify and (not args.handle or not args.app_password):
        print(
            "Error: --handle and --app-password required for verification.\n"
            "Use --no-verify for ledger-only export.",
            file=sys.stderr
        )
        sys.exit(1)
    
    try:
        stats = export_provenance(
            args.handle or "",
            args.app_password or "",
            args.ledger,
            args.output,
            verify_protocol=verify
        )
        
        print("\n=== Export Complete ===", file=sys.stderr)
        print(f"Total entries: {stats['total_entries']}", file=sys.stderr)
        if verify:
            print(f"Fully verified: {stats['fully_verified']}", file=sys.stderr)
            print(f"Partially verified: {stats['partially_verified']}", file=sys.stderr)
            print(f"Verification failed: {stats['verification_failed']}", file=sys.stderr)
        else:
            print(f"Not verified (ledger-only): {stats['not_verified']}", file=sys.stderr)
        print(f"Output: {args.output}", file=sys.stderr)
        
        # Exit with error if any verification failures
        if verify and stats['verification_failed'] > 0:
            print("\n[ERROR] Some entries failed verification!", file=sys.stderr)
            sys.exit(1)
        
    except KeyboardInterrupt:
        print("\nAborted by user.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
