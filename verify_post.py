#!/usr/bin/env python3
"""Full cryptographic verification for SolProvenance records.

Usage:
    # Verify from export
    python verify_post.py provenance_export.json
    
    # Verify specific entry by index
    python verify_post.py provenance_export.json --entry 0
    
    # Verify from ledger entry directly
    python verify_post.py ledger.jsonl --ledger --entry 2
"""

import json
import base64
import subprocess
import tempfile
import hashlib
import sys
import argparse
from pathlib import Path


def verify_gpg_clearsign(signed_text: str) -> tuple[bool, str]:
    """Verify GPG clearsigned text. Returns (valid, error_message)."""
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "sig.asc"
        path.write_text(signed_text, encoding="utf-8")

        proc = subprocess.run(
            ["gpg", "--verify", str(path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        
        if proc.returncode == 0:
            return True, ""
        else:
            return False, proc.stderr.decode()


def verify_ots(hash_hex: str, proof_b64: str) -> tuple[bool, str]:
    """Verify OpenTimestamps proof. Returns (valid, error_message)."""
    with tempfile.TemporaryDirectory() as td:
        base = Path(td) / "hash.txt"
        proof_path = Path(td) / "hash.txt.ots"

        base.write_text(hash_hex, encoding="utf-8")
        try:
            proof_bytes = base64.b64decode(proof_b64)
            proof_path.write_bytes(proof_bytes)
        except Exception as e:
            return False, f"Invalid base64: {e}"

        proc = subprocess.run(
            ["ots", "verify", str(proof_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        
        if proc.returncode == 0:
            return True, ""
        else:
            return False, proc.stderr.decode()


def verify_entry(entry: dict, verbose: bool = True) -> dict:
    """
    Verify a single provenance entry.
    
    Returns dict with verification results.
    """
    results = {
        "gpg_valid": False,
        "sig_hash_matches": False,
        "sig_ots_valid": False,
        "binding_hash_matches": False,
        "binding_ots_valid": False,
        "errors": []
    }
    
    # Extract fields
    signed_text = entry.get("signed_text", "")
    gpg_fpr = entry.get("gpg_fingerprint", "")
    sig_stamp_hash = entry.get("sig_stamp_hash", "")
    sig_ots = entry.get("sig_ots_proof_b64", "")
    
    prov_uri = entry.get("provenance_root_uri", "")
    prov_cid = entry.get("provenance_root_cid", "")
    skeet_uri = entry.get("skeet_uri", "")
    skeet_cid = entry.get("skeet_cid", "")
    binding_stamp_hash = entry.get("binding_stamp_hash", "")
    binding_ots = entry.get("binding_ots_proof_b64", "")
    
    if verbose:
        print("\n=== Verifying Provenance Entry ===")
        print(f"Post: {entry.get('post_text', '')[:50]}...")
    
    # Signature Layer
    if verbose:
        print("\n[1] GPG Signature Verification...")
    
    gpg_valid, gpg_error = verify_gpg_clearsign(signed_text)
    results["gpg_valid"] = gpg_valid
    if not gpg_valid:
        results["errors"].append(f"GPG verification failed: {gpg_error}")
    if verbose:
        print(f"  → GPG signature: {'✓ VALID' if gpg_valid else '✗ INVALID'}")
    
    if verbose:
        print("\n[2] Signature Hash Verification...")
    
    calc_sig_hash = hashlib.sha256(
        f"{signed_text}|{gpg_fpr}".encode()
    ).hexdigest()
    sig_hash_matches = (calc_sig_hash == sig_stamp_hash)
    results["sig_hash_matches"] = sig_hash_matches
    if not sig_hash_matches:
        results["errors"].append(
            f"Signature hash mismatch: expected {sig_stamp_hash}, got {calc_sig_hash}"
        )
    if verbose:
        print(f"  → Hash matches: {'✓ YES' if sig_hash_matches else '✗ NO'}")
    
    if verbose:
        print("\n[3] Signature OTS Proof Verification...")
    
    sig_ots_valid, sig_ots_error = verify_ots(sig_stamp_hash, sig_ots)
    results["sig_ots_valid"] = sig_ots_valid
    if not sig_ots_valid:
        results["errors"].append(f"Signature OTS verification failed: {sig_ots_error}")
    if verbose:
        print(f"  → OTS proof: {'✓ VALID' if sig_ots_valid else '✗ INVALID'}")
    
    # Binding Layer
    if verbose:
        print("\n[4] Binding Hash Verification...")
    
    calc_binding = hashlib.sha256(
        f"{signed_text}|{gpg_fpr}|{prov_uri}|{prov_cid}|{skeet_uri}|{skeet_cid}".encode()
    ).hexdigest()
    binding_hash_matches = (calc_binding == binding_stamp_hash)
    results["binding_hash_matches"] = binding_hash_matches
    if not binding_hash_matches:
        results["errors"].append(
            f"Binding hash mismatch: expected {binding_stamp_hash}, got {calc_binding}"
        )
    if verbose:
        print(f"  → Binding hash matches: {'✓ YES' if binding_hash_matches else '✗ NO'}")
    
    if verbose:
        print("\n[5] Binding OTS Proof Verification...")
    
    binding_ots_valid, binding_ots_error = verify_ots(binding_stamp_hash, binding_ots)
    results["binding_ots_valid"] = binding_ots_valid
    if not binding_ots_valid:
        results["errors"].append(f"Binding OTS verification failed: {binding_ots_error}")
    if verbose:
        print(f"  → OTS proof: {'✓ VALID' if binding_ots_valid else '✗ INVALID'}")
    
    # Summary
    results["fully_verified"] = all([
        results["gpg_valid"],
        results["sig_hash_matches"],
        results["sig_ots_valid"],
        results["binding_hash_matches"],
        results["binding_ots_valid"]
    ])
    
    if verbose:
        print("\n=== Verification Result ===")
        if results["fully_verified"]:
            print("✓ ALL CHECKS PASSED")
        else:
            print("✗ VERIFICATION FAILED")
            for error in results["errors"]:
                print(f"  - {error}")
    
    return results


def main():
    parser = argparse.ArgumentParser(
        description="Verify SolProvenance cryptographic proofs"
    )
    parser.add_argument(
        "file",
        type=Path,
        help="Export JSON or ledger JSONL file"
    )
    parser.add_argument(
        "--ledger",
        action="store_true",
        help="Treat input as ledger.jsonl format"
    )
    parser.add_argument(
        "--entry",
        type=int,
        help="Verify specific entry by index (default: all entries)"
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress verbose output, show only summary"
    )
    
    args = parser.parse_args()
    
    if not args.file.exists():
        print(f"Error: File not found: {args.file}", file=sys.stderr)
        sys.exit(1)
    
    # Load entries
    if args.ledger:
        # Load from ledger JSONL
        entries = []
        with args.file.open("r") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        entry = json.loads(line)
                        # Filter to new-scheme entries
                        if "provenance_root_uri" in entry:
                            entries.append(entry)
                    except json.JSONDecodeError:
                        continue
    else:
        # Load from export JSON
        data = json.loads(args.file.read_text())
        if "entries" in data:
            # Hybrid export format
            entries = data["entries"]
        elif isinstance(data, list):
            # Direct list of entries
            entries = data
        else:
            # Single entry
            entries = [data]
    
    if not entries:
        print("Error: No valid entries found", file=sys.stderr)
        sys.exit(1)
    
    # Select entries to verify
    if args.entry is not None:
        if args.entry < 0 or args.entry >= len(entries):
            print(f"Error: Entry index {args.entry} out of range (0-{len(entries)-1})", file=sys.stderr)
            sys.exit(1)
        entries_to_verify = [entries[args.entry]]
    else:
        entries_to_verify = entries
    
    # Verify
    all_results = []
    for i, entry in enumerate(entries_to_verify):
        if not args.quiet and len(entries_to_verify) > 1:
            print(f"\n{'='*60}")
            print(f"Entry {i+1}/{len(entries_to_verify)}")
            print(f"{'='*60}")
        
        result = verify_entry(entry, verbose=not args.quiet)
        all_results.append(result)
    
    # Final summary
    total = len(all_results)
    passed = sum(1 for r in all_results if r["fully_verified"])
    
    print(f"\n{'='*60}")
    print(f"FINAL SUMMARY: {passed}/{total} entries fully verified")
    print(f"{'='*60}")
    
    if passed < total:
        print(f"\n✗ {total - passed} entries FAILED verification")
        sys.exit(1)
    else:
        print("\n✓ All entries PASSED verification")
        sys.exit(0)


if __name__ == "__main__":
    main()
