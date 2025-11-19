"""Immutable provenance pipeline for Bluesky using dual OpenTimestamps layers."""
from __future__ import annotations

import base64
import hashlib
import json
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Tuple

from atproto import Client

# === Lexicon schemas (reference) ===
PROVENANCE_ROOT_LEXICON = {
    "lexicon": 1,
    "id": "com.SolProvenance.provenanceRoot",
    "type": "record",
    "record": {
        "key": "tid",
        "description": "Immutable per-post provenance record asserting authorship of a signed text.",
        "properties": {
            "signedText": {"type": "string"},
            "gpgFingerprint": {"type": "string"},
            "sigStampHash": {"type": "string"},
            "sigOTSProofB64": {"type": "string"},
        },
        "required": ["signedText", "gpgFingerprint", "sigStampHash", "sigOTSProofB64"],
        "additionalProperties": False,
    },
}

PROVENANCE_KEY_LEXICON = {
    "lexicon": 1,
    "id": "com.SolProvenance.provenanceKey",
    "type": "record",
    "record": {
        "key": "literal",
        "description": "Persistent account-level record containing the GPG public key and fingerprint used for provenance.",
        "properties": {
            "gpgFingerprint": {"type": "string"},
            "gpgPublicKeyArmored": {"type": "string"},
        },
        "required": ["gpgFingerprint", "gpgPublicKeyArmored"],
        "additionalProperties": False,
    },
}

PROVENANCE_OTS_LEXICON = {
    "lexicon": 1,
    "id": "com.SolProvenance.provenanceOTS",
    "type": "record",
    "record": {
        "key": "tid",
        "description": "Temporal proof for a provenance record and its bound skeet via OpenTimestamps.",
        "properties": {
            "provenanceRootUri": {"type": "string"},
            "provenanceRootCid": {"type": "string"},
            "skeetUri": {"type": "string"},
            "skeetCid": {"type": "string"},
            "bindingStampHash": {"type": "string"},
            "bindingOTSProofB64": {"type": "string"},
            "stampedAt": {"type": "string", "format": "datetime"},
        },
        "required": [
            "provenanceRootUri",
            "provenanceRootCid",
            "skeetUri",
            "skeetCid",
            "bindingStampHash",
            "bindingOTSProofB64",
        ],
        "additionalProperties": False,
    },
}

# === Configuration placeholders ===
BLUESKY_HANDLE = "BLUESKY_HANDLE"
BLUESKY_APP_PASSWORD = "BLUESKY_APP_PASSWORD"
GPG_KEY_ID = "GPG_KEY_ID"
LEDGER_PATH = Path("ledger.jsonl")

PROVENANCE_ROOT_COLLECTION = "com.SolProvenance.provenanceRoot"
PROVENANCE_KEY_COLLECTION = "com.SolProvenance.provenanceKey"
PROVENANCE_OTS_COLLECTION = "com.SolProvenance.provenanceOTS"
SKEET_COLLECTION = "app.bsky.feed.post"


# === Helper utilities ===
def read_multiline(prompt="Enter text (finish with CTRL+D):"):
    print(prompt)
    lines = []
    try:
        while True:
            line = input()
            lines.append(line)
    except EOFError:
        pass
    return "\n".join(lines)

def now_iso_utc() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_gpg_fingerprint(raw: str) -> str:
    for line in raw.splitlines():
        if line.startswith("fpr:"):
            fields = line.split(":")
            if len(fields) > 9 and fields[9]:
                return fields[9]
    raise RuntimeError("Unable to locate GPG fingerprint in gpg output")


def _export_gpg_public_key() -> str:
    cmd = ["gpg", "--armor", "--export"]
    if GPG_KEY_ID:
        cmd.append(GPG_KEY_ID)
    proc = subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return proc.stdout.decode("utf-8")


def ots_stamp_hash(hash_hex: str) -> str:
    """Stamp a hex digest with OpenTimestamps and return the proof as base64."""
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


# === Required pipeline functions ===
def login_client() -> Client:
    client = Client()
    client.login(BLUESKY_HANDLE, BLUESKY_APP_PASSWORD)
    return client


def sign_post_text(post_text: str) -> Tuple[str, str]:
    sign_cmd = ["gpg", "--armor", "--clearsign"]
    if GPG_KEY_ID:
        sign_cmd.extend(["--local-user", GPG_KEY_ID])

    sign_proc = subprocess.run(
        sign_cmd,
        input=post_text.encode("utf-8"),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )
    signed_text = sign_proc.stdout.decode("utf-8")

    fpr_cmd = ["gpg", "--with-colons", "--fingerprint"]
    if GPG_KEY_ID:
        fpr_cmd.append(GPG_KEY_ID)
    fpr_proc = subprocess.run(fpr_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
    gpg_fpr = _parse_gpg_fingerprint(fpr_proc.stdout.decode("utf-8"))
    return signed_text, gpg_fpr


def ensure_provenance_key_record(client: Client, gpg_fpr: str, gpg_pubkey: str) -> None:
    params = {
        "repo": client.me.did,
        "collection": PROVENANCE_KEY_COLLECTION,
        "limit": 10,
    }
    res = client.com.atproto.repo.list_records(params=params)
    for record in getattr(res, "records", []):
        record_value = getattr(record, "value", None)
        if record_value is None:
            continue
        if isinstance(record_value, dict):
            current_fpr = record_value.get("gpgFingerprint")
        else:
            current_fpr = getattr(record_value, "gpgFingerprint", None)
        if current_fpr == gpg_fpr:
            return

    record = {
        "gpgFingerprint": gpg_fpr,
        "gpgPublicKeyArmored": gpg_pubkey,
    }
    client.com.atproto.repo.create_record(
        data={
            "repo": client.me.did,
            "collection": PROVENANCE_KEY_COLLECTION,
            "record": record,
        }
    )


def create_provenance_root_record(
    client: Client,
    signed_text: str,
    gpg_fpr: str,
    sig_stamp_hash: str,
    sig_ots_proof_b64: str,
) -> Tuple[str, str]:
    record = {
        "signedText": signed_text,
        "gpgFingerprint": gpg_fpr,
        "sigStampHash": sig_stamp_hash,
        "sigOTSProofB64": sig_ots_proof_b64,
    }
    res = client.com.atproto.repo.create_record(
        data={
            "repo": client.me.did,
            "collection": PROVENANCE_ROOT_COLLECTION,
            "record": record,
        }
    )
    return res["uri"], res["cid"]


def post_skeet(client: Client, post_text: str) -> Tuple[str, str]:
    record = {
        "text": post_text,
        "createdAt": now_iso_utc(),
    }
    res = client.com.atproto.repo.create_record(
        data={
            "repo": client.me.did,
            "collection": SKEET_COLLECTION,
            "record": record,
        }
    )
    return res["uri"], res["cid"]


def create_provenance_ots_record(
    client: Client,
    prov_uri: str,
    prov_cid: str,
    skeet_uri: str,
    skeet_cid: str,
    binding_stamp_hash: str,
    binding_ots_proof_b64: str,
    stamped_at: str,
) -> Tuple[str, str]:
    record = {
        "provenanceRootUri": prov_uri,
        "provenanceRootCid": prov_cid,
        "skeetUri": skeet_uri,
        "skeetCid": skeet_cid,
        "bindingStampHash": binding_stamp_hash,
        "bindingOTSProofB64": binding_ots_proof_b64,
        "stampedAt": stamped_at,
    }
    res = client.com.atproto.repo.create_record(
        data={
            "repo": client.me.did,
            "collection": PROVENANCE_OTS_COLLECTION,
            "record": record,
        }
    )
    return res["uri"], res["cid"]


def append_ledger_entry(entry: dict, ledger_path: str = "ledger.jsonl") -> None:
    path = Path(ledger_path)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


# === Main orchestration ===
def main() -> None:
    post_text = read_multiline().strip()
    if not post_text:
        print("No post text provided; aborting.")
        return

    signed_text, gpg_fpr = sign_post_text(post_text)
    sig_stamp_input = f"{signed_text}|{gpg_fpr}"
    sig_stamp_hash = hashlib.sha256(sig_stamp_input.encode("utf-8")).hexdigest()
    sig_ots_proof_b64 = ots_stamp_hash(sig_stamp_hash)

    gpg_pubkey = _export_gpg_public_key()
    client = login_client()
    ensure_provenance_key_record(client, gpg_fpr, gpg_pubkey)

    prov_uri, prov_cid = create_provenance_root_record(
        client, signed_text, gpg_fpr, sig_stamp_hash, sig_ots_proof_b64
    )

    skeet_uri, skeet_cid = post_skeet(client, post_text)
    # binding_input = signedText|gpgFingerprint|provUri|provCid|skeetUri|skeetCid
    binding_input = "|".join([signed_text, gpg_fpr, prov_uri, prov_cid, skeet_uri, skeet_cid])
    binding_stamp_hash = hashlib.sha256(binding_input.encode("utf-8")).hexdigest()
    binding_ots_proof_b64 = ots_stamp_hash(binding_stamp_hash)
    stamped_at = now_iso_utc()

    ots_uri, ots_cid = create_provenance_ots_record(
        client,
        prov_uri,
        prov_cid,
        skeet_uri,
        skeet_cid,
        binding_stamp_hash,
        binding_ots_proof_b64,
        stamped_at,
    )

    ledger_entry = {
        "created_at": now_iso_utc(),
        "post_text": post_text,
        "signed_text": signed_text,
        "gpg_fingerprint": gpg_fpr,
        "provenance_root_uri": prov_uri,
        "provenance_root_cid": prov_cid,
        "skeet_uri": skeet_uri,
        "skeet_cid": skeet_cid,
        "sig_stamp_hash": sig_stamp_hash,
        "sig_ots_proof_b64": sig_ots_proof_b64,
        "binding_stamp_hash": binding_stamp_hash,
        "binding_ots_proof_b64": binding_ots_proof_b64,
        "provenance_ots_uri": ots_uri,
        "provenance_ots_cid": ots_cid,
        "binding_stamped_at": stamped_at,
    }
    append_ledger_entry(ledger_entry, str(LEDGER_PATH))

    print("Provenance workflow complete. Summary:")
    print(json.dumps(ledger_entry, indent=2))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nAborted by user.")
