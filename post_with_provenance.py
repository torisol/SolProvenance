"""Immutable provenance pipeline for Bluesky using dual OpenTimestamps layers."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Tuple
from urllib.parse import urlparse

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
            "createdAt": {"type": "string", "format": "datetime"},
            "hardwareBacked": {"type": "boolean"},
            "hardwareType": {"type": "string", "nullable": True},
            "attestationPresent": {"type": "boolean"},
            "attestationRecordUri": {"type": "string", "nullable": True},
            "keyBindingHash": {"type": "string"},
            "keyOTSProofB64": {"type": "string"},
        },
        "required": [
            "gpgFingerprint",
            "gpgPublicKeyArmored",
            "createdAt",
            "hardwareBacked",
            "attestationPresent",
            "keyBindingHash",
            "keyOTSProofB64",
        ],
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

PROVENANCE_ATT_LEXICON = {
    "lexicon": 1,
    "id": "com.SolProvenance.provenanceATT",
    "type": "record",
    "record": {
        "key": "tid",
        "description": "Attestation certificates for a hardware-backed key.",
        "properties": {
            "keyRecordUri": {"type": "string"},
            "attDeviceCert": {"type": "string"},
            "attSigCert": {"type": "string", "nullable": True},
            "attDecCert": {"type": "string", "nullable": True},
            "attAutCert": {"type": "string", "nullable": True},
            "createdAt": {"type": "string", "format": "datetime"},
            "attBindingHash": {"type": "string"},
            "attOTSProofB64": {"type": "string"},
        },
        "required": [
            "keyRecordUri",
            "attDeviceCert",
            "createdAt",
            "attBindingHash",
            "attOTSProofB64",
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
PROVENANCE_ATT_COLLECTION = "com.SolProvenance.provenanceATT"
SKEET_COLLECTION = "app.bsky.feed.post"

URL_RE = re.compile(r"(https?://[^\s]+)")


# === Helper utilities ===
def read_multiline(prompt: str = "Enter text (finish with CTRL+D):") -> str:
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



def _facet_to_dict(facet):
    if hasattr(facet, "to_dict"):
        return facet.to_dict()
    if hasattr(facet, "as_dict"):
        return facet.as_dict()  # type: ignore[attr-defined]
    if hasattr(facet, "asdict"):
        return facet.asdict()  # type: ignore[attr-defined]
    if isinstance(facet, dict):
        return facet
    try:
        return facet.__dict__
    except Exception:
        return {"data": str(facet)}


def build_rich_text(post_text: str) -> Tuple[str, list]:
    """Return text and link facets. Manual byte offsets to avoid SDK signature drift."""
    facets: list = []
    for match in URL_RE.finditer(post_text):
        url = match.group(0)
        byte_start = len(post_text[: match.start()].encode("utf-8"))
        byte_end = len(post_text[: match.end()].encode("utf-8"))
        facets.append(
            {
                "index": {"byteStart": byte_start, "byteEnd": byte_end},
                "features": [
                    {
                        "$type": "app.bsky.richtext.facet#link",
                        "uri": url,
                    }
                ],
            }
        )
    return post_text, facets


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




def normalize_post_ref(uri: str, client: Client) -> Tuple[str, str, str, str]:
    if uri.startswith("at://"):
        without_scheme = uri[len("at://"):]
        parts = without_scheme.split("/")
        if len(parts) != 3:
            raise ValueError(f"Unexpected at:// format: {uri}")
        repo, collection, rkey = parts
        return uri, repo, collection, rkey

    parsed = urlparse(uri)
    if parsed.scheme in {"http", "https"} and parsed.netloc.endswith("bsky.app"):
        parts = parsed.path.strip("/").split("/")
        if len(parts) >= 4 and parts[0] == "profile" and parts[2] == "post":
            repo = parts[1]
            rkey = parts[3]
            collection = SKEET_COLLECTION
            if not repo.startswith("did:"):
                resolved = client.com.atproto.identity.resolve_handle(params={"handle": repo})
                repo = resolved.get("did") if isinstance(resolved, dict) else resolved.did
            at_uri = f"at://{repo}/{collection}/{rkey}"
            return at_uri, repo, collection, rkey

    raise ValueError(f"Unsupported skeet link format: {uri}")


def _extract_uri_cid(record) -> Tuple[str | None, str | None]:
    uri = None
    cid = None
    if isinstance(record, dict):
        uri = record.get("uri")
        cid = record.get("cid")
        value = record.get("value")
        if uri is None and isinstance(value, dict):
            uri = value.get("uri")
        if cid is None and isinstance(value, dict):
            cid = value.get("cid")
    else:
        uri = getattr(record, "uri", None)
        cid = getattr(record, "cid", None)
        value = getattr(record, "value", None)
        if uri is None and isinstance(value, dict):
            uri = value.get("uri")
        elif uri is None:
            uri = getattr(value, "uri", None)
        if cid is None and isinstance(value, dict):
            cid = value.get("cid")
        elif cid is None:
            cid = getattr(value, "cid", None)
    return uri, cid


def build_reply_block(client: Client, parent_uri: str, root_uri: str | None) -> tuple[dict, str, str]:
    parent_at, parent_repo, parent_collection, parent_rkey = normalize_post_ref(parent_uri, client)
    if root_uri:
        root_at, root_repo, root_collection, root_rkey = normalize_post_ref(root_uri, client)
    else:
        root_at, root_repo, root_collection, root_rkey = parent_at, parent_repo, parent_collection, parent_rkey

    parent_record = client.com.atproto.repo.get_record(
        params={"repo": parent_repo, "collection": parent_collection, "rkey": parent_rkey}
    )
    root_record = client.com.atproto.repo.get_record(
        params={"repo": root_repo, "collection": root_collection, "rkey": root_rkey}
    )

    parent_uri_val, parent_cid = _extract_uri_cid(parent_record)
    root_uri_val, root_cid = _extract_uri_cid(root_record)

    parent_ref = {"uri": parent_uri_val or parent_at, "cid": parent_cid}
    root_ref = {"uri": root_uri_val or root_at, "cid": root_cid}

    return {"parent": parent_ref, "root": root_ref}, parent_at, root_at

def post_skeet(client: Client, post_text: str, facets: list | None = None, reply: dict | None = None) -> Tuple[str, str]:
    record = {
        "text": post_text,
        "createdAt": now_iso_utc(),
    }
    if facets:
        record["facets"] = facets
    if reply:
        record["reply"] = reply

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
    parser = argparse.ArgumentParser(description="Post a skeet with SolProvenance provenance + OTS")
    parser.add_argument("--reply-parent-uri", help="at:// or https://bsky.app/... link of the post you are replying to")
    parser.add_argument(
        "--reply-root-uri",
        help="at:// or https://bsky.app/... link of the thread root (defaults to parent when replying)",
    )
    args = parser.parse_args()

    reply_parent_uri = args.reply_parent_uri
    reply_root_uri = args.reply_root_uri or reply_parent_uri

    post_text_raw = read_multiline().strip()
    if not post_text_raw:
        print("No post text provided; aborting.")
        return

    rich_text, facets = build_rich_text(post_text_raw)
    post_text = rich_text

    signed_text, gpg_fpr = sign_post_text(post_text)
    sig_stamp_input = f"{signed_text}|{gpg_fpr}"
    sig_stamp_hash = hashlib.sha256(sig_stamp_input.encode("utf-8")).hexdigest()
    sig_ots_proof_b64 = ots_stamp_hash(sig_stamp_hash)

    client = login_client()

    prov_uri, prov_cid = create_provenance_root_record(
        client, signed_text, gpg_fpr, sig_stamp_hash, sig_ots_proof_b64
    )

    reply_block = None
    reply_parent_norm = None
    reply_root_norm = None
    if reply_parent_uri:
        reply_block, reply_parent_norm, reply_root_norm = build_reply_block(client, reply_parent_uri, reply_root_uri)

    skeet_uri, skeet_cid = post_skeet(client, post_text, facets=facets, reply=reply_block)
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
    if reply_parent_norm:
        ledger_entry["parent_skeet_uri"] = reply_parent_norm
    if reply_root_norm:
        ledger_entry["root_skeet_uri"] = reply_root_norm

    append_ledger_entry(ledger_entry, str(LEDGER_PATH))

    print("Provenance workflow complete. Summary:")
    print(json.dumps(ledger_entry, indent=2))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nAborted by user.")
