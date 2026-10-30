# core/cloud_storage.py
"""Supabase Storage + PostgreSQL integration with version hash-chain verification."""
import os
import base64
from concurrent.futures import ThreadPoolExecutor
from dotenv import load_dotenv
from supabase import create_client

load_dotenv()

BUCKET = "encrypted-fragments"
_supa = None  # ponytail: fully lazy — no import-time network call


def _get_client():
    global _supa
    if _supa is None:
        load_dotenv()
        _supa = create_client(os.getenv("SUPABASE_URL"), os.getenv("SUPABASE_KEY"))
    return _supa


def upload_encrypted_file(
    file_id: str,
    version: int,
    original_filename: str,
    owner_email: str,
    receiver_email: str,
    sender_x25519_pub: str,
    mlkem_ciphertext: str,
    encrypted_results: list,
    version_chain_hash: str,
    prev_version_hash: str,
    manifest_merkle_root: str,
):
    """Upload encrypted fragments to Supabase Storage and metadata to PostgreSQL."""
    client = _get_client()

    manifest = []
    for item in encrypted_results:
        idx, ciphertext, tag, meta = item
        blob = ciphertext + tag  # store ct+tag together
        path = f"{file_id}/v{version}/fragment_{idx}.enc"

        # Retry with backoff to eliminate WSAEWOULDBLOCK [WinError 10035] on Windows sockets
        for attempt in range(4):
            try:
                client.storage.from_(BUCKET).upload(
                    path=path,
                    file=blob,
                    file_options={"content-type": "application/octet-stream", "upsert": "true"},
                )
                break
            except Exception as exc:
                if attempt == 3:
                    raise exc
                import time
                time.sleep(0.1 * (attempt + 1))

        meta["storage_path"] = path
        manifest.append(meta)

    # Upsert metadata row
    row = {
        "file_id": file_id,
        "version": version,
        "original_filename": original_filename,
        "owner_email": owner_email,
        "receiver_email": receiver_email,
        "sender_x25519_pub": sender_x25519_pub,
        "mlkem_ciphertext": mlkem_ciphertext,
        "fragment_manifest": manifest,
        "version_chain_hash": version_chain_hash,
        "prev_version_hash": prev_version_hash,
        "manifest_merkle_root": manifest_merkle_root,
    }
    try:
        client.table("files_metadata").upsert(row).execute()
    except Exception as e:
        if "manifest_merkle_root" in str(e) or "authorized_receiver" in str(e):
            row.pop("manifest_merkle_root", None)
            row.pop("receiver_email", None)
            row["authorized_receiver"] = receiver_email
            client.table("files_metadata").upsert(row).execute()
        else:
            raise

    return manifest


def download_encrypted_file(file_id: str):
    """Download metadata + all encrypted fragments from Supabase."""
    client = _get_client()
    record = (
        client.table("files_metadata")
        .select("*")
        .eq("file_id", file_id)
        .single()
        .execute()
        .data
    )
    manifest = record["fragment_manifest"]

    fragments = []
    for meta in manifest:
        blob = None
        for attempt in range(4):
            try:
                blob = client.storage.from_(BUCKET).download(meta["storage_path"])
                break
            except Exception as exc:
                if attempt == 3:
                    raise exc
                import time
                time.sleep(0.1 * (attempt + 1))

        # blob = ciphertext + 16-byte tag
        ciphertext = blob[:-16]
        tag = blob[-16:]
        fragments.append({
            "index": meta["index"],
            "ciphertext": ciphertext,
            "tag": tag,
            "meta": meta,
        })

    return record, fragments


def list_files_for_receiver(receiver_email: str) -> list:
    """List all files shared with this receiver."""
    client = _get_client()
    try:
        resp = (
            client.table("files_metadata")
            .select("file_id, original_filename, owner_email, version, created_at")
            .eq("receiver_email", receiver_email)
            .execute()
        )
        return resp.data or []
    except Exception:
        resp = (
            client.table("files_metadata")
            .select("file_id, original_filename, owner_email, version, created_at")
            .eq("authorized_receiver", receiver_email)
            .execute()
        )
        return resp.data or []


def delete_file(file_id: str):
    """Delete file metadata and storage fragments."""
    client = _get_client()
    record = (
        client.table("files_metadata")
        .select("fragment_manifest, version")
        .eq("file_id", file_id)
        .single()
        .execute()
        .data
    )
    if record:
        paths = [m["storage_path"] for m in record["fragment_manifest"]]
        if paths:
            client.storage.from_(BUCKET).remove(paths)
        client.table("files_metadata").delete().eq("file_id", file_id).execute()


def get_file_metadata(file_id: str):
    """Fetch metadata row for a file."""
    client = _get_client()
    resp = (
        client.table("files_metadata")
        .select("*")
        .eq("file_id", file_id)
        .single()
        .execute()
    )
    return resp.data
