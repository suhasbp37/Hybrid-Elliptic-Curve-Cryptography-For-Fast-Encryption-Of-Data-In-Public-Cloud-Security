# cloud_storage.py
import os
from concurrent.futures import ThreadPoolExecutor
from dotenv import load_dotenv
from supabase import create_client

load_dotenv()
supa = create_client(os.getenv("SUPABASE_URL"), os.getenv("SUPABASE_KEY"))
BUCKET_NAME = "encrypted-fragments"

def upload_to_public_cloud(
    file_id: str,
    original_filename: str,
    sender_x25519_pub: str,
    mlkem_ciphertext: str,
    encrypted_results: list
):
    """Uploads encrypted fragments to Supabase Bucket and metadata to Supabase DB."""
    def _upload_single_fragment(item):
        idx, ciphertext_bytes, meta = item
        storage_path = f"{file_id}/fragment_{idx}.enc"
        supa.storage.from_(BUCKET_NAME).upload(
            path=storage_path,
            file=ciphertext_bytes,
            file_options={"content-type": "application/octet-stream", "upsert": "true"}
        )
        meta["storage_path"] = storage_path
        return meta

    # Upload fragments concurrently over network
    with ThreadPoolExecutor(max_workers=8) as pool:
        manifest = list(pool.map(_upload_single_fragment, encrypted_results))

    # Store Public Metadata in PostgreSQL (Private keys are NEVER stored here)
    supa.table("files_metadata").upsert({
        "file_id": file_id,
        "original_filename": original_filename,
        "sender_x25519_pub": sender_x25519_pub,
        "mlkem_ciphertext": mlkem_ciphertext,
        "fragment_manifest": manifest
    }).execute()

def download_from_public_cloud(file_id: str):
    """Downloads metadata from Supabase DB and encrypted fragments from Supabase Bucket."""
    record = supa.table("files_metadata").select("*").eq("file_id", file_id).single().execute().data
    manifest = record["fragment_manifest"]

    def _download_single_fragment(meta):
        ct_bytes = supa.storage.from_(BUCKET_NAME).download(meta["storage_path"])
        return {
            "index": meta["index"],
            "ciphertext": ct_bytes,
            "meta": meta
        }

    with ThreadPoolExecutor(max_workers=8) as pool:
        downloaded_fragments = list(pool.map(_download_single_fragment, manifest))

    return record, downloaded_fragments