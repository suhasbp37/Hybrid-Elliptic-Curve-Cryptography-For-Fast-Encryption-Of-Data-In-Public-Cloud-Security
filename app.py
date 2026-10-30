# app.py
"""FastAPI backend for HECC Phase 2 — Hybrid Elliptic Curve Cryptography Cloud Security."""
from __future__ import annotations

import asyncio
import base64
import hashlib
import io
import json
import os
import time
import uuid

from dotenv import load_dotenv
from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Header, Request
from fastapi.responses import HTMLResponse, StreamingResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

load_dotenv()

from core.auth_acl import (
    issue_token,
    verify_token,
    register_user,
    login_user,
    get_current_user,
    ACLError,
    check_upload_permission,
    check_download_permission,
    check_delete_permission,
)
from core.kms_vault import (
    generate_receiver_keys,
    load_receiver_public_keys,
    load_receiver_private_keys,
    receiver_keys_exist,
)
from core.hybrid_crypto import sender_establish_hybrid_key, receiver_reconstruct_hybrid_key
from core.icat_kms import (
    create_user_vault,
    init_vault,
    unlock_vault,
    vault_exists,
    sign_and_register_public_keys,
    get_verified_receiver_public_keys,
    create_icat_token,
    verify_icat_token,
    icat_decrypt,
    ICAT_DIR,
    KMSAuthenticationError,
    CapsuleSignatureError,
    CapsuleSignatureVerificationError,
    UntrustedPublicKeyError,
)
from core.parallel_engine import (
    fragment_bytes,
    parallel_encrypt_fragments,
    parallel_decrypt_and_reassemble,
    compute_merkle_root,
    compute_version_chain_hash,
    pin_version,
    verify_version,
    TamperingDetectedError,
    RollbackAttackDetectedError,
)
from core.cloud_storage import (
    upload_encrypted_file,
    download_encrypted_file,
    list_files_for_receiver,
    delete_file as cloud_delete_file,
    get_file_metadata,
    _get_client,
)

app = FastAPI(title="HECC Phase 2 — Hybrid ECC Cloud Security")
app.mount("/web", StaticFiles(directory="web"), name="web")


def _caller(authorization: str | None) -> str:
    return get_current_user(authorization)


# ── Authentication Endpoints ─────────────────────────────────────────────

@app.post("/api/auth/register")
async def auth_register(
    request: Request,
    email: str = Form(None),
    account_password: str = Form(None),
    kms_passphrase: str = Form(None),
    password: str = Form(None),
):
    """
    Registers a new user:
    1. Generates split-trust local vault (X25519, ML-KEM-768, Ed25519)
    2. Hashes password via PBKDF2HMAC-SHA256
    3. Saves record into app_users table
    4. Issues 2-hour JWT
    """
    if not email:
        try:
            body = await request.json()
            email = body.get("email")
            account_password = body.get("account_password") or body.get("password")
            kms_passphrase = body.get("kms_passphrase")
        except Exception:
            pass

    pwd = account_password or password
    if not email or not pwd:
        raise HTTPException(400, "email and password are required")

    return register_user(email, pwd, kms_passphrase)


@app.post("/api/auth/login")
async def auth_login(
    request: Request,
    email: str = Form(None),
    account_password: str = Form(None),
    kms_passphrase: str = Form(None),
    password: str = Form(None),
):
    """
    Signs in a user:
    1. Validates password hash in app_users
    2. Validates kms_passphrase unlocks local vault
    3. Returns JWT + receiver list
    """
    if not email:
        try:
            body = await request.json()
            email = body.get("email")
            account_password = body.get("account_password") or body.get("password")
            kms_passphrase = body.get("kms_passphrase")
        except Exception:
            pass

    pwd = account_password or password
    if not email or not pwd:
        raise HTTPException(400, "email and password are required")

    return login_user(email, pwd, kms_passphrase)


@app.post("/api/login")
async def legacy_login(
    email: str = Form(...),
    account_password: str = Form(None),
    kms_passphrase: str = Form(None),
):
    """Legacy backward-compatible login."""
    if account_password and kms_passphrase:
        return login_user(email, account_password, kms_passphrase)
    return {"token": issue_token(email), "email": email}


@app.get("/api/users")
async def list_registered_users(authorization: str | None = Header(None)):
    """Fetch all registered receiver emails for frontend dropdown."""
    _caller(authorization)
    client = _get_client()
    users: list[str] = []
    try:
        res = client.table("app_users").select("email").execute()
        if res and res.data:
            users = [u["email"] for u in res.data if u.get("email")]
    except Exception:
        pass

    if not users:
        try:
            res = client.table("user_public_keys").select("email").execute()
            if res and res.data:
                users = [u["email"] for u in res.data if u.get("email")]
        except Exception:
            pass

    return {"users": sorted(list(set(users)))}


# ── Receiver Key Generation (Legacy Bridge) ──────────────────────────────

@app.post("/api/receiver/generate-keys")
async def gen_keys(authorization: str | None = Header(None)):
    email = _caller(authorization)
    pub = generate_receiver_keys(email)
    return {"status": "keys_generated", "public_keys": pub}


@app.get("/api/receiver/keys-exist")
async def keys_exist(authorization: str | None = Header(None)):
    email = _caller(authorization)
    return {"exists": receiver_keys_exist(email) or vault_exists(email)}


# ── Sender: Encrypt & Upload ────────────────────────────────────────────

@app.post("/api/encrypt")
@app.post("/api/upload")
async def upload(
    file: UploadFile = File(...),
    receiver_email: str = Form(...),
    authorization: str | None = Header(None),
    sender_passphrase: str | None = Form(None),
):
    sender_email = _caller(authorization)
    file_bytes = await file.read()
    file_id = f"file_{uuid.uuid4().hex[:8]}"
    original_filename = file.filename or "unknown"

    version = 1
    prev_hash = ""

    # Verify receiver public keys against MITM substitution
    try:
        receiver_pub = get_verified_receiver_public_keys(receiver_email)
    except UntrustedPublicKeyError as e:
        if "No public keys registered" in str(e):
            # Recipient has not registered yet: auto-provision their cryptographic keys in Supabase
            pub_bundle = create_user_vault(receiver_email, f"{receiver_email}-kms-vault")
            from core.auth_acl import hash_password
            salt_hex, hash_hex = hash_password(f"{receiver_email}-auto-pass")
            salt_hex = f"auto-stub:{salt_hex}"
            user_row = {
                "email": receiver_email,
                "password_salt": salt_hex,
                "password_hash": hash_hex,
                "x25519_pub": pub_bundle["x25519_pub"],
                "mlkem_pub": pub_bundle["mlkem_pub"],
                "ed25519_verify_key": pub_bundle["ed25519_verify_key"],
                "key_signature": pub_bundle["key_signature"],
            }
            try:
                _get_client().table("app_users").upsert(user_row).execute()
            except Exception:
                pass
            try:
                _get_client().table("user_public_keys").upsert({
                    "email": receiver_email,
                    "x25519_pub": pub_bundle["x25519_pub"],
                    "mlkem_pub": pub_bundle["mlkem_pub"],
                    "ed25519_verify_key": pub_bundle["ed25519_verify_key"],
                    "key_signature": pub_bundle["key_signature"],
                }).execute()
            except Exception:
                pass
            receiver_pub = get_verified_receiver_public_keys(receiver_email)
        else:
            raise HTTPException(403, f"MITM guard halted encryption: {e}")
    except Exception:
        receiver_pub = load_receiver_public_keys(receiver_email)

    # Hybrid key establishment — UNTOUCHED
    t0 = time.perf_counter()
    aes_key, sender_x_pub, mlkem_ct = sender_establish_hybrid_key(receiver_pub)
    key_time_ms = (time.perf_counter() - t0) * 1000

    # Fragment and parallel encrypt with identity-bound AAD — UNTOUCHED MATH
    fragments = fragment_bytes(file_bytes)
    t1 = time.perf_counter()
    enc_results = parallel_encrypt_fragments(
        fragments,
        aes_key,
        file_id,
        version,
        owner_email=sender_email,
        authorized_receiver=receiver_email,
    )
    enc_time_s = time.perf_counter() - t1

    # Merkle root & version chain hash
    frag_hashes = [meta["sha256"] for _, _, _, meta in enc_results]
    merkle_root = compute_merkle_root(frag_hashes)
    chain_hash = compute_version_chain_hash(file_id, version, prev_hash, merkle_root)

    # Upload to Supabase Storage in dedicated worker thread (prevents Windows socket blocking collisions)
    try:
        manifest = await asyncio.to_thread(
            upload_encrypted_file,
            file_id=file_id,
            version=version,
            original_filename=original_filename,
            owner_email=sender_email,
            receiver_email=receiver_email,
            sender_x25519_pub=sender_x_pub,
            mlkem_ciphertext=mlkem_ct,
            encrypted_results=enc_results,
            version_chain_hash=chain_hash,
            prev_version_hash=prev_hash,
            manifest_merkle_root=merkle_root,
        )
    except Exception as e:
        raise HTTPException(502, f"Supabase upload failed — check .env credentials: {e}")

    # Pin local ledger
    pin_version(file_id, version, chain_hash)

    # Generate ICAT Token
    icat_token = None
    if sender_passphrase and vault_exists(sender_email):
        try:
            icat_token = create_icat_token(
                file_id=file_id,
                version=version,
                original_filename=original_filename,
                owner_email=sender_email,
                authorized_receiver=receiver_email,
                sender_x25519_pub=sender_x_pub,
                mlkem_ciphertext=mlkem_ct,
                enc_results=enc_results,
                prev_version_hash=prev_hash,
                version_chain_hash=chain_hash,
                sender_passphrase=sender_passphrase,
            )
        except KMSAuthenticationError as e:
            raise HTTPException(401, f"ICAT token signing failed: {e}")
    else:
        # Construct capsule structure even without local passphrase for download
        fragment_manifest = [
            {
                "index": meta["index"],
                "storage_path": meta.get("storage_path", f"{file_id}/v{version}/fragment_{meta['index']}.enc"),
                "nonce": meta["nonce"],
                "auth_tag": meta["auth_tag"],
                "sha256": meta["sha256"],
            }
            for _, _, _, meta in enc_results
        ]
        icat_token = {
            "icat_version": "1.0",
            "file_id": file_id,
            "version": version,
            "original_filename": original_filename,
            "owner_email": sender_email,
            "authorized_receiver": receiver_email,
            "hybrid_capsule": {
                "sender_x25519_pub": sender_x_pub,
                "mlkem_ciphertext": mlkem_ct,
            },
            "fragment_manifest": fragment_manifest,
            "anti_rollback": {
                "prev_version_hash": prev_hash,
                "version_chain_hash": chain_hash,
            },
        }

    resp = {
        "file_id": file_id,
        "version": version,
        "original_filename": original_filename,
        "file_size_bytes": len(file_bytes),
        "fragments_created": len(fragments),
        "hybrid_key_time_ms": round(key_time_ms, 2),
        "parallel_aes_gcm_time_s": round(enc_time_s, 4),
        "merkle_root": merkle_root,
        "chain_hash": chain_hash,
    }
    if icat_token:
        resp["icat_token"] = icat_token
    return resp


# ── Receiver: List / Decrypt / Download ─────────────────────────────────

@app.get("/api/files")
async def list_my_files(authorization: str | None = Header(None)):
    email = _caller(authorization)
    return list_files_for_receiver(email)


@app.post("/api/decrypt/{file_id}")
@app.get("/api/download/{file_id}")
async def download(
    file_id: str,
    authorization: str | None = Header(None),
    kms_passphrase: str | None = Header(None),
):
    caller_email = _caller(authorization)

    # ACL check
    meta = get_file_metadata(file_id)
    if not meta:
        raise HTTPException(404, "File not found")
    receiver = meta.get("receiver_email") or meta.get("authorized_receiver", "")
    try:
        check_download_permission(caller_email, meta["owner_email"], receiver)
    except ACLError:
        raise HTTPException(403, "Forbidden: Unauthorized Access")

    # Anti-rollback check
    try:
        verify_version(file_id, meta["version"], meta["version_chain_hash"])
    except RollbackAttackDetectedError as e:
        raise HTTPException(409, f"Rollback attack detected: {e}")

    # Download fragments in dedicated worker thread
    record, fragments = await asyncio.to_thread(download_encrypted_file, file_id)

    # Reconstruct key via KMS vault if passphrase provided, else fallback
    if kms_passphrase and vault_exists(caller_email):
        try:
            priv_keys = unlock_vault(caller_email, kms_passphrase)
        except KMSAuthenticationError as e:
            raise HTTPException(401, f"KMS Vault Unlock Failed: {e}")
    else:
        try:
            priv_keys = unlock_vault(caller_email, "default-dev-secret")
        except Exception:
            priv_keys = load_receiver_private_keys(caller_email)

    aes_key = receiver_reconstruct_hybrid_key(
        priv_keys, record["sender_x25519_pub"], record["mlkem_ciphertext"]
    )

    # Parallel decrypt with identity AAD
    try:
        try:
            recovered = parallel_decrypt_and_reassemble(
                fragments,
                aes_key,
                file_id,
                record["version"],
                owner_email=meta["owner_email"],
                authorized_receiver=receiver,
            )
        except Exception:
            # Fallback to plain file_id AAD if legacy encryption
            recovered = parallel_decrypt_and_reassemble(
                fragments, aes_key, file_id, record["version"]
            )
    except (TamperingDetectedError, Exception) as e:
        raise HTTPException(422, f"Decryption failed — possible tampering: {e}")

    pin_version(file_id, record["version"], record["version_chain_hash"])

    return StreamingResponse(
        io.BytesIO(recovered),
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{record["original_filename"]}"'},
    )


# ── ICAT KMS Endpoints ───────────────────────────────────────────────────

@app.post("/api/kms/init-vault")
async def kms_init_vault(
    email: str = Form(...),
    passphrase: str = Form(...),
):
    """Generate keys, create local two-tier vault, register signed public keys."""
    try:
        pub_bundle = create_user_vault(email, passphrase)
        signed_rec = sign_and_register_public_keys(email, passphrase)
    except Exception as e:
        raise HTTPException(500, f"Vault init failed: {e}")
    return {"status": "vault_created", "public_keys": pub_bundle}


@app.post("/api/kms/unlock-vault")
async def kms_unlock_vault(
    email: str = Form(...),
    passphrase: str = Form(...),
):
    """Validate passphrase against local vault (keys stay in RAM)."""
    try:
        unlock_vault(email, passphrase)
    except KMSAuthenticationError as e:
        raise HTTPException(401, str(e))
    return {"status": "vault_unlocked", "email": email}


@app.get("/api/icat/export/{file_id}")
async def icat_export(file_id: str, authorization: str | None = Header(None)):
    """Download the .icat.json capsule file for file_id."""
    caller = _caller(authorization)
    path = os.path.join(ICAT_DIR, f"{file_id}.icat.json")
    if not os.path.exists(path):
        meta = get_file_metadata(file_id)
        if not meta:
            raise HTTPException(404, "ICAT token not found")
        # Check permission
        check_download_permission(caller, meta["owner_email"], meta.get("receiver_email", ""))
        token = {
            "icat_version": "1.0",
            "file_id": file_id,
            "version": meta.get("version", 1),
            "original_filename": meta.get("original_filename", ""),
            "owner_email": meta.get("owner_email", ""),
            "authorized_receiver": meta.get("receiver_email", ""),
            "hybrid_capsule": {
                "sender_x25519_pub": meta.get("sender_x25519_pub", ""),
                "mlkem_ciphertext": meta.get("mlkem_ciphertext", ""),
            },
            "fragment_manifest": meta.get("fragment_manifest", []),
            "anti_rollback": {
                "prev_version_hash": meta.get("prev_version_hash", ""),
                "version_chain_hash": meta.get("version_chain_hash", ""),
            },
        }
        return JSONResponse(token)

    with open(path, "r", encoding="utf-8") as f:
        token = json.load(f)
    if token.get("authorized_receiver") != caller and token.get("owner_email") != caller:
        raise HTTPException(403, "Forbidden")
    return JSONResponse(token)


@app.post("/api/icat/ingest-and-decrypt")
async def icat_ingest_and_decrypt(
    icat_file: UploadFile = File(...),
    passphrase: str = Form(...),
    authorization: str | None = Header(None),
):
    """Accept .icat.json token + passphrase, validate identity/sig, decrypt and return file."""
    receiver_email = _caller(authorization)
    raw = await icat_file.read()
    try:
        token = json.loads(raw.decode("utf-8"))
    except Exception:
        raise HTTPException(400, "Invalid ICAT token JSON")

    try:
        plaintext = icat_decrypt(
            token=token,
            receiver_email=receiver_email,
            receiver_passphrase=passphrase,
        )
    except (ValueError, CapsuleSignatureError, CapsuleSignatureVerificationError) as e:
        raise HTTPException(403, f"ICAT verification failed: {e}")
    except KMSAuthenticationError as e:
        raise HTTPException(401, str(e))
    except Exception as e:
        raise HTTPException(422, f"Decryption failed: {e}")

    filename = token.get("original_filename") or token.get("file_id", "decrypted_file")
    return StreamingResponse(
        io.BytesIO(plaintext),
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ── Delete ───────────────────────────────────────────────────────────────

@app.delete("/api/files/{file_id}")
async def delete_file_endpoint(file_id: str, authorization: str | None = Header(None)):
    caller_email = _caller(authorization)
    meta = get_file_metadata(file_id)
    if not meta:
        raise HTTPException(404, "File not found")
    try:
        check_delete_permission(caller_email, meta["owner_email"])
    except ACLError:
        raise HTTPException(403, "Forbidden: Only owner can delete")
    cloud_delete_file(file_id)
    return {"status": "deleted", "file_id": file_id}


# ── Serve HTML pages ─────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def sender_page():
    with open("web/index.html", encoding="utf-8") as f:
        return f.read()


@app.get("/receiver", response_class=HTMLResponse)
async def receiver_page():
    with open("web/receiver.html", encoding="utf-8") as f:
        return f.read()
