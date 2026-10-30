# core/icat_kms.py
"""
Identity-Bound Cryptographic Access Capsule — Key Management System (ICAC-KMS).

Split-Trust Envelope Architecture:
  1. KEK derived on-the-fly in RAM from kms_passphrase + salt via Scrypt(n=2**14, r=8, p=1).
     Never written to disk.
  2. DEK = os.urandom(32) random 256-bit key.
  3. Private keys {"x25519_priv", "mlkem_priv", "ed25519_priv"} encrypted via AES-256-GCM
     using DEK and AAD = email.encode().
  4. DEK wrapped with KEK via AES-256-GCM using AAD = b"ICAT-KMS-DEK".
  5. Ed25519 signs f"{email}|{x25519_pub}|{mlkem_pub}" to prevent cloud-side MITM.
  6. .icat.json access capsule binds identity, hybrid ciphertext, fragment manifests,
     anti-rollback hashes, and sender's Ed25519 signature.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

# ── Custom Exceptions ────────────────────────────────────────────────────

class KMSAuthenticationError(Exception):
    """Wrong passphrase, invalid tag, or corrupted vault."""
    pass


class CapsuleSignatureVerificationError(Exception):
    """ICAT capsule_signature failed Ed25519 verification."""
    pass

# Direct alias per prompt specification
CapsuleSignatureError = CapsuleSignatureVerificationError


class UntrustedPublicKeyError(Exception):
    """Cloud-side public key bundle signature verification failed (MITM guard)."""
    pass


from core.parallel_engine import RollbackAttackDetectedError  # noqa: F401


# ── Directory Paths & Constants ──────────────────────────────────────────

PROJECT_ROOT = os.path.dirname(os.path.dirname(__file__))
VAULT_DIR = os.path.join(PROJECT_ROOT, "vaults")
KMS_DATA_DIR = os.path.join(PROJECT_ROOT, "kms_data")
ICAT_DIR = os.path.join(PROJECT_ROOT, "icat_tokens")
VAULT_VERSION = "2.0"

_N = 2**14  # 16384 iterations (NIST standard, fast memory-hard KDF)
_R = 8
_P = 1


def _derive_kek(passphrase: str, salt: bytes, n: int = _N) -> bytes:
    """Derive 256-bit KEK in RAM from passphrase + salt using Scrypt."""
    kdf = Scrypt(salt=salt, length=32, n=n, r=_R, p=_P)
    return kdf.derive(passphrase.encode("utf-8"))


def _vault_paths_for_email(email: str) -> list[str]:
    """Return primary and fallback vault file paths."""
    safe = email.replace("@", "_at_").replace(".", "_")
    return [
        os.path.join(VAULT_DIR, f"vault_{safe}.enc"),
        os.path.join(KMS_DATA_DIR, f"vault_{safe}.enc"),
        os.path.join(VAULT_DIR, f"{safe}.vault.enc"),
        os.path.join(KMS_DATA_DIR, f"{safe}.vault.enc"),
    ]


def vault_exists(email: str) -> bool:
    """Check if vault file exists in either vaults/ or kms_data/ directory."""
    return any(os.path.exists(p) for p in _vault_paths_for_email(email))


# ── Vault Creation & Two-Tier Key Wrapping ───────────────────────────────

def create_user_vault(email: str, kms_passphrase: str) -> dict:
    """
    Generate X25519, ML-KEM-768, and Ed25519 keys.
    Wrap private keys into a two-tier (KEK -> DEK) local vault.
    Sign public keys bundle with Ed25519 private key -> key_signature.
    Save encrypted JSON to vault_{email}.enc.
    Returns:
      {
        "x25519_pub": str,
        "mlkem_pub": str,
        "ed25519_verify_key": str,
        "key_signature": str
      }
    """
    from core.hybrid_crypto import KeyEncapsulation

    os.makedirs(VAULT_DIR, exist_ok=True)
    os.makedirs(KMS_DATA_DIR, exist_ok=True)

    # 0. Check if an auto-provisioned vault exists for this email to preserve cryptographic continuity
    existing_priv = None
    existing_mlkem_pub = None
    for p in _vault_paths_for_email(email):
        if os.path.exists(p):
            try:
                existing_priv = unlock_vault(email, f"{email}-kms-vault")
                with open(p, "r", encoding="utf-8") as f:
                    v_data = json.load(f)
                    existing_mlkem_pub = v_data.get("mlkem_pub")
                break
            except Exception:
                pass

    if existing_priv and existing_mlkem_pub:
        x_priv = x25519.X25519PrivateKey.from_private_bytes(existing_priv["x25519_priv"])
        x_pub_bytes = x_priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        x_priv_bytes = existing_priv["x25519_priv"]
        mlkem_priv_bytes = existing_priv["mlkem_priv"]
        mlkem_pub_bytes = base64.b64decode(existing_mlkem_pub)

        ed_priv = Ed25519PrivateKey.from_private_bytes(existing_priv["ed25519_priv"])
        ed_pub_bytes = ed_priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        ed_priv_bytes = existing_priv["ed25519_priv"]
    else:
        # 1. Generate X25519
        x_priv = x25519.X25519PrivateKey.generate()
        x_pub_bytes = x_priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        x_priv_bytes = x_priv.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )

        # 2. Generate ML-KEM-768
        with KeyEncapsulation("ML-KEM-768") as kem:
            mlkem_pub_bytes = kem.generate_keypair()
            mlkem_priv_bytes = kem.export_secret_key()

        # 3. Generate Ed25519 Identity Keypair
        ed_priv = Ed25519PrivateKey.generate()
        ed_pub_bytes = ed_priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        ed_priv_bytes = ed_priv.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )

    # Base64 representations
    x25519_pub_b64 = base64.b64encode(x_pub_bytes).decode()
    mlkem_pub_b64 = base64.b64encode(mlkem_pub_bytes).decode()
    ed25519_verify_b64 = base64.b64encode(ed_pub_bytes).decode()

    # 4. Anti-MITM Signature: Sign f"{email}|{x25519_pub}|{mlkem_pub}"
    sig_payload = f"{email}|{x25519_pub_b64}|{mlkem_pub_b64}".encode("utf-8")
    sig_bytes = ed_priv.sign(sig_payload)
    key_signature_b64 = base64.b64encode(sig_bytes).decode()

    # 5. Two-Tier Envelope Encryption:
    # KEK derived from passphrase + 16-byte random salt
    salt = os.urandom(16)
    kek = _derive_kek(kms_passphrase, salt, n=_N)

    # Random DEK
    dek = os.urandom(32)

    # Wrap DEK with KEK via AESGCM(AAD=b"ICAT-KMS-DEK")
    dek_nonce = os.urandom(12)
    wrapped_dek = AESGCM(kek).encrypt(dek_nonce, dek, b"ICAT-KMS-DEK")

    # Encrypt private keys with DEK via AESGCM(AAD=email.encode())
    priv_payload = json.dumps({
        "x25519_priv": base64.b64encode(x_priv_bytes).decode(),
        "mlkem_priv": base64.b64encode(mlkem_priv_bytes).decode(),
        "ed25519_priv": base64.b64encode(ed_priv_bytes).decode(),
    }).encode("utf-8")
    keys_nonce = os.urandom(12)
    enc_keys = AESGCM(dek).encrypt(keys_nonce, priv_payload, email.encode("utf-8"))

    # Save encrypted JSON to vault
    vault_doc = {
        "vault_version": VAULT_VERSION,
        "email": email,
        "salt": base64.b64encode(salt).decode(),
        "wrapped_dek": base64.b64encode(wrapped_dek).decode(),
        "dek_nonce": base64.b64encode(dek_nonce).decode(),
        "enc_keys": base64.b64encode(enc_keys).decode(),
        "keys_nonce": base64.b64encode(keys_nonce).decode(),
        # Backward-compatible aliases
        "encrypted_priv_keys": base64.b64encode(enc_keys).decode(),
        "priv_nonce": base64.b64encode(keys_nonce).decode(),
        "mlkem_pub": mlkem_pub_b64,
        "x25519_pub": x25519_pub_b64,
        "ed25519_verify_key": ed25519_verify_b64,
        "key_signature": key_signature_b64,
    }

    target_paths = _vault_paths_for_email(email)
    for p in target_paths[:2]:  # write to primary vaults/ and kms_data/
        try:
            with open(p, "w", encoding="utf-8") as f:
                json.dump(vault_doc, f, indent=2)
        except Exception:
            pass

    return {
        "x25519_pub": x25519_pub_b64,
        "mlkem_pub": mlkem_pub_b64,
        "ed25519_verify_key": ed25519_verify_b64,
        "key_signature": key_signature_b64,
    }


def init_vault(email: str, passphrase: str) -> dict:
    """Alias for create_user_vault."""
    return create_user_vault(email, passphrase)


# ── Vault Unlock (Private Keys Decrypted Strictly in RAM) ────────────────

def unlock_vault(email: str, passphrase: str) -> dict:
    """
    Unlock local envelope vault in RAM using passphrase.
    Returns:
      {
        "x25519_priv": bytes,
        "mlkem_priv": bytes,
        "ed25519_priv": bytes
      }
    Raises KMSAuthenticationError on wrong passphrase or tampering.
    """
    chosen_path = None
    for p in _vault_paths_for_email(email):
        if os.path.exists(p):
            chosen_path = p
            break

    if not chosen_path:
        raise KMSAuthenticationError(f"No local KMS vault found for {email}")

    with open(chosen_path, "r", encoding="utf-8") as f:
        vault = json.load(f)

    salt = base64.b64decode(vault["salt"])
    wrapped_dek = base64.b64decode(vault["wrapped_dek"])
    dek_nonce = base64.b64decode(vault["dek_nonce"])
    enc_keys = base64.b64decode(vault.get("enc_keys") or vault.get("encrypted_priv_keys"))
    keys_nonce = base64.b64decode(vault.get("keys_nonce") or vault.get("priv_nonce"))

    # Try standard Scrypt N=2**14 first, then fallback to 2**16 if legacy vault
    dek = None
    last_err = None
    for n_val in (_N, 2**16):
        try:
            kek = _derive_kek(passphrase, salt, n=n_val)
            # Try with AAD = b"ICAT-KMS-DEK"
            try:
                dek = AESGCM(kek).decrypt(dek_nonce, wrapped_dek, b"ICAT-KMS-DEK")
                break
            except Exception:
                # Try without AAD (backward compatibility)
                dek = AESGCM(kek).decrypt(dek_nonce, wrapped_dek, None)
                break
        except Exception as e:
            last_err = e

    if dek is None:
        raise KMSAuthenticationError("Vault decryption failed: Invalid KMS Vault Passphrase") from last_err

    # Decrypt private keys with DEK
    try:
        try:
            priv_blob = AESGCM(dek).decrypt(keys_nonce, enc_keys, email.encode("utf-8"))
        except Exception:
            priv_blob = AESGCM(dek).decrypt(keys_nonce, enc_keys, None)
        priv_dict = json.loads(priv_blob.decode("utf-8"))
    except Exception as e:
        raise KMSAuthenticationError("Corrupted or tampered key material inside vault") from e

    return {
        "x25519_priv": base64.b64decode(priv_dict["x25519_priv"]),
        "mlkem_priv": base64.b64decode(priv_dict["mlkem_priv"]),
        "ed25519_priv": base64.b64decode(priv_dict["ed25519_priv"]),
    }


# ── Public Key Anti-MITM Verification ────────────────────────────────────

def verify_receiver_public_keys(receiver_row: dict) -> None:
    """
    Verify Ed25519 signature over receiver's public keys.
    Raises UntrustedPublicKeyError on tampering.
    """
    email = receiver_row.get("email", "")
    x25519_pub = receiver_row.get("x25519_pub", "")
    mlkem_pub = receiver_row.get("mlkem_pub", "")
    ed_verify_b64 = receiver_row.get("ed25519_verify_key", "")
    sig_b64 = receiver_row.get("key_signature", "")

    if not (email and x25519_pub and mlkem_pub and ed_verify_b64 and sig_b64):
        raise UntrustedPublicKeyError(f"Incomplete public key registration record for {email}")

    ed_pub_bytes = base64.b64decode(ed_verify_b64)
    sig_bytes = base64.b64decode(sig_b64)
    verifier = Ed25519PublicKey.from_public_bytes(ed_pub_bytes)

    # Primary signature format: f"{email}|{x25519_pub}|{mlkem_pub}"
    primary_msg = f"{email}|{x25519_pub}|{mlkem_pub}".encode("utf-8")
    try:
        verifier.verify(sig_bytes, primary_msg)
        return
    except InvalidSignature:
        pass

    # Fallback to sorted JSON bundle (if legacy record)
    bundle_bytes = json.dumps({
        "email": email,
        "x25519_pub": x25519_pub,
        "mlkem_pub": mlkem_pub,
        "ed25519_verify_key": ed_verify_b64,
    }, sort_keys=True).encode("utf-8")
    try:
        verifier.verify(sig_bytes, bundle_bytes)
        return
    except InvalidSignature as exc:
        raise UntrustedPublicKeyError(
            f"Public key bundle signature invalid for {email} — cloud DB public key tampering detected"
        ) from exc


def get_verified_receiver_public_keys(receiver_email: str) -> dict:
    """
    Fetch receiver row from Supabase app_users (or user_public_keys)
    and verify Ed25519 signature before returning.
    """
    from core.cloud_storage import _get_client

    client = _get_client()
    row = None
    try:
        res = client.table("app_users").select("*").eq("email", receiver_email).single().execute()
        row = res.data
    except Exception:
        pass

    if not row:
        try:
            res = client.table("user_public_keys").select("*").eq("email", receiver_email).single().execute()
            row = res.data
        except Exception:
            pass

    if not row:
        raise UntrustedPublicKeyError(f"No public keys registered for recipient {receiver_email}")

    verify_receiver_public_keys(row)
    return row


def sign_and_register_public_keys(email: str, passphrase: str) -> dict:
    """Sign and register public keys in Supabase (convenience helper)."""
    from core.cloud_storage import _get_client

    priv_keys = unlock_vault(email, passphrase)
    ed_priv = Ed25519PrivateKey.from_private_bytes(priv_keys["ed25519_priv"])
    x_pub = (
        x25519.X25519PrivateKey.from_private_bytes(priv_keys["x25519_priv"])
        .public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    )
    ed_pub = ed_priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )

    # Read stored mlkem_pub
    for p in _vault_paths_for_email(email):
        if os.path.exists(p):
            with open(p, "r", encoding="utf-8") as f:
                v = json.load(f)
                mlkem_pub_b64 = v.get("mlkem_pub")
                break
    else:
        raise KMSAuthenticationError("Vault missing mlkem_pub")

    x_b64 = base64.b64encode(x_pub).decode()
    ed_b64 = base64.b64encode(ed_pub).decode()
    sig = base64.b64encode(ed_priv.sign(f"{email}|{x_b64}|{mlkem_pub_b64}".encode())).decode()

    rec = {
        "email": email,
        "x25519_pub": x_b64,
        "mlkem_pub": mlkem_pub_b64,
        "ed25519_verify_key": ed_b64,
        "key_signature": sig,
    }
    _get_client().table("user_public_keys").upsert(rec).execute()
    return rec


# ── ICAT Capsule Generation & Verification ───────────────────────────────

def _icat_path(file_id: str) -> str:
    os.makedirs(ICAT_DIR, exist_ok=True)
    return os.path.join(ICAT_DIR, f"{file_id}.icat.json")


def create_icat_token(
    *,
    file_id: str,
    version: int,
    original_filename: str = "",
    owner_email: str,
    authorized_receiver: str,
    sender_x25519_pub: str,
    mlkem_ciphertext: str,
    enc_results: list,
    prev_version_hash: str,
    version_chain_hash: str,
    sender_passphrase: str | None = None,
    sender_ed_priv: Ed25519PrivateKey | None = None,
) -> dict:
    """
    Construct ICAT Access Capsule and sign with Sender's Ed25519 private key.
    """
    if sender_ed_priv is None:
        if not sender_passphrase:
            raise KMSAuthenticationError("sender_passphrase or sender_ed_priv required to sign ICAT capsule")
        priv_keys = unlock_vault(owner_email, sender_passphrase)
        sender_ed_priv = Ed25519PrivateKey.from_private_bytes(priv_keys["ed25519_priv"])

    fragment_manifest = [
        {
            "index": meta["index"],
            "storage_path": meta.get(
                "storage_path",
                f"{file_id}/v{version}/fragment_{meta['index']}.enc",
            ),
            "nonce": meta["nonce"],
            "auth_tag": meta["auth_tag"],
            "sha256": meta["sha256"],
        }
        for _, _, _, meta in enc_results
    ]

    token_body = {
        "icat_version": "1.0",
        "file_id": file_id,
        "version": version,
        "original_filename": original_filename,
        "owner_email": owner_email,
        "authorized_receiver": authorized_receiver,
        "hybrid_capsule": {
            "sender_x25519_pub": sender_x25519_pub,
            "mlkem_ciphertext": mlkem_ciphertext,
        },
        "fragment_manifest": fragment_manifest,
        "anti_rollback": {
            "prev_version_hash": prev_version_hash,
            "version_chain_hash": version_chain_hash,
        },
    }

    # Canonical sorted JSON signature
    body_bytes = json.dumps(token_body, sort_keys=True).encode("utf-8")
    sig_bytes = sender_ed_priv.sign(body_bytes)
    token_body["capsule_signature"] = base64.b64encode(sig_bytes).decode()

    # Save to icat_tokens/
    try:
        with open(_icat_path(file_id), "w", encoding="utf-8") as f:
            json.dump(token_body, f, indent=2)
    except Exception:
        pass

    return token_body


def verify_icat_token(token: dict, current_user_email: str) -> None:
    """
    1. Verify current_user is authorized_receiver or owner_email
    2. Verify Ed25519 capsule_signature against Sender's ed25519_verify_key
    Raises CapsuleSignatureError or ACLError / ValueError on failure.
    """
    from core.cloud_storage import _get_client

    authorized_rec = token.get("authorized_receiver")
    owner_email = token.get("owner_email")

    if current_user_email not in (authorized_rec, owner_email):
        raise CapsuleSignatureVerificationError(
            f"Unauthorized: Token authorized for {authorized_rec}, but accessed by {current_user_email}"
        )

    if "capsule_signature" not in token:
        raise CapsuleSignatureVerificationError("Missing capsule_signature in ICAT token")

    token_copy = dict(token)
    sig_b64 = token_copy.pop("capsule_signature")
    sig_bytes = base64.b64decode(sig_b64)

    client = _get_client()
    row = None
    try:
        res = client.table("app_users").select("ed25519_verify_key").eq("email", owner_email).single().execute()
        row = res.data
    except Exception:
        pass

    if not row or not row.get("ed25519_verify_key"):
        try:
            res = client.table("user_public_keys").select("ed25519_verify_key").eq("email", owner_email).single().execute()
            row = res.data
        except Exception:
            pass

    if not row or not row.get("ed25519_verify_key"):
        raise CapsuleSignatureVerificationError(
            f"Unable to locate public identity verification key for sender {owner_email}"
        )

    ed_pub_bytes = base64.b64decode(row["ed25519_verify_key"])
    verifier = Ed25519PublicKey.from_public_bytes(ed_pub_bytes)

    body_bytes = json.dumps(token_copy, sort_keys=True).encode("utf-8")
    try:
        verifier.verify(sig_bytes, body_bytes)
    except InvalidSignature as exc:
        raise CapsuleSignatureVerificationError(
            "ICAT capsule_signature verification failed: Token identity or fragments tampered"
        ) from exc


# ── Full ICAT-Driven Decryption ──────────────────────────────────────────

def icat_decrypt(
    *,
    token: dict,
    receiver_email: str,
    receiver_passphrase: str,
    downloaded_fragments: list | None = None,
) -> bytes:
    """
    1. Verify current receiver identity & capsule_signature
    2. Audit anti-rollback version_chain_hash
    3. Unlock receiver vault in RAM using receiver_passphrase
    4. Reconstruct hybrid AES key
    5. Parallel AES-256-GCM decrypt with identity-bound AAD
    """
    from core.cloud_storage import download_encrypted_file
    from core.hybrid_crypto import receiver_reconstruct_hybrid_key
    from core.parallel_engine import (
        parallel_decrypt_and_reassemble,
        verify_version,
    )

    # 1. Audit identity & signature
    verify_icat_token(token, receiver_email)

    # 2. Anti-rollback check
    ar = token.get("anti_rollback", {})
    verify_version(token["file_id"], token["version"], ar.get("version_chain_hash", ""))

    # 3. Unlock receiver private keys
    priv_keys = unlock_vault(receiver_email, receiver_passphrase)

    # 4. Reconstruct hybrid AES key
    aes_key = receiver_reconstruct_hybrid_key(
        priv_keys,
        token["hybrid_capsule"]["sender_x25519_pub"],
        token["hybrid_capsule"]["mlkem_ciphertext"],
    )

    # 5. Fetch fragments if not supplied
    if downloaded_fragments is None:
        _, downloaded_fragments = download_encrypted_file(token["file_id"])

    # 6. Parallel decrypt with exact AAD identity binding
    return parallel_decrypt_and_reassemble(
        downloaded_fragments,
        aes_key,
        token["file_id"],
        token["version"],
        owner_email=token["owner_email"],
        authorized_receiver=token["authorized_receiver"],
    )


def icat_aad_file_id(
    file_id: str, version: int, owner_email: str, authorized_receiver: str
) -> str:
    """Backward compatibility helper."""
    return f"{file_id}:owner:{owner_email}:rec:{authorized_receiver}"
