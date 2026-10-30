# core/auth_acl.py
"""
Cryptographic Authentication and Access Control List (ACL) system.
Backed by PBKDF2-HMAC password hashing, local KMS vault attestation,
and signed HS256 JWT tokens.
"""
from __future__ import annotations

import hmac
import os
import time
from typing import Optional

import jwt
from dotenv import load_dotenv
from fastapi import Header, HTTPException
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

load_dotenv()
JWT_SECRET = os.getenv("JWT_SECRET", "hecc-jwt-secret-change-in-production")
JWT_ALGO = "HS256"
TOKEN_TTL = 7200  # 2 hours (per specification)

from core.cloud_storage import _get_client


class ACLError(Exception):
    """Raised when a user is not authorized for the requested action."""
    pass


# ── Password Hashing (PBKDF2-HMAC-SHA256, 200,000 iterations) ────────────

def hash_password(password: str, salt: bytes | None = None) -> tuple[str, str]:
    """
    Hash password using PBKDF2HMAC(SHA256, 200_000 iterations).
    Returns (salt_hex, hash_hex).
    """
    if salt is None:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200_000,
    )
    derived = kdf.derive(password.encode("utf-8"))
    return salt.hex(), derived.hex()


def verify_password(password: str, salt_hex: str, hash_hex: str) -> bool:
    """
    Verify password against salt and expected hash using constant-time comparison.
    """
    try:
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(hash_hex)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=200_000,
        )
        derived = kdf.derive(password.encode("utf-8"))
        return hmac.compare_digest(derived, expected)
    except Exception:
        return False


# ── JWT Issuance & Verification ──────────────────────────────────────────

def issue_token(email: str) -> str:
    """Issue a signed HS256 JWT for the given email (2-hour expiry)."""
    now = int(time.time())
    payload = {
        "sub": email,
        "iat": now,
        "exp": now + TOKEN_TTL,
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGO)


def verify_token(token: str) -> str:
    """Verify JWT signature and expiry. Returns subject email or raises."""
    payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
    return payload["sub"]


def get_current_user(authorization: Optional[str] = Header(None)) -> str:
    """FastAPI dependency to extract and verify the logged-in JWT caller."""
    if not authorization:
        raise HTTPException(401, "Missing Authorization header")
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(401, "Invalid Authorization header format. Expected 'Bearer <token>'")
    token = parts[1]
    try:
        return verify_token(token)
    except jwt.ExpiredSignatureError:
        raise HTTPException(401, "Authentication token has expired")
    except Exception:
        raise HTTPException(401, "Invalid or unauthorized token")


# ── ACL Permission Checks ────────────────────────────────────────────────

def check_upload_permission(caller_email: str, owner_email: str):
    """Owner must match authenticated caller."""
    if caller_email != owner_email:
        raise ACLError(f"Access Denied: {caller_email} is not the file owner ({owner_email})")


def check_download_permission(caller_email: str, owner_email: str, receiver_email: str):
    """Caller must be the file owner or designated authorized receiver."""
    if caller_email not in (owner_email, receiver_email):
        raise ACLError(
            f"Access Denied: {caller_email} is not authorized (owner={owner_email}, receiver={receiver_email})"
        )


def check_delete_permission(caller_email: str, owner_email: str):
    """Only owner can delete file artifacts."""
    if caller_email != owner_email:
        raise ACLError(f"Access Denied: {caller_email} cannot delete file owned by {owner_email}")


# ── Full Auth Flow Orchestration (backed by app_users in Supabase) ────────

import re

EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")


def validate_email(email: str) -> str:
    """Validate email format, raising 400 with a clear message if invalid."""
    if not email or not EMAIL_REGEX.match(email.strip()):
        raise HTTPException(
            400,
            "Invalid email format. Email must be in username@mail.com format (e.g. user@example.com)"
        )
    return email.strip()


def register_user(email: str, account_password: str, kms_passphrase: str | None = None) -> dict:
    """
    1. Validate email format
    2. Create/claim local client-side vault via icat_kms.create_user_vault
    3. Hash password via PBKDF2HMAC-SHA256
    4. Upsert user record into app_users table
    5. Return signed JWT + user public info
    """
    email = validate_email(email)
    kms_passphrase = kms_passphrase or account_password
    from core.cloud_storage import _get_client
    from core.icat_kms import create_user_vault

    client = _get_client()

    # Step B: Create / claim local two-tier vault and sign public keys
    pub_bundle = create_user_vault(email, kms_passphrase)

    # Step C: Hash password
    salt_hex, hash_hex = hash_password(account_password)

    user_row = {
        "email": email,
        "password_salt": salt_hex,
        "password_hash": hash_hex,
        "x25519_pub": pub_bundle["x25519_pub"],
        "mlkem_pub": pub_bundle["mlkem_pub"],
        "ed25519_verify_key": pub_bundle["ed25519_verify_key"],
        "key_signature": pub_bundle["key_signature"],
    }

    try:
        client.table("app_users").upsert(user_row).execute()
    except Exception as e:
        print(f"[AUTH ERROR] Failed to upsert app_users: {e}")

    # Also mirror into user_public_keys for legacy compatibility
    try:
        client.table("user_public_keys").upsert({
            "email": email,
            "x25519_pub": pub_bundle["x25519_pub"],
            "mlkem_pub": pub_bundle["mlkem_pub"],
            "ed25519_verify_key": pub_bundle["ed25519_verify_key"],
            "key_signature": pub_bundle["key_signature"],
        }).execute()
    except Exception as e:
        print(f"[AUTH ERROR] Failed to upsert user_public_keys: {e}")

    # Step D: Issue JWT token
    token = issue_token(email)
    return {
        "status": "registered",
        "token": token,
        "email": email,
        "public_keys": pub_bundle,
    }


def login_user(email: str, account_password: str, kms_passphrase: str | None = None) -> dict:
    """
    1. Validate email format
    2. Fetch user from Supabase app_users
    3. Verify account_password against PBKDF2 hash (or claim stub account seamlessly)
    4. Verify kms_passphrase unlocks local vault
    5. Return signed JWT Bearer token + registered receiver emails
    """
    email = validate_email(email)
    effective_kms_pass = kms_passphrase or account_password
    from core.cloud_storage import _get_client
    from core.icat_kms import unlock_vault, create_user_vault, KMSAuthenticationError

    client = _get_client()

    try:
        res = client.table("app_users").select("*").eq("email", email).single().execute()
        user = res.data if res else None
    except Exception:
        user = None

    if not user:
        raise HTTPException(401, "Invalid email or password")

    # If account was auto-provisioned during upload, seamlessly claim it with user's chosen password
    is_auto_stub = "auto-stub" in str(user.get("password_salt", "")) or "auto-pass" in str(user.get("password_salt", ""))
    if is_auto_stub:
        salt_hex, hash_hex = hash_password(account_password)
        pub_bundle = create_user_vault(email, effective_kms_pass)
        user["password_salt"] = salt_hex
        user["password_hash"] = hash_hex
        try:
            client.table("app_users").upsert({
                "email": email,
                "password_salt": salt_hex,
                "password_hash": hash_hex,
                "x25519_pub": pub_bundle["x25519_pub"],
                "mlkem_pub": pub_bundle["mlkem_pub"],
                "ed25519_verify_key": pub_bundle["ed25519_verify_key"],
                "key_signature": pub_bundle["key_signature"],
            }).execute()
        except Exception as e:
            print(f"[AUTH ERROR] Failed to claim app_users stub: {e}")
    else:
        if not verify_password(account_password, user["password_salt"], user["password_hash"]):
            raise HTTPException(401, "Invalid email or password")

        # Step B: Verify KMS vault passphrase
        try:
            unlock_vault(email, effective_kms_pass)
        except KMSAuthenticationError as exc:
            # If the caller explicitly passed a wrong kms_passphrase, raise 401
            if kms_passphrase and kms_passphrase != account_password:
                raise HTTPException(401, "Invalid KMS Vault Passphrase") from exc
            # Otherwise attempt auto-provisioned fallback or vault recreation if missing locally
            try:
                unlock_vault(email, f"{email}-kms-vault")
                create_user_vault(email, effective_kms_pass)
            except Exception:
                if "No local KMS vault found" in str(exc):
                    create_user_vault(email, effective_kms_pass)
                else:
                    raise HTTPException(401, "Invalid KMS Vault Passphrase") from exc
        except Exception as exc:
            raise HTTPException(401, "Invalid KMS Vault Passphrase") from exc

    # Step C: Return JWT + receiver list
    token = issue_token(email)
    receivers: list[str] = []
    try:
        all_users = client.table("app_users").select("email").execute().data or []
        receivers = [u["email"] for u in all_users if u.get("email") != email]
    except Exception:
        pass

    return {
        "status": "authenticated",
        "token": token,
        "email": email,
        "receivers": receivers,
        "public_keys": {
            "x25519_pub": user.get("x25519_pub", ""),
            "ed25519_verify_key": user.get("ed25519_verify_key", ""),
        },
    }
