# test_icat_security_suite.py
"""
Automated Auth & ICAT KMS Security Benchmark & Test Suite.

Self-contained: in-memory mock for Supabase storage and postgres tables.
Tests:
  1. test_register_and_login_flow (valid credentials, wrong password 401, wrong KMS passphrase 401)
  2. test_unauthenticated_access_blocked_401 (/api/encrypt, /api/download blocked without JWT)
  3. test_unauthorized_user_acl_blocked_403 (Eve blocked with 403 on Bob's files and deletes)
  4. test_icat_capsule_identity_tampering_blocked (CapsuleSignatureError + AES-GCM InvalidTag)
  5. test_mitm_public_key_tampering_blocked (cloud DB substitution raises UntrustedPublicKeyError)
  6. test_end_to_end_authenticated_recovery (Alice encrypts -> Bob ICAT decrypts -> SHA256 match)
  7. test_benchmark_auth_and_icat_kms (latency table + icat_kms_benchmark.png chart)
"""
from __future__ import annotations

import base64
import copy
import hashlib
import io
import json
import os
import sys
import time

import pytest
from cryptography.exceptions import InvalidTag
from fastapi.testclient import TestClient

# Ensure workspace root is in sys.path
WORKSPACE_DIR = os.path.dirname(os.path.abspath(__file__))
if WORKSPACE_DIR not in sys.path:
    sys.path.insert(0, WORKSPACE_DIR)

from app import app
import core.cloud_storage as cs
import core.icat_kms as kms
from core.icat_kms import (
    create_user_vault,
    unlock_vault,
    create_icat_token,
    verify_icat_token,
    get_verified_receiver_public_keys,
    KMSAuthenticationError,
    CapsuleSignatureError,
    CapsuleSignatureVerificationError,
    UntrustedPublicKeyError,
)
from core.hybrid_crypto import sender_establish_hybrid_key, receiver_reconstruct_hybrid_key
from core.parallel_engine import (
    fragment_bytes,
    parallel_encrypt_fragments,
    parallel_decrypt_and_reassemble,
    _decrypt_fragment_worker,
)
from core.auth_acl import issue_token, verify_token, check_download_permission


# ── In-Memory Supabase Client Mock ───────────────────────────────────────

class _FakeTable:
    def __init__(self, store: dict, name: str):
        self._store = store
        self._name = name
        self._filters: list = []
        self._sel = "*"

    def select(self, cols="*"):
        self._sel = cols
        return self

    def eq(self, col, val):
        self._filters.append((col, val))
        return self

    def single(self):
        return self

    def upsert(self, row):
        key = row.get("email") or row.get("file_id")
        self._store[self._name][key] = copy.deepcopy(row)
        class R:
            data = row
        return self

    def insert(self, row):
        return self.upsert(row)

    def delete(self):
        class D:
            def __init__(self, table): self.table = table
            def eq(self, col, val):
                for k, v in list(self.table._store[self.table._name].items()):
                    if v.get(col) == val:
                        del self.table._store[self.table._name][k]
                class R: data = []
                return R()
        return D(self)

    def execute(self):
        class R:
            pass
        r = R()
        results = list(self._store[self._name].values())
        for col, val in self._filters:
            results = [x for x in results if x.get(col) == val]
        r.data = results[0] if (len(self._filters) and results) else results
        return r


class _FakeStorageBucket:
    def __init__(self, store: dict):
        self.store = store

    def upload(self, path, file, file_options=None):
        self.store[path] = bytes(file)
        return {"path": path}

    def download(self, path):
        if path not in self.store:
            raise Exception(f"File not found in bucket: {path}")
        return self.store[path]

    def remove(self, paths):
        for p in paths:
            self.store.pop(p, None)


class _FakeStorage:
    def __init__(self):
        self.buckets: dict[str, dict] = {}

    def from_(self, bucket_name):
        if bucket_name not in self.buckets:
            self.buckets[bucket_name] = {}
        return _FakeStorageBucket(self.buckets[bucket_name])


class _FakeClient:
    def __init__(self):
        self._store: dict[str, dict] = {
            "app_users": {},
            "user_public_keys": {},
            "files_metadata": {},
        }
        self.storage = _FakeStorage()

    def table(self, name):
        if name not in self._store:
            self._store[name] = {}
        return _FakeTable(self._store, name)


_GLOBAL_FAKE_CLIENT = _FakeClient()


@pytest.fixture(autouse=True)
def setup_mock_environment(tmp_path, monkeypatch):
    """Isolate vault files, icat tokens, and Supabase client in memory."""
    vaults_dir = str(tmp_path / "vaults")
    icat_dir = str(tmp_path / "icat_tokens")
    os.makedirs(vaults_dir, exist_ok=True)
    os.makedirs(icat_dir, exist_ok=True)

    monkeypatch.setattr(kms, "VAULT_DIR", vaults_dir)
    monkeypatch.setattr(kms, "KMS_DATA_DIR", vaults_dir)
    monkeypatch.setattr(kms, "ICAT_DIR", icat_dir)

    _GLOBAL_FAKE_CLIENT._store = {
        "app_users": {},
        "user_public_keys": {},
        "files_metadata": {},
    }
    _GLOBAL_FAKE_CLIENT.storage.buckets = {}

    monkeypatch.setattr(cs, "_get_client", lambda: _GLOBAL_FAKE_CLIENT)

    import core.auth_acl as auth_acl
    monkeypatch.setattr(auth_acl, "_get_client", lambda: _GLOBAL_FAKE_CLIENT)

    import app as app_mod
    monkeypatch.setattr(app_mod, "_get_client", lambda: _GLOBAL_FAKE_CLIENT)
    monkeypatch.setattr(app_mod, "ICAT_DIR", icat_dir)

    yield


# ── Test Credentials ─────────────────────────────────────────────────────

ALICE = "alice@demo.local"
PASS_A = "alice-secure-pass-123"
KMS_A = "alice-vault-kek-passphrase"

BOB = "bob@demo.local"
PASS_B = "bob-secure-pass-456"
KMS_B = "bob-vault-kek-passphrase"

EVE = "eve@hacker.local"
PASS_E = "eve-secure-pass-789"
KMS_E = "eve-vault-kek-passphrase"


# ═══════════════════════════════════════════════════════════════════════════
# 1. Test Register and Login Flow
# ═══════════════════════════════════════════════════════════════════════════

def test_register_and_login_flow():
    """
    Registers Alice and Bob, validates successful authentication,
    and asserts wrong password (401) and wrong KMS passphrase (401) rejection.
    """
    client = TestClient(app)

    # Register Alice
    r_reg_a = client.post("/api/auth/register", data={
        "email": ALICE,
        "account_password": PASS_A,
        "kms_passphrase": KMS_A,
    })
    assert r_reg_a.status_code == 200, r_reg_a.text
    data_a = r_reg_a.json()
    assert data_a["status"] == "registered"
    assert "token" in data_a
    assert data_a["email"] == ALICE

    # Register Bob
    r_reg_b = client.post("/api/auth/register", data={
        "email": BOB,
        "account_password": PASS_B,
        "kms_passphrase": KMS_B,
    })
    assert r_reg_b.status_code == 200
    assert "token" in r_reg_b.json()

    # Valid Login Alice
    r_login_ok = client.post("/api/auth/login", data={
        "email": ALICE,
        "account_password": PASS_A,
        "kms_passphrase": KMS_A,
    })
    assert r_login_ok.status_code == 200
    assert r_login_ok.json()["status"] == "authenticated"
    assert "token" in r_login_ok.json()

    # Invalid Account Password -> 401
    r_bad_pwd = client.post("/api/auth/login", data={
        "email": ALICE,
        "account_password": "WrongPassword999",
        "kms_passphrase": KMS_A,
    })
    assert r_bad_pwd.status_code == 401
    assert "Invalid email or password" in r_bad_pwd.json()["detail"]

    # Invalid KMS Passphrase -> 401
    r_bad_kms = client.post("/api/auth/login", data={
        "email": ALICE,
        "account_password": PASS_A,
        "kms_passphrase": "WrongKmsPassphrase!",
    })
    assert r_bad_kms.status_code == 401
    assert "Invalid KMS Vault Passphrase" in r_bad_kms.json()["detail"]


# ═══════════════════════════════════════════════════════════════════════════
# 2. Test Unauthenticated Access Blocked (401)
# ═══════════════════════════════════════════════════════════════════════════

def test_unauthenticated_access_blocked_401():
    """
    Ensures endpoints reject requests missing the JWT Bearer header.
    """
    client = TestClient(app)

    # POST /api/encrypt without Authorization -> 401
    r_enc = client.post(
        "/api/encrypt",
        files={"file": ("test.bin", b"hello", "application/octet-stream")},
        data={"receiver_email": BOB},
    )
    assert r_enc.status_code == 401
    assert "Missing Authorization" in r_enc.json()["detail"]

    # POST /api/upload without Authorization -> 401
    r_up = client.post(
        "/api/upload",
        files={"file": ("test.bin", b"hello", "application/octet-stream")},
        data={"receiver_email": BOB},
    )
    assert r_up.status_code == 401

    # GET /api/download/file_test without Authorization -> 401
    r_down = client.get("/api/download/file_test")
    assert r_down.status_code == 401


# ═══════════════════════════════════════════════════════════════════════════
# 3. Test Unauthorized User ACL Blocked (403)
# ═══════════════════════════════════════════════════════════════════════════

def test_unauthorized_user_acl_blocked_403():
    """
    Registers Eve. Eve logs in with a valid JWT but attempts to download
    or delete a file encrypted by Alice for Bob -> asserts 403 Forbidden.
    """
    client = TestClient(app)

    # 1. Register Alice, Bob, and Eve
    client.post("/api/auth/register", data={"email": ALICE, "account_password": PASS_A, "kms_passphrase": KMS_A})
    client.post("/api/auth/register", data={"email": BOB, "account_password": PASS_B, "kms_passphrase": KMS_B})
    r_eve = client.post("/api/auth/register", data={"email": EVE, "account_password": PASS_E, "kms_passphrase": KMS_E})
    eve_token = r_eve.json()["token"]

    # Alice logs in
    r_alice = client.post("/api/auth/login", data={"email": ALICE, "account_password": PASS_A, "kms_passphrase": KMS_A})
    alice_token = r_alice.json()["token"]

    # 2. Alice encrypts file for Bob
    test_content = b"Top secret data for Bob's eyes only."
    r_upload = client.post(
        "/api/upload",
        files={"file": ("secret.txt", test_content, "text/plain")},
        data={"receiver_email": BOB, "sender_passphrase": KMS_A},
        headers={"Authorization": f"Bearer {alice_token}"},
    )
    assert r_upload.status_code == 200, r_upload.text
    file_id = r_upload.json()["file_id"]

    # 3. Eve attempts to download Bob's file -> 403 Forbidden
    r_eve_down = client.get(
        f"/api/download/{file_id}",
        headers={"Authorization": f"Bearer {eve_token}"},
    )
    assert r_eve_down.status_code == 403
    assert "Forbidden" in r_eve_down.json()["detail"] or "Unauthorized" in r_eve_down.json()["detail"]

    # 4. Eve attempts to delete Alice's file -> 403 Forbidden
    r_eve_del = client.delete(
        f"/api/files/{file_id}",
        headers={"Authorization": f"Bearer {eve_token}"},
    )
    assert r_eve_del.status_code == 403
    assert "Only owner can delete" in r_eve_del.json()["detail"] or "Forbidden" in r_eve_del.json()["detail"]


# ═══════════════════════════════════════════════════════════════════════════
# 4. Test ICAT Capsule Identity Tampering Blocked
# ═══════════════════════════════════════════════════════════════════════════

def test_icat_capsule_identity_tampering_blocked():
    """
    Modifies authorized_receiver inside .icat.json from Bob to Eve.
    Asserts:
      1. CapsuleSignatureError is raised during token signature verification.
      2. If signature check is bypassed, AES-256-GCM decryption fails with InvalidTag
         due to identity-bound AAD mismatch.
    """
    client = TestClient(app)
    client.post("/api/auth/register", data={"email": ALICE, "account_password": PASS_A, "kms_passphrase": KMS_A})
    client.post("/api/auth/register", data={"email": BOB, "account_password": PASS_B, "kms_passphrase": KMS_B})
    r_alice = client.post("/api/auth/login", data={"email": ALICE, "account_password": PASS_A, "kms_passphrase": KMS_A})
    alice_token = r_alice.json()["token"]

    payload = b"Identity-bound cryptographic access capsule testing payload."
    r_up = client.post(
        "/api/upload",
        files={"file": ("vault_doc.bin", payload, "application/octet-stream")},
        data={"receiver_email": BOB, "sender_passphrase": KMS_A},
        headers={"Authorization": f"Bearer {alice_token}"},
    )
    assert r_up.status_code == 200
    token = r_up.json()["icat_token"]

    # 1. Attacker alters authorized_receiver to Eve
    tampered_token = copy.deepcopy(token)
    tampered_token["authorized_receiver"] = EVE

    # Verification must fail with CapsuleSignatureError
    with pytest.raises((CapsuleSignatureError, CapsuleSignatureVerificationError)):
        verify_icat_token(tampered_token, EVE)

    # 2. Simulate signature bypass: verify AES-GCM InvalidTag via AAD mismatch
    # Retrieve Bob's shared key and fragments
    bob_priv = unlock_vault(BOB, KMS_B)
    aes_key = receiver_reconstruct_hybrid_key(
        bob_priv,
        token["hybrid_capsule"]["sender_x25519_pub"],
        token["hybrid_capsule"]["mlkem_ciphertext"],
    )

    manifest_item = token["fragment_manifest"][0]
    raw_blob = _GLOBAL_FAKE_CLIENT.storage.from_("encrypted-fragments").download(manifest_item["storage_path"])
    ct = raw_blob[:-16]
    tag = raw_blob[-16:]

    # Attempt decryption with tampered authorized_receiver in worker args
    tampered_args = (
        manifest_item["index"],
        ct,
        tag,
        manifest_item,
        aes_key,
        token["file_id"],
        token["version"],
        ALICE,
        EVE,  # Attacker injected identity into AAD
    )
    with pytest.raises(InvalidTag):
        _decrypt_fragment_worker(tampered_args)


# ═══════════════════════════════════════════════════════════════════════════
# 5. Test MITM Public Key Tampering Blocked
# ═══════════════════════════════════════════════════════════════════════════

def test_mitm_public_key_tampering_blocked():
    """
    Simulates compromised cloud DB where Bob's mlkem_pub is swapped with Eve's
    while retaining Bob's ed25519_verify_key.
    Asserts Sender aborts key establishment with UntrustedPublicKeyError.
    """
    client = TestClient(app)
    client.post("/api/auth/register", data={"email": BOB, "account_password": PASS_B, "kms_passphrase": KMS_B})
    client.post("/api/auth/register", data={"email": EVE, "account_password": PASS_E, "kms_passphrase": KMS_E})

    # Tamper with Bob's mlkem_pub in app_users
    bob_row = _GLOBAL_FAKE_CLIENT._store["app_users"][BOB]
    eve_row = _GLOBAL_FAKE_CLIENT._store["app_users"][EVE]
    bob_row["mlkem_pub"] = eve_row["mlkem_pub"]  # Malicious substitution

    with pytest.raises(UntrustedPublicKeyError):
        get_verified_receiver_public_keys(BOB)


# ═══════════════════════════════════════════════════════════════════════════
# 6. Test End-to-End Authenticated Recovery
# ═══════════════════════════════════════════════════════════════════════════

def test_end_to_end_authenticated_recovery():
    """
    Alice encrypts 2 MB random data for Bob with ICAT KMS -> Bob ingests
    .icat.json, verifies signatures, and parallel-decrypts -> exact SHA256 match.
    """
    client = TestClient(app)

    # 1. Register & Login Alice & Bob
    client.post("/api/auth/register", data={"email": ALICE, "account_password": PASS_A, "kms_passphrase": KMS_A})
    client.post("/api/auth/register", data={"email": BOB, "account_password": PASS_B, "kms_passphrase": KMS_B})

    r_alice = client.post("/api/auth/login", data={"email": ALICE, "account_password": PASS_A, "kms_passphrase": KMS_A})
    alice_token = r_alice.json()["token"]

    r_bob = client.post("/api/auth/login", data={"email": BOB, "account_password": PASS_B, "kms_passphrase": KMS_B})
    bob_token = r_bob.json()["token"]

    # 2. Alice encrypts 2MB file
    original_data = os.urandom(2 * 1024 * 1024)
    original_hash = hashlib.sha256(original_data).hexdigest()

    r_enc = client.post(
        "/api/upload",
        files={"file": ("dataset.bin", original_data, "application/octet-stream")},
        data={"receiver_email": BOB, "sender_passphrase": KMS_A},
        headers={"Authorization": f"Bearer {alice_token}"},
    )
    assert r_enc.status_code == 200, r_enc.text
    icat_token = r_enc.json()["icat_token"]

    # 3. Bob ingests .icat.json via /api/icat/ingest-and-decrypt
    token_bytes = json.dumps(icat_token).encode("utf-8")
    r_decap = client.post(
        "/api/icat/ingest-and-decrypt",
        files={"icat_file": ("capsule.icat.json", token_bytes, "application/json")},
        data={"passphrase": KMS_B},
        headers={"Authorization": f"Bearer {bob_token}"},
    )
    assert r_decap.status_code == 200, r_decap.text
    recovered_data = r_decap.content
    recovered_hash = hashlib.sha256(recovered_data).hexdigest()

    assert original_hash == recovered_hash, "SHA-256 hash mismatch on recovered file!"


# ═══════════════════════════════════════════════════════════════════════════
# 7. Benchmark: Auth & ICAT KMS Latency + Chart Export
# ═══════════════════════════════════════════════════════════════════════════

def test_benchmark_auth_and_icat_kms():
    """
    Benchmarks latency of:
      1. Scrypt KMS Vault Unlock + AES-GCM DEK Unwrap
      2. Ed25519 Public Key & ICAT Capsule Signature Verification
      3. JWT Verification + ACL Check
      4. X25519 + ML-KEM-768 + HKDF-SHA256 Hybrid Key Reconstruction
    Prints benchmark table and saves icat_kms_benchmark.png chart.
    """
    bob_bundle = create_user_vault(BOB, KMS_B)
    create_user_vault(ALICE, KMS_A)

    # 1. Scrypt KMS Vault Unlock + AES-GCM DEK Unwrap
    t0 = time.perf_counter()
    iterations = 5
    for _ in range(iterations):
        priv = unlock_vault(BOB, KMS_B)
    unlock_latency_ms = ((time.perf_counter() - t0) / iterations) * 1000

    # 2. Ed25519 Signature Verification
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
    ed_priv = Ed25519PrivateKey.generate()
    ed_pub = ed_priv.public_key()
    msg = b"benchmark-token-payload-data"
    sig = ed_priv.sign(msg)

    t0 = time.perf_counter()
    sig_iters = 500
    for _ in range(sig_iters):
        ed_pub.verify(sig, msg)
    sig_latency_ms = ((time.perf_counter() - t0) / sig_iters) * 1000

    # 3. JWT Verification + ACL Check
    token = issue_token(ALICE)
    t0 = time.perf_counter()
    jwt_iters = 500
    for _ in range(jwt_iters):
        caller = verify_token(token)
        check_download_permission(caller, ALICE, BOB)
    jwt_latency_ms = ((time.perf_counter() - t0) / jwt_iters) * 1000

    # 4. Hybrid Key Reconstruction (X25519 + ML-KEM-768 + HKDF)
    receiver_pub = {
        "x25519_pub": bob_bundle["x25519_pub"],
        "mlkem_pub": bob_bundle["mlkem_pub"],
    }
    aes_key, sender_x_pub, mlkem_ct = sender_establish_hybrid_key(receiver_pub)

    t0 = time.perf_counter()
    hybrid_iters = 100
    for _ in range(hybrid_iters):
        _ = receiver_reconstruct_hybrid_key(priv, sender_x_pub, mlkem_ct)
    hybrid_latency_ms = ((time.perf_counter() - t0) / hybrid_iters) * 1000

    # Output Benchmark Table
    print("\n" + "=" * 70)
    print("      HECC PHASE 2 — ICAT KMS & AUTHENTICATION BENCHMARKS")
    print("=" * 70)
    print(f" {'Operation':<50} | {'Latency (ms)':<12}")
    print("-" * 70)
    print(f" {'1. Scrypt KMS Vault Unlock + DEK Unwrap':<50} | {unlock_latency_ms:>10.2f} ms")
    print(f" {'2. Ed25519 Signature Verification':<50} | {sig_latency_ms:>10.4f} ms")
    print(f" {'3. JWT Auth Verification + ACL Check':<50} | {jwt_latency_ms:>10.4f} ms")
    print(f" {'4. Hybrid Key Reconstruction (X25519+ML-KEM+HKDF)':<50} | {hybrid_latency_ms:>10.2f} ms")
    print("=" * 70)

    # Save benchmark chart
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        ops = [
            "KMS Vault Unlock\n(Scrypt+AES-GCM)",
            "Ed25519 Verify\n(Anti-MITM)",
            "JWT & ACL Check\n(HS256 Auth)",
            "Hybrid Key Reconstruct\n(X25519+ML-KEM)",
        ]
        times = [unlock_latency_ms, sig_latency_ms, jwt_latency_ms, hybrid_latency_ms]
        colors = ["#38bdf8", "#00e5a3", "#a78bfa", "#f59e0b"]

        plt.figure(figsize=(9, 5), dpi=150)
        plt.style.use("dark_background")
        bars = plt.bar(ops, times, color=colors, width=0.55, edgecolor="#1e293b", linewidth=1.2)
        plt.title("HECC Phase 2 — ICAT KMS & Auth Latency Benchmark", fontsize=13, fontweight="bold", pad=15, color="#f1f5f9")
        plt.ylabel("Execution Latency (milliseconds)", fontsize=11, color="#94a3b8")
        plt.grid(axis="y", linestyle="--", alpha=0.3, color="#334155")

        for bar in bars:
            yval = bar.get_height()
            plt.text(bar.get_x() + bar.get_width()/2.0, yval + (max(times)*0.02), f"{yval:.2f} ms", ha="center", va="bottom", fontsize=9.5, fontweight="600", color="#f8fafc")

        plt.tight_layout()
        chart_path = os.path.join(WORKSPACE_DIR, "icat_kms_benchmark.png")
        plt.savefig(chart_path)
        plt.close()
        print(f"[Chart] Saved benchmark chart: {chart_path}")
        assert os.path.exists(chart_path)
    except Exception as e:
        print(f"[Chart Warning] Could not save chart: {e}")


def test_email_validation_and_claim_flow():
    """
    1. Validates that malformed emails are rejected with 400.
    2. Validates that when a sender encrypts for an unregistered recipient,
       the recipient can subsequently register to claim their account, set their password,
       and sign in without getting blocked.
    """
    client = TestClient(app)

    # 1. Email format rejection
    r_bad_email = client.post("/api/auth/register", data={
        "email": "not-an-email",
        "account_password": "Pass12345Password",
        "kms_passphrase": "KmsPassphrase123",
    })
    assert r_bad_email.status_code == 400
    assert "username@mail.com" in r_bad_email.json()["detail"]

    # 2. Register Alice
    client.post("/api/auth/register", data={
        "email": ALICE,
        "account_password": PASS_A,
        "kms_passphrase": KMS_A,
    })
    r_login_a = client.post("/api/auth/login", data={
        "email": ALICE,
        "account_password": PASS_A,
        "kms_passphrase": KMS_A,
    })
    alice_token = r_login_a.json()["token"]

    # 3. Alice encrypts file for an unregistered recipient
    NEW_USER = "newcolleague@demo.local"
    r_enc = client.post(
        "/api/upload",
        files={"file": ("colleague_notes.txt", b"Confidential memo for new colleague", "text/plain")},
        data={"receiver_email": NEW_USER, "sender_passphrase": KMS_A},
        headers={"Authorization": f"Bearer {alice_token}"},
    )
    assert r_enc.status_code == 200, r_enc.text

    # 4. New user registers to claim their account with their own password
    NEW_PASS = "MyNewPassword123!"
    NEW_KMS = "MyNewKmsPassphrase!"
    r_claim = client.post("/api/auth/register", data={
        "email": NEW_USER,
        "account_password": NEW_PASS,
        "kms_passphrase": NEW_KMS,
    })
    assert r_claim.status_code == 200, r_claim.text
    assert r_claim.json()["status"] == "registered"

    # 5. New user signs in with their chosen password
    r_login_new = client.post("/api/auth/login", data={
        "email": NEW_USER,
        "account_password": NEW_PASS,
        "kms_passphrase": NEW_KMS,
    })
    assert r_login_new.status_code == 200
    assert r_login_new.json()["status"] == "authenticated"

