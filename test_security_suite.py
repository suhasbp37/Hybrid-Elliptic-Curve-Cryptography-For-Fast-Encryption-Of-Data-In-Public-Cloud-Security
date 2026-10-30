# test_security_suite.py
"""
Pytest security and workflow integration tests for HECC Phase 2.
Tests run entirely locally (no Supabase needed) by exercising the crypto + parallel engine directly.
"""
import os
import sys
import copy
import hashlib
import base64
import json
import pytest

# Ensure core imports work
sys.path.insert(0, os.path.dirname(__file__))

from core.kms_vault import generate_receiver_keys, load_receiver_private_keys
from core.hybrid_crypto import sender_establish_hybrid_key, receiver_reconstruct_hybrid_key
from core.parallel_engine import (
    fragment_bytes,
    parallel_encrypt_fragments,
    parallel_decrypt_and_reassemble,
    sequential_encrypt_fragments,
    compute_merkle_root,
    compute_version_chain_hash,
    pin_version,
    verify_version,
    TamperingDetectedError,
    RollbackAttackDetectedError,
    LEDGER_PATH,
)
from core.auth_acl import issue_token, verify_token, ACLError, check_download_permission


SENDER = "alice@demo.local"
RECEIVER = "bob@demo.local"
EVE = "eve@hacker.local"


@pytest.fixture(autouse=True)
def clean_ledger():
    """Remove local ledger before each test to avoid cross-test contamination."""
    if os.path.exists(LEDGER_PATH):
        os.remove(LEDGER_PATH)
    yield
    if os.path.exists(LEDGER_PATH):
        os.remove(LEDGER_PATH)


def _full_encrypt_cycle(data: bytes, file_id: str = "test_file_001", version: int = 1):
    """Helper: keygen -> hybrid key -> fragment -> parallel encrypt -> return everything needed to decrypt."""
    pub = generate_receiver_keys(RECEIVER)
    aes_key, sender_x_pub, mlkem_ct = sender_establish_hybrid_key(pub)
    frags = fragment_bytes(data)
    enc_results = parallel_encrypt_fragments(frags, aes_key, file_id, version)
    # Build download-style fragment list
    dl_frags = [
        {"index": idx, "ciphertext": ct, "tag": tag, "meta": meta}
        for idx, ct, tag, meta in enc_results
    ]
    return aes_key, sender_x_pub, mlkem_ct, enc_results, dl_frags


# ── Test 1: End-to-end parallel recovery ─────────────────────────────

def test_end_to_end_parallel_recovery():
    """Encrypt -> parallel decrypt -> verify SHA-256 matches original."""
    original = os.urandom(3 * 1024 * 1024)  # 3 MB
    orig_hash = hashlib.sha256(original).hexdigest()

    aes_key, sender_x_pub, mlkem_ct, enc_results, dl_frags = _full_encrypt_cycle(original)

    # Receiver reconstructs key
    priv = load_receiver_private_keys(RECEIVER)
    recv_key = receiver_reconstruct_hybrid_key(priv, sender_x_pub, mlkem_ct)
    assert recv_key == aes_key

    # Parallel decrypt
    recovered = parallel_decrypt_and_reassemble(dl_frags, recv_key, "test_file_001", version=1)
    assert hashlib.sha256(recovered).hexdigest() == orig_hash


# ── Test 2: Unauthorized user blocked ────────────────────────────────

def test_unauthorized_user_blocked():
    """Eve cannot access Bob's file — ACL raises PermissionError."""
    with pytest.raises(ACLError):
        check_download_permission(EVE, SENDER, RECEIVER)

    # Also verify JWT works correctly
    token = issue_token(EVE)
    assert verify_token(token) == EVE


# ── Test 3: Ciphertext tampering detected ────────────────────────────

def test_ciphertext_tampering_detected():
    """Flip 1 bit in fragment_0 ciphertext -> decryption must fail."""
    original = os.urandom(2 * 1024 * 1024)
    aes_key, _, _, _, dl_frags = _full_encrypt_cycle(original)

    # Tamper: flip one bit in first fragment's ciphertext
    tampered = dl_frags[0].copy()
    ct = bytearray(tampered["ciphertext"])
    ct[0] ^= 0x01
    tampered["ciphertext"] = bytes(ct)
    dl_frags[0] = tampered

    with pytest.raises((TamperingDetectedError, Exception)):
        parallel_decrypt_and_reassemble(dl_frags, aes_key, "test_file_001", version=1)


# ── Test 4: Chunk swap detected ──────────────────────────────────────

def test_chunk_swap_detected():
    """Swap fragment_0 and fragment_1 -> AAD mismatch must cause failure."""
    original = os.urandom(3 * 1024 * 1024)  # 3 fragments
    aes_key, _, _, _, dl_frags = _full_encrypt_cycle(original)

    assert len(dl_frags) >= 2, "Need at least 2 fragments"

    # Swap fragment 0 and 1
    dl_frags[0], dl_frags[1] = dl_frags[1], dl_frags[0]
    # Keep original indices so AAD doesn't match the swapped content
    dl_frags[0]["index"] = 0
    dl_frags[1]["index"] = 1

    with pytest.raises(Exception):  # AES-GCM InvalidTag or TamperingDetectedError
        parallel_decrypt_and_reassemble(dl_frags, aes_key, "test_file_001", version=1)


# ── Test 5: Rollback attack detected ────────────────────────────────

def test_rollback_attack_detected():
    """Upload v1, then v2. Simulate cloud serving old v1 metadata -> RollbackAttackDetectedError."""
    file_id = "rollback_test_file"

    # v1
    data_v1 = os.urandom(1024 * 1024)
    aes_key_v1, _, _, enc_v1, _ = _full_encrypt_cycle(data_v1, file_id, version=1)
    hashes_v1 = [m["sha256"] for _, _, _, m in enc_v1]
    merkle_v1 = compute_merkle_root(hashes_v1)
    chain_v1 = compute_version_chain_hash(file_id, 1, "", merkle_v1)
    pin_version(file_id, 1, chain_v1)

    # v2
    data_v2 = os.urandom(1024 * 1024)
    aes_key_v2, _, _, enc_v2, _ = _full_encrypt_cycle(data_v2, file_id, version=2)
    hashes_v2 = [m["sha256"] for _, _, _, m in enc_v2]
    merkle_v2 = compute_merkle_root(hashes_v2)
    chain_v2 = compute_version_chain_hash(file_id, 2, chain_v1, merkle_v2)
    pin_version(file_id, 2, chain_v2)

    # Simulate rollback: cloud returns v1 after v2 is pinned
    with pytest.raises(RollbackAttackDetectedError):
        verify_version(file_id, 1, chain_v1)
