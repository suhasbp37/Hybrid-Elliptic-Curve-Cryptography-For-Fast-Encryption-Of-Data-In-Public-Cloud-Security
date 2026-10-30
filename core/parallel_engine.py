# core/parallel_engine.py
"""
Parallel AES-256-GCM encryption/decryption engine.
ALL worker functions are defined at module top-level so Windows `spawn` multiprocessing works.
"""
import os
import base64
import hashlib
import json
from concurrent.futures import ProcessPoolExecutor
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

FRAGMENT_SIZE = 1 * 1024 * 1024  # 1 MB


class TamperingDetectedError(Exception):
    pass


class RollbackAttackDetectedError(Exception):
    pass


# ── Version hash-chain helpers ──────────────────────────────────────────

LEDGER_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "local_version_ledger.json")


def _load_ledger() -> dict:
    if os.path.exists(LEDGER_PATH):
        with open(LEDGER_PATH) as f:
            return json.load(f)
    return {}


def _save_ledger(ledger: dict):
    with open(LEDGER_PATH, "w") as f:
        json.dump(ledger, f, indent=2)


def compute_merkle_root(hashes: list[str]) -> str:
    """Simple binary Merkle tree of SHA-256 hex strings."""
    if not hashes:
        return hashlib.sha256(b"").hexdigest()
    layer = [bytes.fromhex(h) for h in hashes]
    while len(layer) > 1:
        nxt = []
        for i in range(0, len(layer), 2):
            if i + 1 < len(layer):
                nxt.append(hashlib.sha256(layer[i] + layer[i + 1]).digest())
            else:
                nxt.append(layer[i])  # odd node promoted
        layer = nxt
    return layer[0].hex()


def compute_version_chain_hash(file_id: str, version: int, prev_hash: str, merkle_root: str) -> str:
    return hashlib.sha256(f"{file_id}|{version}|{prev_hash}|{merkle_root}".encode()).hexdigest()


def pin_version(file_id: str, version: int, chain_hash: str):
    ledger = _load_ledger()
    ledger[file_id] = {"latest_version": version, "version_chain_hash": chain_hash}
    _save_ledger(ledger)


def verify_version(file_id: str, version: int, chain_hash: str):
    ledger = _load_ledger()
    if file_id not in ledger:
        return  # first time seeing this file
    entry = ledger[file_id]
    if version < entry["latest_version"]:
        raise RollbackAttackDetectedError(
            f"Cloud version {version} < local pinned {entry['latest_version']}"
        )
    if version == entry["latest_version"] and chain_hash != entry["version_chain_hash"]:
        raise RollbackAttackDetectedError(
            f"Version chain hash mismatch for v{version}"
        )


# ── File fragmentation ──────────────────────────────────────────────────

def fragment_file(file_path: str) -> list[tuple[int, bytes]]:
    """Splits file into ordered 1 MB fragments."""
    fragments = []
    with open(file_path, "rb") as f:
        idx = 0
        while chunk := f.read(FRAGMENT_SIZE):
            fragments.append((idx, chunk))
            idx += 1
    return fragments


def fragment_bytes(data: bytes) -> list[tuple[int, bytes]]:
    """Splits raw bytes into ordered 1 MB fragments."""
    fragments = []
    for idx in range(0, len(data), FRAGMENT_SIZE):
        fragments.append((idx // FRAGMENT_SIZE, data[idx : idx + FRAGMENT_SIZE]))
    return fragments


def _encrypt_fragment_worker(args):
    """Encrypts one fragment with AES-256-GCM. AAD binds file_id, version, index, and optional identity."""
    idx, plaintext, aes_key, file_id, version = args[:5]
    owner_email = args[5] if len(args) > 5 else None
    authorized_receiver = args[6] if len(args) > 6 else None

    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)
    if owner_email and authorized_receiver:
        aad = f"{file_id}:v:{version}:chunk:{idx}:owner:{owner_email}:rec:{authorized_receiver}".encode()
    else:
        aad = f"{file_id}:v:{version}:chunk:{idx}".encode()

    ct_tag = aesgcm.encrypt(nonce, plaintext, aad)
    ciphertext = ct_tag[:-16]
    tag = ct_tag[-16:]
    sha = hashlib.sha256(ct_tag).hexdigest()  # hash full ciphertext+tag blob
    meta = {
        "index": idx,
        "nonce": base64.b64encode(nonce).decode(),
        "auth_tag": base64.b64encode(tag).decode(),
        "sha256": sha,
    }
    return idx, ciphertext, tag, meta


def _decrypt_fragment_worker(args):
    """Verifies integrity and decrypts one fragment."""
    idx, ciphertext, tag, meta, aes_key, file_id, version = args[:7]
    owner_email = args[7] if len(args) > 7 else None
    authorized_receiver = args[8] if len(args) > 8 else None

    ct_tag = ciphertext + tag
    if hashlib.sha256(ct_tag).hexdigest() != meta["sha256"]:
        raise TamperingDetectedError(f"SHA-256 mismatch on fragment {idx}")
    nonce = base64.b64decode(meta["nonce"])
    if owner_email and authorized_receiver:
        aad = f"{file_id}:v:{version}:chunk:{idx}:owner:{owner_email}:rec:{authorized_receiver}".encode()
    else:
        aad = f"{file_id}:v:{version}:chunk:{idx}".encode()

    aesgcm = AESGCM(aes_key)
    plaintext = aesgcm.decrypt(nonce, ct_tag, aad)
    return idx, plaintext


# ── Sequential helpers (for benchmarking) ────────────────────────────────

def sequential_encrypt_fragments(
    fragments, aes_key: bytes, file_id: str, version: int = 1,
    owner_email: str | None = None, authorized_receiver: str | None = None
):
    return [
        _encrypt_fragment_worker((idx, chunk, aes_key, file_id, version, owner_email, authorized_receiver))
        for idx, chunk in fragments
    ]


def sequential_decrypt_fragments(
    enc_results, aes_key: bytes, file_id: str, version: int = 1,
    owner_email: str | None = None, authorized_receiver: str | None = None
):
    return [
        _decrypt_fragment_worker((idx, ct, tag, meta, aes_key, file_id, version, owner_email, authorized_receiver))
        for idx, ct, tag, meta in enc_results
    ]


# ── Parallel controllers ────────────────────────────────────────────────

def parallel_encrypt_fragments(
    fragments, aes_key: bytes, file_id: str, version: int = 1,
    owner_email: str | None = None, authorized_receiver: str | None = None
):
    """Parallel AES-256-GCM encryption across CPU cores."""
    tasks = [
        (idx, chunk, aes_key, file_id, version, owner_email, authorized_receiver)
        for idx, chunk in fragments
    ]
    with ProcessPoolExecutor(max_workers=os.cpu_count()) as exe:
        results = list(exe.map(_encrypt_fragment_worker, tasks))
    results.sort(key=lambda x: x[0])
    return results


def parallel_decrypt_and_reassemble(
    downloaded_fragments: list, aes_key: bytes, file_id: str, version: int = 1,
    owner_email: str | None = None, authorized_receiver: str | None = None
) -> bytes:
    """Decrypts fragments in parallel, returns reassembled bytes."""
    tasks = [
        (
            item["index"],
            item["ciphertext"],
            item["tag"],
            item["meta"],
            aes_key,
            file_id,
            version,
            owner_email,
            authorized_receiver,
        )
        for item in downloaded_fragments
    ]
    with ProcessPoolExecutor(max_workers=os.cpu_count()) as exe:
        decrypted = list(exe.map(_decrypt_fragment_worker, tasks))
    decrypted.sort(key=lambda x: x[0])
    return b"".join(pt for _, pt in decrypted)
