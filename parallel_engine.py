# parallel_engine.py
import os
import base64
import hashlib
from concurrent.futures import ProcessPoolExecutor
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

FRAGMENT_SIZE = 1 * 1024 * 1024  # 1 MB per fragment (easy to test with 5MB-50MB files)

# --- 1. FILE FRAGMENTATION ---
def fragment_file(file_path: str):
    """Splits input file into ordered binary fragments."""
    fragments = []
    with open(file_path, "rb") as f:
        idx = 0
        while chunk := f.read(FRAGMENT_SIZE):
            fragments.append((idx, chunk))
            idx += 1
    return fragments

# --- 2. TOP-LEVEL WORKERS FOR MULTIPROCESSING ---
def _encrypt_fragment_worker(args):
    """Encrypts a single fragment on an independent CPU core using AES-256-GCM."""
    idx, plaintext_bytes, aes_key, file_id = args
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)  # Unique 96-bit nonce per fragment
    aad = f"{file_id}:fragment:{idx}".encode()  # Binds fragment order to prevent swapping

    # AESGCM.encrypt returns: ciphertext + 16-byte authentication tag at the end
    ct_with_tag = aesgcm.encrypt(nonce, plaintext_bytes, aad)
    ciphertext_only = ct_with_tag[:-16]
    auth_tag = ct_with_tag[-16:]

    sha256_hash = hashlib.sha256(ciphertext_only).hexdigest()

    metadata = {
        "index": idx,
        "nonce": base64.b64encode(nonce).decode(),
        "auth_tag": base64.b64encode(auth_tag).decode(),
        "sha256": sha256_hash
    }
    return idx, ciphertext_only, metadata

def _decrypt_fragment_worker(args):
    """Verifies authentication tag and decrypts a single fragment on an independent CPU core."""
    idx, ciphertext_only, meta, aes_key, file_id = args

    # Verify SHA-256 integrity hash
    if hashlib.sha256(ciphertext_only).hexdigest() != meta["sha256"]:
        raise ValueError(f"Integrity check failed on fragment {idx}!")

    nonce = base64.b64decode(meta["nonce"])
    auth_tag = base64.b64decode(meta["auth_tag"])
    aad = f"{file_id}:fragment:{idx}".encode()

    # Reattach auth_tag for AESGCM.decrypt verification
    aesgcm = AESGCM(aes_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext_only + auth_tag, aad)
    return idx, plaintext

# --- 3. PARALLEL CONTROLLERS ---
def parallel_encrypt_fragments(fragments, aes_key: bytes, file_id: str):
    """Runs AES-256-GCM encryption across all CPU cores in parallel."""
    tasks = [(idx, chunk, aes_key, file_id) for idx, chunk in fragments]
    with ProcessPoolExecutor(max_workers=os.cpu_count()) as executor:
        results = list(executor.map(_encrypt_fragment_worker, tasks))
    results.sort(key=lambda x: x[0])
    return results  # List of (idx, ciphertext_only, metadata_dict)

def parallel_decrypt_and_reassemble(downloaded_fragments, aes_key: bytes, file_id: str, output_path: str):
    """Decrypts fragments in parallel and reassembles them in original order."""
    tasks = [
        (item["index"], item["ciphertext"], item["meta"], aes_key, file_id)
        for item in downloaded_fragments
    ]
    with ProcessPoolExecutor(max_workers=os.cpu_count()) as executor:
        decrypted = list(executor.map(_decrypt_fragment_worker, tasks))

    # Fragment Reassembly in original order
    decrypted.sort(key=lambda x: x[0])
    with open(output_path, "wb") as f:
        for _, plaintext in decrypted:
            f.write(plaintext)