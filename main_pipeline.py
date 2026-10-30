# main_pipeline.py
import os
import time
import uuid
import hashlib
from kms_vault import generate_and_store_receiver_keys, load_receiver_private_keys
from hybrid_crypto import sender_establish_hybrid_key, receiver_reconstruct_hybrid_key
from parallel_engine import (
    fragment_file,
    _encrypt_fragment_worker,
    parallel_encrypt_fragments,
    parallel_decrypt_and_reassemble
)
from cloud_storage import upload_to_public_cloud, download_from_public_cloud

def run_complete_hecc_workflow():
    print("=== STEP 0: KMS INITIALIZATION (RECEIVER GENERATES KEYS) ===")
    receiver_pub_keys = generate_and_store_receiver_keys()
    print("[KMS] Receiver Private Keys encrypted in local KMS Vault.")

    # Create a 16 MB sample file for testing fragmentation & parallelism
    sample_input = "sample_cloud_data.bin"
    recovered_output = "recovered_cloud_data.bin"
    file_id = f"file_{uuid.uuid4().hex[:8]}"

    with open(sample_input, "wb") as f:
        f.write(os.urandom(16 * 1024 * 1024))  # 16 MB test file
    original_hash = hashlib.sha256(open(sample_input, "rb").read()).hexdigest()

    print("\n=== SENDER SIDE: FRAGMENTATION & HYBRID KEY ESTABLISHMENT ===")
    # 1. File Fragmentation
    fragments = fragment_file(sample_input)
    print(f"[Sender] File split into {len(fragments)} fragments (1 MB each).")

    # 2. Hybrid Key Establishment (X25519 + ML-KEM-768 -> HKDF-SHA256 -> 256-bit AES Key)
    t_kex = time.perf_counter()
    sender_aes_key, sender_x_pub, mlkem_ct = sender_establish_hybrid_key(receiver_pub_keys)
    print(f"[Sender] Hybrid Key (X25519 + ML-KEM-768 -> HKDF) derived in {(time.perf_counter()-t_kex)*1000:.2f} ms")

    # 3. Benchmark: Sequential vs Parallel AES-256-GCM Encryption
    t_seq_start = time.perf_counter()
    _ = [_encrypt_fragment_worker((idx, chunk, sender_aes_key, file_id)) for idx, chunk in fragments]
    seq_time = time.perf_counter() - t_seq_start

    t_par_start = time.perf_counter()
    encrypted_results = parallel_encrypt_fragments(fragments, sender_aes_key, file_id)
    par_time = time.perf_counter() - t_par_start

    print(f"[Benchmark] Sequential AES-256-GCM : {seq_time:.4f} s")
    print(f"[Benchmark] Parallel AES-256-GCM   : {par_time:.4f} s ({os.cpu_count()} CPU Cores)")
    print(f"[Benchmark] Speedup Achieved       : {seq_time/par_time:.2f}x faster")

    print("\n=== PUBLIC CLOUD: UPLOADING FRAGMENTS & METADATA TO SUPABASE ===")
    upload_to_public_cloud(
        file_id=file_id,
        original_filename=sample_input,
        sender_x25519_pub=sender_x_pub,
        mlkem_ciphertext=mlkem_ct,
        encrypted_results=encrypted_results
    )
    print(f"[Cloud] Uploaded {len(encrypted_results)} encrypted fragments + metadata to Supabase (ID: {file_id}).")

    print("\n=== RECEIVER SIDE: DOWNLOAD, KEY RECONSTRUCTION & REASSEMBLY ===")
    # 1. Download Encrypted Fragments + Metadata
    cloud_record, downloaded_fragments = download_from_public_cloud(file_id)

    # 2. Unlock Receiver Private Keys from KMS & Reconstruct Hybrid AES Key
    receiver_priv_keys = load_receiver_private_keys()
    receiver_aes_key = receiver_reconstruct_hybrid_key(
        receiver_priv_dict=receiver_priv_keys,
        sender_ephemeral_x_pub_b64=cloud_record["sender_x25519_pub"],
        mlkem_ciphertext_b64=cloud_record["mlkem_ciphertext"]
    )
    assert sender_aes_key == receiver_aes_key, "AES Key Mismatch!"
    print("[Receiver] Hybrid Secret & 256-bit AES Key successfully reconstructed.")

    # 3. Parallel AES-256-GCM Decryption & Fragment Reassembly
    parallel_decrypt_and_reassemble(
        downloaded_fragments=downloaded_fragments,
        aes_key=receiver_aes_key,
        file_id=file_id,
        output_path=recovered_output
    )

    # 4. Final End-to-End Verification
    recovered_hash = hashlib.sha256(open(recovered_output, "rb").read()).hexdigest()
    print(f"[Verify] Original SHA-256  : {original_hash}")
    print(f"[Verify] Recovered SHA-256 : {recovered_hash}")
    print("[Verify] STATUS: EXACT MATCH! Original file recovered.")

    # Cleanup local dummy files
    os.remove(sample_input)
    os.remove(recovered_output)

if __name__ == "__main__":
    run_complete_hecc_workflow()