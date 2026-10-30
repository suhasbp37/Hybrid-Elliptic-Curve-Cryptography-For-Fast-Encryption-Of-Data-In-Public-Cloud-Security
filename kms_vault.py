# kms_vault.py
import os
import json
import base64
import oqs
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization

KMS_MASTER_KEY_FILE = "kms_master.key"
VAULT_PRIVATE_FILE = "vault_receiver_private.enc"
PUBLIC_KEYS_FILE = "receiver_public_keys.json"

def get_or_create_kms_key() -> bytes:
    """Generates or loads the local KMS Master Wrapping Key."""
    if not os.path.exists(KMS_MASTER_KEY_FILE):
        key = Fernet.generate_key()
        with open(KMS_MASTER_KEY_FILE, "wb") as f:
            f.write(key)
    with open(KMS_MASTER_KEY_FILE, "rb") as f:
        return f.read()

def generate_and_store_receiver_keys():
    """Generates X25519 + ML-KEM-768 keys. Stores private keys encrypted in KMS."""
    # 1. Classical X25519 Key Pair
    x_priv = x25519.X25519PrivateKey.generate()
    x_pub_bytes = x_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    x_priv_bytes = x_priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )

    # 2. Post-Quantum ML-KEM-768 Key Pair
    with oqs.KeyEncapsulation("ML-KEM-768") as kem:
        mlkem_pub_bytes = kem.generate_keypair()
        mlkem_priv_bytes = kem.export_secret_key()

    # 3. Save Public Keys openly for Sender
    public_data = {
        "x25519_pub": base64.b64encode(x_pub_bytes).decode(),
        "mlkem_pub": base64.b64encode(mlkem_pub_bytes).decode()
    }
    with open(PUBLIC_KEYS_FILE, "w") as f:
        json.dump(public_data, f, indent=2)

    # 4. Encrypt Private Keys inside KMS Vault (Never uploaded to public cloud!)
    private_data = json.dumps({
        "x25519_priv": base64.b64encode(x_priv_bytes).decode(),
        "mlkem_priv": base64.b64encode(mlkem_priv_bytes).decode()
    }).encode()

    fernet = Fernet(get_or_create_kms_key())
    encrypted_vault = fernet.encrypt(private_data)
    with open(VAULT_PRIVATE_FILE, "wb") as f:
        f.write(encrypted_vault)

    return public_data

def load_receiver_private_keys() -> dict:
    """Unlocks and retrieves Receiver Private Keys from the KMS Vault."""
    fernet = Fernet(get_or_create_kms_key())
    with open(VAULT_PRIVATE_FILE, "rb") as f:
        decrypted_bytes = fernet.decrypt(f.read())
    data = json.loads(decrypted_bytes.decode())
    return {
        "x25519_priv": base64.b64decode(data["x25519_priv"]),
        "mlkem_priv": base64.b64decode(data["mlkem_priv"])
    }