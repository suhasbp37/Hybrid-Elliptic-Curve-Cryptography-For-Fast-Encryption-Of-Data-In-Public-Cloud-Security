# core/kms_vault.py
"""Local KMS vault: encrypts receiver private keys at rest using Fernet (AES-128-CBC + HMAC).
Keys are stored per-receiver email so multiple receivers can coexist."""
import os
import json
import base64
import hashlib
from core.hybrid_crypto import KeyEncapsulation
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
from dotenv import load_dotenv

load_dotenv()

VAULT_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "kms_data")


def _vault_path(receiver_email: str) -> str:
    safe = receiver_email.replace("@", "_at_").replace(".", "_")
    return os.path.join(VAULT_DIR, f"{safe}.vault.enc")


def _pub_path(receiver_email: str) -> str:
    safe = receiver_email.replace("@", "_at_").replace(".", "_")
    return os.path.join(VAULT_DIR, f"{safe}.pub.json")


def _master_key() -> bytes:
    """Deterministic Fernet key from KMS_MASTER_SECRET env var."""
    secret = os.getenv("KMS_MASTER_SECRET", "default-dev-secret")
    # Fernet needs url-safe-b64 of 32 bytes
    raw = hashlib.sha256(secret.encode()).digest()
    return base64.urlsafe_b64encode(raw)


def generate_receiver_keys(receiver_email: str) -> dict:
    """Generate X25519 + ML-KEM-768 keypair; encrypt privates locally, return pub dict."""
    os.makedirs(VAULT_DIR, exist_ok=True)

    # X25519
    x_priv = x25519.X25519PrivateKey.generate()
    x_pub_bytes = x_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    x_priv_bytes = x_priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )

    # ML-KEM-768
    with KeyEncapsulation("ML-KEM-768") as kem:
        mlkem_pub = kem.generate_keypair()
        mlkem_priv = kem.export_secret_key()

    pub_dict = {
        "x25519_pub": base64.b64encode(x_pub_bytes).decode(),
        "mlkem_pub": base64.b64encode(mlkem_pub).decode(),
    }
    with open(_pub_path(receiver_email), "w") as f:
        json.dump(pub_dict, f)

    # Encrypt private keys at rest
    priv_blob = json.dumps({
        "x25519_priv": base64.b64encode(x_priv_bytes).decode(),
        "mlkem_priv": base64.b64encode(mlkem_priv).decode(),
    }).encode()
    enc = Fernet(_master_key()).encrypt(priv_blob)
    with open(_vault_path(receiver_email), "wb") as f:
        f.write(enc)

    return pub_dict


def load_receiver_public_keys(receiver_email: str) -> dict:
    path = _pub_path(receiver_email)
    if not os.path.exists(path):
        return generate_receiver_keys(receiver_email)
    with open(path) as f:
        return json.load(f)


def load_receiver_private_keys(receiver_email: str) -> dict:
    vpath = _vault_path(receiver_email)
    if not os.path.exists(vpath):
        generate_receiver_keys(receiver_email)
    dec = Fernet(_master_key()).decrypt(open(vpath, "rb").read())
    data = json.loads(dec)
    return {
        "x25519_priv": base64.b64decode(data["x25519_priv"]),
        "mlkem_priv": base64.b64decode(data["mlkem_priv"]),
    }


def receiver_keys_exist(receiver_email: str) -> bool:
    return os.path.exists(_vault_path(receiver_email))
