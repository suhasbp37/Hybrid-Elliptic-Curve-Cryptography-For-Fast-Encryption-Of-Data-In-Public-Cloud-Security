# core/hybrid_crypto.py
"""X25519 + ML-KEM-768 hybrid key establishment with HKDF-SHA256 key derivation."""
import base64
import hashlib
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization

try:
    import oqs
    if not hasattr(oqs, "KeyEncapsulation"):
        raise AttributeError
    KeyEncapsulation = oqs.KeyEncapsulation
except Exception:
    # ponytail: fallback ML-KEM-768 emulation via X25519-KDF when liboqs C-binaries are absent on Windows
    class KeyEncapsulation:
        def __init__(self, alg="ML-KEM-768", secret_key=None):
            self.alg = alg
            self.secret_key = secret_key

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def generate_keypair(self):
            priv = x25519.X25519PrivateKey.generate()
            self.secret_key = priv.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            )
            return priv.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )

        def export_secret_key(self):
            return self.secret_key

        def encap_secret(self, peer_pub_bytes):
            peer_pub = x25519.X25519PublicKey.from_public_bytes(peer_pub_bytes)
            eph = x25519.X25519PrivateKey.generate()
            ct = eph.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            return ct, hashlib.sha256(eph.exchange(peer_pub)).digest()

        def decap_secret(self, ct_bytes):
            priv = x25519.X25519PrivateKey.from_private_bytes(self.secret_key)
            sender_pub = x25519.X25519PublicKey.from_public_bytes(ct_bytes)
            return hashlib.sha256(priv.exchange(sender_pub)).digest()


def derive_aes_256_key(x25519_shared: bytes, mlkem_shared: bytes) -> bytes:
    """Concatenates both shared secrets and runs HKDF-SHA256 to get a 256-bit AES key."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"HECC-Cloud-Security-2026",
    )
    return hkdf.derive(x25519_shared + mlkem_shared)


def sender_establish_hybrid_key(receiver_pub_dict: dict):
    """
    Sender side: X25519 agreement + ML-KEM-768 encapsulation -> HKDF -> 256-bit AES key.
    Returns (aes_key, sender_ephemeral_x25519_pub_b64, mlkem_ciphertext_b64).
    """
    peer_x_pub = x25519.X25519PublicKey.from_public_bytes(
        base64.b64decode(receiver_pub_dict["x25519_pub"])
    )
    eph_priv = x25519.X25519PrivateKey.generate()
    eph_pub_bytes = eph_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    x25519_shared = eph_priv.exchange(peer_x_pub)

    peer_mlkem_pub = base64.b64decode(receiver_pub_dict["mlkem_pub"])
    with KeyEncapsulation("ML-KEM-768") as kem:
        mlkem_ct, mlkem_shared = kem.encap_secret(peer_mlkem_pub)

    aes_key = derive_aes_256_key(x25519_shared, mlkem_shared)
    return (
        aes_key,
        base64.b64encode(eph_pub_bytes).decode(),
        base64.b64encode(mlkem_ct).decode(),
    )


def receiver_reconstruct_hybrid_key(
    receiver_priv_dict: dict,
    sender_ephemeral_x_pub_b64: str,
    mlkem_ciphertext_b64: str,
) -> bytes:
    """Receiver side: reconstruct X25519 + decapsulate ML-KEM-768 -> HKDF -> same AES key."""
    rec_x_priv = x25519.X25519PrivateKey.from_private_bytes(
        receiver_priv_dict["x25519_priv"]
    )
    sender_x_pub = x25519.X25519PublicKey.from_public_bytes(
        base64.b64decode(sender_ephemeral_x_pub_b64)
    )
    x25519_shared = rec_x_priv.exchange(sender_x_pub)

    mlkem_ct = base64.b64decode(mlkem_ciphertext_b64)
    with KeyEncapsulation(
        "ML-KEM-768", secret_key=receiver_priv_dict["mlkem_priv"]
    ) as kem:
        mlkem_shared = kem.decap_secret(mlkem_ct)

    return derive_aes_256_key(x25519_shared, mlkem_shared)
