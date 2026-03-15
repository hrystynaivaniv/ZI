from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.exceptions import InvalidSignature


def generate_dsa_keys(key_size=2048):
    private_key = dsa.generate_private_key(key_size=key_size)
    public_key = private_key.public_key()

    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return priv_pem, pub_pem


def dsa_sign_file(data: bytes, priv_pem: bytes) -> bytes:
    private_key = serialization.load_pem_private_key(priv_pem, password=None)

    chosen_hash = hashes.SHA256()
    hasher = hashes.Hash(chosen_hash)
    hasher.update(data)
    digest = hasher.finalize()

    signature = private_key.sign(
        digest,
        utils.Prehashed(chosen_hash)
    )
    return signature


def dsa_verify_file(data: bytes, signature: bytes, pub_pem: bytes) -> bool:
    public_key = serialization.load_pem_public_key(pub_pem)

    chosen_hash = hashes.SHA256()
    hasher = hashes.Hash(chosen_hash)
    hasher.update(data)
    digest = hasher.finalize()

    try:
        public_key.verify(
            signature,
            digest,
            utils.Prehashed(chosen_hash)
        )
        return True
    except InvalidSignature:
        return False