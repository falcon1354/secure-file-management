from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

class RSAModel:
    def __init__(self):
        self.backend = default_backend()

    def generate_keys(self):
        """Generate RSA key pair for the session"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=self.backend
        )
        public_key = private_key.public_key()
        return public_key, private_key

    def encrypt_key(self, aes_key, public_key):
        """Encrypt symmetric key with RSA public key"""
        return public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    def decrypt_key(self, encrypted_aes_key, private_key):
        """Decrypt symmetric key with RSA private key"""
        return private_key.decrypt(
            encrypted_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
