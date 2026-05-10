import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

class AESModel:
    def __init__(self, key=None):
        self.key = key if key else os.urandom(32)
        self.backend = default_backend()

    def encrypt(self, file_path):
        """Encrypt file using AES-256-CFB"""
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.key), modes.CFB(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        
        with open(file_path, "rb") as f:
            data = f.read()
        
        # Prepend IV to the encrypted data for use in decryption
        return iv + encryptor.update(data) + encryptor.finalize()

    def decrypt(self, encrypted_data):
        """Decrypt data using AES-256-CFB"""
        iv = encrypted_data[:16]
        data = encrypted_data[16:]
        cipher = Cipher(algorithms.AES(self.key), modes.CFB(iv), backend=self.backend)
        decryptor = cipher.decryptor()
        
        return decryptor.update(data) + decryptor.finalize()
