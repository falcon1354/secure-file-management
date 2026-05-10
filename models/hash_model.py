"""
SHA-256 Hashing Model
Provides file hashing and verification functionality
"""
import hashlib


class HashModel:
    def __init__(self, algorithm="sha256"):
        self.algorithm = algorithm

    def hash_file(self, file_path: str) -> str:
        """Generate SHA-256 hash of a file"""
        hash_obj = hashlib.new(self.algorithm)
        with open(file_path, "rb") as f:
            # Read in chunks for large files
            for chunk in iter(lambda: f.read(4096), b""):
                hash_obj.update(chunk)
        return hash_obj.hexdigest()

    def hash_data(self, data: bytes) -> str:
        """Generate SHA-256 hash of raw bytes"""
        hash_obj = hashlib.new(self.algorithm)
        hash_obj.update(data)
        return hash_obj.hexdigest()

    def verify_hash(self, data: bytes, expected_hash: str) -> bool:
        """Verify if data matches expected hash"""
        computed_hash = self.hash_data(data)
        return computed_hash == expected_hash

    def verify_file_hash(self, file_path: str, expected_hash: str) -> bool:
        """Verify if file matches expected hash"""
        computed_hash = self.hash_file(file_path)
        return computed_hash == expected_hash
