"""
PKI (Public Key Infrastructure) Model
Handles digital certificates, CA operations, and certificate management
"""
import os
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend


class PKIModel:
    def __init__(self, ca_cert_path="certs/ca_cert.pem", ca_key_path="certs/ca_key.pem"):
        self.ca_cert_path = ca_cert_path
        self.ca_key_path = ca_key_path
        self.certs_dir = "certs"
        os.makedirs(self.certs_dir, exist_ok=True)

    def generate_ca_certificate(self, common_name="SecureFile CA", 
                                 organization="SecureFile Inc",
                                 country="US",
                                 validity_days=3650):
        """Generate a self-signed CA certificate"""
        # Generate CA private key
        ca_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
            backend=default_backend()
        )

        # Build CA certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, country),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])

        ca_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(ca_private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=validity_days))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(ca_private_key, hashes.SHA256(), default_backend())
        )

        # Save CA certificate and private key
        with open(self.ca_cert_path, "wb") as f:
            f.write(ca_cert.public_bytes(serialization.Encoding.PEM))

        with open(self.ca_key_path, "wb") as f:
            f.write(ca_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))

        return ca_cert, ca_private_key

    def load_ca(self):
        """Load existing CA certificate and private key"""
        if not os.path.exists(self.ca_cert_path) or not os.path.exists(self.ca_key_path):
            return self.generate_ca_certificate()

        with open(self.ca_cert_path, "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())

        with open(self.ca_key_path, "rb") as f:
            ca_private_key = serialization.load_pem_private_key(
                f.read(), password=None, backend=default_backend()
            )

        return ca_cert, ca_private_key

    def generate_user_certificate(self, user_id: int, email: str, common_name: str,
                                   organization: str = "SecureFile User",
                                   validity_days: int = 365):
        """Generate a user certificate signed by the CA"""
        # Load CA
        ca_cert, ca_private_key = self.load_ca()

        # Generate user private key
        user_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        # Build user certificate
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            x509.NameAttribute(NameOID.EMAIL_ADDRESS, email),
        ])

        user_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_cert.subject)
            .public_key(user_private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=validity_days))
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=True,
                    key_encipherment=True,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([
                    ExtendedKeyUsageOID.CLIENT_AUTH,
                    ExtendedKeyUsageOID.EMAIL_PROTECTION,
                ]),
                critical=False,
            )
            .sign(ca_private_key, hashes.SHA256(), default_backend())
        )

        # Save user certificate and key
        user_cert_path = os.path.join(self.certs_dir, f"user_{user_id}_cert.pem")
        user_key_path = os.path.join(self.certs_dir, f"user_{user_id}_key.pem")

        with open(user_cert_path, "wb") as f:
            f.write(user_cert.public_bytes(serialization.Encoding.PEM))

        with open(user_key_path, "wb") as f:
            f.write(user_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))

        return {
            "certificate": user_cert,
            "private_key": user_private_key,
            "cert_path": user_cert_path,
            "key_path": user_key_path,
            "serial_number": str(user_cert.serial_number),
            "fingerprint": user_cert.fingerprint(hashes.SHA256()).hex(),
            "not_valid_before": user_cert.not_valid_before_utc.isoformat(),
            "not_valid_after": user_cert.not_valid_after_utc.isoformat(),
        }

    def verify_certificate(self, cert_path: str) -> dict:
        """Verify a certificate against the CA"""
        ca_cert, _ = self.load_ca()

        with open(cert_path, "rb") as f:
            user_cert = x509.load_pem_x509_certificate(f.read(), default_backend())

        result = {
            "valid": False,
            "subject": None,
            "issuer": None,
            "serial_number": None,
            "not_valid_before": None,
            "not_valid_after": None,
            "is_expired": False,
            "error": None
        }

        try:
            # Check if certificate is signed by our CA
            ca_cert.public_key().verify(
                user_cert.signature,
                user_cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                user_cert.signature_hash_algorithm,
            )

            # Check validity period
            now = datetime.datetime.utcnow()
            is_expired = now > user_cert.not_valid_after_utc.replace(tzinfo=None)

            result.update({
                "valid": not is_expired,
                "subject": user_cert.subject.rfc4514_string(),
                "issuer": user_cert.issuer.rfc4514_string(),
                "serial_number": str(user_cert.serial_number),
                "not_valid_before": user_cert.not_valid_before_utc.isoformat(),
                "not_valid_after": user_cert.not_valid_after_utc.isoformat(),
                "is_expired": is_expired,
                "fingerprint": user_cert.fingerprint(hashes.SHA256()).hex(),
            })

        except Exception as e:
            result["error"] = str(e)

        return result

    def sign_data(self, data: bytes, private_key_path: str) -> bytes:
        """Sign data using a private key (digital signature)"""
        with open(private_key_path, "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(), password=None, backend=default_backend()
            )

        signature = private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature

    def verify_signature(self, data: bytes, signature: bytes, cert_path: str) -> bool:
        """Verify a digital signature using the certificate's public key"""
        with open(cert_path, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())

        try:
            cert.public_key().verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False

    def get_certificate_info(self, cert_path: str) -> dict:
        """Get detailed information about a certificate"""
        with open(cert_path, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())

        # Extract subject attributes
        subject_attrs = {}
        for attr in cert.subject:
            subject_attrs[attr.oid._name] = attr.value

        return {
            "subject": subject_attrs,
            "issuer": cert.issuer.rfc4514_string(),
            "serial_number": str(cert.serial_number),
            "not_valid_before": cert.not_valid_before_utc.isoformat(),
            "not_valid_after": cert.not_valid_after_utc.isoformat(),
            "fingerprint_sha256": cert.fingerprint(hashes.SHA256()).hex(),
            "public_key_algorithm": cert.public_key().__class__.__name__,
            "signature_algorithm": cert.signature_algorithm_oid._name,
        }
