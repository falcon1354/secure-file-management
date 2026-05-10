"""
Database Model for PKI
Uses MySQL to store certificates, users, and file metadata
"""
import mysql.connector
from mysql.connector import Error
import os
from datetime import datetime


class DatabaseModel:
    def __init__(self):
        self.config = {
            'host': os.environ.get('MYSQL_HOST', 'localhost'),
            'database': os.environ.get('MYSQL_DATABASE', 'secure_file_db'),
            'user': os.environ.get('MYSQL_USER', 'root'),
            'password': os.environ.get('MYSQL_PASSWORD', ''),
            'port': int(os.environ.get('MYSQL_PORT', 3306))
        }
        self.connection = None

    def connect(self):
        """Establish database connection"""
        try:
            self.connection = mysql.connector.connect(**self.config)
            if self.connection.is_connected():
                return True
        except Error as e:
            print(f"Database connection error: {e}")
            return False

    def disconnect(self):
        """Close database connection"""
        if self.connection and self.connection.is_connected():
            self.connection.close()

    def initialize_database(self):
        """Create necessary tables for PKI"""
        if not self.connect():
            return False

        cursor = self.connection.cursor()

        # Users table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                email VARCHAR(255) UNIQUE NOT NULL,
                name VARCHAR(255) NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
            )
        """)

        # Certificates table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS certificates (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                serial_number VARCHAR(255) UNIQUE NOT NULL,
                fingerprint VARCHAR(255) NOT NULL,
                subject VARCHAR(512) NOT NULL,
                issuer VARCHAR(512) NOT NULL,
                not_valid_before DATETIME NOT NULL,
                not_valid_after DATETIME NOT NULL,
                cert_path VARCHAR(512) NOT NULL,
                key_path VARCHAR(512) NOT NULL,
                status ENUM('active', 'revoked', 'expired') DEFAULT 'active',
                revoked_at TIMESTAMP NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)

        # Files table (for tracking encrypted files with hashes)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS encrypted_files (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                original_filename VARCHAR(255) NOT NULL,
                encrypted_filename VARCHAR(255) NOT NULL,
                original_hash VARCHAR(64) NOT NULL,
                encrypted_hash VARCHAR(64) NOT NULL,
                file_size BIGINT NOT NULL,
                encryption_algorithm VARCHAR(50) DEFAULT 'AES-256-CFB',
                signature BLOB NULL,
                certificate_id INT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (certificate_id) REFERENCES certificates(id) ON DELETE SET NULL
            )
        """)

        # Certificate Revocation List (CRL)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS certificate_revocations (
                id INT AUTO_INCREMENT PRIMARY KEY,
                certificate_id INT NOT NULL,
                serial_number VARCHAR(255) NOT NULL,
                revocation_reason VARCHAR(255),
                revoked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (certificate_id) REFERENCES certificates(id) ON DELETE CASCADE
            )
        """)

        # Audit log for tracking all operations
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT,
                action VARCHAR(100) NOT NULL,
                resource_type VARCHAR(50),
                resource_id INT,
                details TEXT,
                ip_address VARCHAR(45),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
            )
        """)

        self.connection.commit()
        cursor.close()
        self.disconnect()
        return True

    # ==================== USER OPERATIONS ====================

    def create_user(self, email: str, name: str, password_hash: str) -> int:
        """Create a new user and return user ID"""
        if not self.connect():
            return None

        cursor = self.connection.cursor()
        try:
            cursor.execute(
                "INSERT INTO users (email, name, password_hash) VALUES (%s, %s, %s)",
                (email, name, password_hash)
            )
            self.connection.commit()
            user_id = cursor.lastrowid
            return user_id
        except Error as e:
            print(f"Error creating user: {e}")
            return None
        finally:
            cursor.close()
            self.disconnect()

    def get_user_by_email(self, email: str) -> dict:
        """Get user by email"""
        if not self.connect():
            return None

        cursor = self.connection.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
        cursor.close()
        self.disconnect()
        return user

    def get_user_by_id(self, user_id: int) -> dict:
        """Get user by ID"""
        if not self.connect():
            return None

        cursor = self.connection.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        user = cursor.fetchone()
        cursor.close()
        self.disconnect()
        return user

    # ==================== CERTIFICATE OPERATIONS ====================

    def store_certificate(self, user_id: int, cert_info: dict) -> int:
        """Store certificate information in database"""
        if not self.connect():
            return None

        cursor = self.connection.cursor()
        try:
            cursor.execute("""
                INSERT INTO certificates 
                (user_id, serial_number, fingerprint, subject, issuer, 
                 not_valid_before, not_valid_after, cert_path, key_path)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                user_id,
                cert_info['serial_number'],
                cert_info['fingerprint'],
                cert_info.get('subject', ''),
                cert_info.get('issuer', 'SecureFile CA'),
                cert_info['not_valid_before'],
                cert_info['not_valid_after'],
                cert_info['cert_path'],
                cert_info['key_path']
            ))
            self.connection.commit()
            return cursor.lastrowid
        except Error as e:
            print(f"Error storing certificate: {e}")
            return None
        finally:
            cursor.close()
            self.disconnect()

    def get_user_certificates(self, user_id: int) -> list:
        """Get all certificates for a user"""
        if not self.connect():
            return []

        cursor = self.connection.cursor(dictionary=True)
        cursor.execute(
            "SELECT * FROM certificates WHERE user_id = %s ORDER BY created_at DESC",
            (user_id,)
        )
        certs = cursor.fetchall()
        cursor.close()
        self.disconnect()
        return certs

    def get_certificate_by_id(self, cert_id: int) -> dict:
        """Get certificate by ID"""
        if not self.connect():
            return None

        cursor = self.connection.cursor(dictionary=True)
        cursor.execute("SELECT * FROM certificates WHERE id = %s", (cert_id,))
        cert = cursor.fetchone()
        cursor.close()
        self.disconnect()
        return cert

    def get_active_certificate(self, user_id: int) -> dict:
        """Get user's active (non-revoked, non-expired) certificate"""
        if not self.connect():
            return None

        cursor = self.connection.cursor(dictionary=True)
        cursor.execute("""
            SELECT * FROM certificates 
            WHERE user_id = %s AND status = 'active' AND not_valid_after > NOW()
            ORDER BY created_at DESC LIMIT 1
        """, (user_id,))
        cert = cursor.fetchone()
        cursor.close()
        self.disconnect()
        return cert

    def revoke_certificate(self, cert_id: int, reason: str = "User requested") -> bool:
        """Revoke a certificate"""
        if not self.connect():
            return False

        cursor = self.connection.cursor()
        try:
            # Update certificate status
            cursor.execute(
                "UPDATE certificates SET status = 'revoked', revoked_at = NOW() WHERE id = %s",
                (cert_id,)
            )

            # Get serial number
            cursor.execute("SELECT serial_number FROM certificates WHERE id = %s", (cert_id,))
            result = cursor.fetchone()

            # Add to CRL
            if result:
                cursor.execute("""
                    INSERT INTO certificate_revocations (certificate_id, serial_number, revocation_reason)
                    VALUES (%s, %s, %s)
                """, (cert_id, result[0], reason))

            self.connection.commit()
            return True
        except Error as e:
            print(f"Error revoking certificate: {e}")
            return False
        finally:
            cursor.close()
            self.disconnect()

    def is_certificate_revoked(self, serial_number: str) -> bool:
        """Check if a certificate is in the revocation list"""
        if not self.connect():
            return True  # Fail safe

        cursor = self.connection.cursor()
        cursor.execute(
            "SELECT id FROM certificate_revocations WHERE serial_number = %s",
            (serial_number,)
        )
        result = cursor.fetchone()
        cursor.close()
        self.disconnect()
        return result is not None

    # ==================== FILE OPERATIONS ====================

    def store_encrypted_file(self, user_id: int, file_info: dict) -> int:
        """Store encrypted file metadata"""
        if not self.connect():
            return None

        cursor = self.connection.cursor()
        try:
            cursor.execute("""
                INSERT INTO encrypted_files 
                (user_id, original_filename, encrypted_filename, original_hash, 
                 encrypted_hash, file_size, signature, certificate_id)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                user_id,
                file_info['original_filename'],
                file_info['encrypted_filename'],
                file_info['original_hash'],
                file_info['encrypted_hash'],
                file_info['file_size'],
                file_info.get('signature'),
                file_info.get('certificate_id')
            ))
            self.connection.commit()
            return cursor.lastrowid
        except Error as e:
            print(f"Error storing file info: {e}")
            return None
        finally:
            cursor.close()
            self.disconnect()

    def get_user_files(self, user_id: int) -> list:
        """Get all encrypted files for a user"""
        if not self.connect():
            return []

        cursor = self.connection.cursor(dictionary=True)
        cursor.execute(
            "SELECT * FROM encrypted_files WHERE user_id = %s ORDER BY created_at DESC",
            (user_id,)
        )
        files = cursor.fetchall()
        cursor.close()
        self.disconnect()
        return files

    def get_file_by_name(self, encrypted_filename: str) -> dict:
        """Get file info by encrypted filename"""
        if not self.connect():
            return None

        cursor = self.connection.cursor(dictionary=True)
        cursor.execute(
            "SELECT * FROM encrypted_files WHERE encrypted_filename = %s",
            (encrypted_filename,)
        )
        file_info = cursor.fetchone()
        cursor.close()
        self.disconnect()
        return file_info

    # ==================== AUDIT OPERATIONS ====================

    def log_action(self, user_id: int, action: str, resource_type: str = None,
                   resource_id: int = None, details: str = None, ip_address: str = None):
        """Log an action for audit trail"""
        if not self.connect():
            return

        cursor = self.connection.cursor()
        try:
            cursor.execute("""
                INSERT INTO audit_log (user_id, action, resource_type, resource_id, details, ip_address)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (user_id, action, resource_type, resource_id, details, ip_address))
            self.connection.commit()
        except Error as e:
            print(f"Error logging action: {e}")
        finally:
            cursor.close()
            self.disconnect()

    def get_audit_log(self, user_id: int = None, limit: int = 100) -> list:
        """Get audit log entries"""
        if not self.connect():
            return []

        cursor = self.connection.cursor(dictionary=True)
        if user_id:
            cursor.execute(
                "SELECT * FROM audit_log WHERE user_id = %s ORDER BY created_at DESC LIMIT %s",
                (user_id, limit)
            )
        else:
            cursor.execute(
                "SELECT * FROM audit_log ORDER BY created_at DESC LIMIT %s",
                (limit,)
            )
        logs = cursor.fetchall()
        cursor.close()
        self.disconnect()
        return logs
