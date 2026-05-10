"""
File Controller
Handles file upload, encryption, decryption with hashing and PKI
"""
import os
from flask import flash, render_template, request, redirect, url_for, session
from models.aes_model import AESModel
from models.rsa_model import RSAModel
from models.hash_model import HashModel
from models.pki_model import PKIModel
from models.database import DatabaseModel

UPLOAD_FOLDER = "uploads"
ENCRYPTED_FOLDER = "encrypted"
PROCESSED_FOLDER = "processed"

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(ENCRYPTED_FOLDER, exist_ok=True)
os.makedirs(PROCESSED_FOLDER, exist_ok=True)

# Initialize models
rsa_model = RSAModel()
hash_model = HashModel()
pki_model = PKIModel()
db = DatabaseModel()

# Generate RSA keys for session
public_key, private_key = rsa_model.generate_keys()


def upload_and_encrypt():
    """
    Enhanced workflow with hashing:
    Upload → Hash (SHA-256) → Encrypt (AES) → Encrypt AES Key (RSA) → 
    Sign with Certificate → Store
    """
    if "file" not in request.files:
        flash("No file uploaded", "error")
        return redirect(url_for("index"))

    file = request.files["file"]
    if file.filename == "":
        flash("No selected file", "error")
        return redirect(url_for("index"))

    # Get user ID from session (default to 1 for demo)
    user_id = session.get('user_id', 1)

    # Save uploaded file
    file_path = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(file_path)

    try:
        # Step 1: Generate SHA-256 hash of original file
        original_hash = hash_model.hash_file(file_path)

        # Step 2: Generate random AES key and encrypt file
        aes_key = os.urandom(32)
        aes_model = AESModel(key=aes_key)
        encrypted_data = aes_model.encrypt(file_path)

        # Step 3: Save encrypted file
        encrypted_filename = f"encrypted_{file.filename}"
        encrypted_file_path = os.path.join(ENCRYPTED_FOLDER, encrypted_filename)
        with open(encrypted_file_path, "wb") as enc_file:
            enc_file.write(encrypted_data)

        # Step 4: Encrypt AES key with RSA
        encrypted_aes_key = rsa_model.encrypt_key(aes_key, public_key)
        encrypted_key_path = os.path.join(ENCRYPTED_FOLDER, f"{file.filename}_key.bin")
        with open(encrypted_key_path, "wb") as key_file:
            key_file.write(encrypted_aes_key)

        # Step 5: Store hash for verification
        hash_file_path = os.path.join(ENCRYPTED_FOLDER, f"{file.filename}_hash.txt")
        with open(hash_file_path, "w") as hash_file:
            hash_file.write(original_hash)

        # Step 6: Digital signature (if user has certificate)
        signature = None
        certificate_id = None
        cert = db.get_active_certificate(user_id)
        if cert:
            signature = pki_model.sign_data(encrypted_data, cert['key_path'])
            certificate_id = cert['id']
            # Save signature
            sig_path = os.path.join(ENCRYPTED_FOLDER, f"{file.filename}_sig.bin")
            with open(sig_path, "wb") as sig_file:
                sig_file.write(signature)

        # Step 7: Store file metadata in database
        file_info = {
            'original_filename': file.filename,
            'encrypted_filename': encrypted_filename,
            'original_hash': original_hash,
            'encrypted_hash': hash_model.hash_data(encrypted_data),
            'file_size': os.path.getsize(file_path),
            'signature': signature,
            'certificate_id': certificate_id
        }
        db.store_encrypted_file(user_id, file_info)

        # Log action
        db.log_action(user_id, 'ENCRYPT_FILE', 'file', None,
                      f"Encrypted file: {file.filename}", request.remote_addr)

        flash("File encrypted and signed successfully!", "success")
        return render_template(
            "result.html",
            file_name=encrypted_filename,
            action="Encryption",
            key_file=f"{file.filename}_key.bin",
            original_hash=original_hash,
            signed=certificate_id is not None
        )

    except Exception as e:
        flash(f"Encryption error: {e}", "error")
        return redirect(url_for("index"))


def download_and_decrypt():
    """
    Enhanced workflow with hash verification:
    Download → Decrypt AES Key (RSA) → Decrypt File (AES) → 
    Verify Signature → Verify Hash → Download
    """
    if "file" not in request.files:
        flash("No file uploaded", "error")
        return redirect(url_for("index"))

    file = request.files["file"]
    if file.filename == "":
        flash("No selected file", "error")
        return redirect(url_for("index"))

    user_id = session.get('user_id', 1)

    # Save uploaded encrypted file
    file_path = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(file_path)

    # Derive original filename
    original_name = file.filename.replace("encrypted_", "", 1)

    try:
        # Step 1: Load encrypted AES key
        key_file_path = os.path.join(ENCRYPTED_FOLDER, f"{original_name}_key.bin")
        if not os.path.exists(key_file_path):
            flash("Encrypted AES key not found", "error")
            return redirect(url_for("index"))

        with open(key_file_path, "rb") as key_file:
            encrypted_aes_key = key_file.read()

        # Step 2: Decrypt AES key with RSA
        decrypted_aes_key = rsa_model.decrypt_key(encrypted_aes_key, private_key)

        # Step 3: Load encrypted data
        with open(file_path, "rb") as enc_file:
            encrypted_data = enc_file.read()

        # Step 4: Verify digital signature (if exists)
        sig_path = os.path.join(ENCRYPTED_FOLDER, f"{original_name}_sig.bin")
        signature_valid = None
        if os.path.exists(sig_path):
            file_info = db.get_file_by_name(file.filename)
            if file_info and file_info.get('certificate_id'):
                cert = db.get_certificate_by_id(file_info['certificate_id'])
                if cert:
                    with open(sig_path, "rb") as sig_file:
                        signature = sig_file.read()
                    signature_valid = pki_model.verify_signature(
                        encrypted_data, signature, cert['cert_path']
                    )

        # Step 5: Decrypt file with AES
        aes_model = AESModel(key=decrypted_aes_key)
        decrypted_data = aes_model.decrypt(encrypted_data)

        # Step 6: Verify hash
        hash_file_path = os.path.join(ENCRYPTED_FOLDER, f"{original_name}_hash.txt")
        hash_valid = False
        original_hash = None
        if os.path.exists(hash_file_path):
            with open(hash_file_path, "r") as hash_file:
                original_hash = hash_file.read().strip()
            hash_valid = hash_model.verify_hash(decrypted_data, original_hash)

        # Step 7: Save decrypted file
        decrypted_filename = f"decrypted_{original_name}"
        decrypted_file_path = os.path.join(PROCESSED_FOLDER, decrypted_filename)
        with open(decrypted_file_path, "wb") as dec_file:
            dec_file.write(decrypted_data)

        # Log action
        db.log_action(user_id, 'DECRYPT_FILE', 'file', None,
                      f"Decrypted file: {file.filename}", request.remote_addr)

        if hash_valid:
            flash("File decrypted and integrity verified successfully!", "success")
        else:
            flash("File decrypted but hash verification failed - file may be corrupted!", "warning")

        return render_template(
            "result.html",
            file_name=decrypted_filename,
            action="Decryption",
            hash_valid=hash_valid,
            original_hash=original_hash,
            signature_valid=signature_valid
        )

    except Exception as e:
        flash(f"Decryption error: {e}", "error")
        return redirect(url_for("index"))
