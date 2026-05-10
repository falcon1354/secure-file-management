"""
Secure File Management System
Main Flask Application with AES, RSA, SHA-256 Hashing, and PKI
"""
import os
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, session
from models.aes_model import AESModel
from models.rsa_model import RSAModel
from models.hash_model import HashModel
from models.pki_model import PKIModel
from models.database import DatabaseModel
from controllers.file_controller import upload_and_encrypt, download_and_decrypt
from controllers.pki_controller import (
    register_user, login_user, logout_user, dashboard,
    view_certificate, download_certificate, revoke_certificate,
    generate_new_certificate, view_ca_certificate, audit_log
)

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your_super_secret_key_change_in_production')

UPLOAD_FOLDER = "uploads"
ENCRYPTED_FOLDER = "encrypted"
PROCESSED_FOLDER = "processed"

# Ensure folders exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(ENCRYPTED_FOLDER, exist_ok=True)
os.makedirs(PROCESSED_FOLDER, exist_ok=True)

# Initialize database
db = DatabaseModel()


@app.before_request
def initialize_db():
    """Initialize database tables on first request"""
    if not hasattr(app, 'db_initialized'):
        db.initialize_database()
        app.db_initialized = True


# ==================== MAIN ROUTES ====================

@app.route("/")
def index():
    """Home page"""
    return render_template("index.html")


@app.route("/upload", methods=["POST"])
def upload_file():
    """Handle file upload - encryption or decryption"""
    action = request.form.get("action")
    if action == "encrypt":
        return upload_and_encrypt()
    elif action == "decrypt":
        return download_and_decrypt()
    else:
        flash("Invalid action", "error")
        return redirect(url_for("index"))


@app.route("/download/<filename>")
def download_file(filename):
    """Download encrypted or decrypted file"""
    # Check in both folders
    if os.path.exists(os.path.join(ENCRYPTED_FOLDER, filename)):
        return send_from_directory(ENCRYPTED_FOLDER, filename, as_attachment=True)
    elif os.path.exists(os.path.join(PROCESSED_FOLDER, filename)):
        return send_from_directory(PROCESSED_FOLDER, filename, as_attachment=True)
    else:
        flash("File not found", "error")
        return redirect(url_for("index"))


# ==================== PKI ROUTES ====================

@app.route("/register", methods=["GET", "POST"])
def register():
    """User registration"""
    return register_user()


@app.route("/login", methods=["GET", "POST"])
def login():
    """User login"""
    return login_user()


@app.route("/logout")
def logout():
    """User logout"""
    return logout_user()


@app.route("/dashboard")
def user_dashboard():
    """User dashboard"""
    return dashboard()


@app.route("/certificate/<int:cert_id>")
def certificate_detail(cert_id):
    """View certificate details"""
    return view_certificate(cert_id)


@app.route("/certificate/<int:cert_id>/download")
def certificate_download(cert_id):
    """Download certificate"""
    return download_certificate(cert_id)


@app.route("/certificate/<int:cert_id>/revoke", methods=["POST"])
def certificate_revoke(cert_id):
    """Revoke certificate"""
    return revoke_certificate(cert_id)


@app.route("/certificate/new", methods=["POST"])
def certificate_new():
    """Generate new certificate"""
    return generate_new_certificate()


@app.route("/ca-certificate")
def ca_certificate():
    """View CA certificate"""
    return view_ca_certificate()


@app.route("/audit-log")
def view_audit_log():
    """View audit log"""
    return audit_log()


# ==================== ERROR HANDLERS ====================

@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", error="Page not found"), 404


@app.errorhandler(500)
def server_error(e):
    return render_template("error.html", error="Internal server error"), 500


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
