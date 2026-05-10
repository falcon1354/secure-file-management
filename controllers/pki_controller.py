"""
PKI Controller
Handles certificate management, user registration, and PKI operations
"""
import os
import hashlib
from flask import flash, render_template, request, redirect, url_for, session, send_file
from models.pki_model import PKIModel
from models.database import DatabaseModel

pki_model = PKIModel()
db = DatabaseModel()


def register_user():
    """Register a new user and generate their certificate"""
    if request.method == "POST":
        email = request.form.get("email")
        name = request.form.get("name")
        password = request.form.get("password")
        organization = request.form.get("organization", "SecureFile User")

        if not all([email, name, password]):
            flash("All fields are required", "error")
            return redirect(url_for("register"))

        # Check if user exists
        existing_user = db.get_user_by_email(email)
        if existing_user:
            flash("User with this email already exists", "error")
            return redirect(url_for("register"))

        # Hash password
        password_hash = hashlib.sha256(password.encode()).hexdigest()

        # Create user
        user_id = db.create_user(email, name, password_hash)
        if not user_id:
            flash("Failed to create user", "error")
            return redirect(url_for("register"))

        # Generate certificate for user
        cert_info = pki_model.generate_user_certificate(
            user_id=user_id,
            email=email,
            common_name=name,
            organization=organization
        )

        # Store certificate in database
        cert_info['subject'] = name
        cert_info['issuer'] = 'SecureFile CA'
        db.store_certificate(user_id, cert_info)

        # Log action
        db.log_action(user_id, 'USER_REGISTERED', 'user', user_id,
                      f"User registered: {email}", request.remote_addr)
        db.log_action(user_id, 'CERT_GENERATED', 'certificate', None,
                      f"Certificate generated for: {email}", request.remote_addr)

        flash("User registered and certificate generated successfully!", "success")
        return render_template(
            "certificate_result.html",
            user_name=name,
            email=email,
            cert_info=cert_info,
            action="Registration"
        )

    return render_template("register.html")


def login_user():
    """User login"""
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        if not all([email, password]):
            flash("Email and password are required", "error")
            return redirect(url_for("login"))

        user = db.get_user_by_email(email)
        if not user:
            flash("Invalid email or password", "error")
            return redirect(url_for("login"))

        password_hash = hashlib.sha256(password.encode()).hexdigest()
        if user['password_hash'] != password_hash:
            flash("Invalid email or password", "error")
            return redirect(url_for("login"))

        # Set session
        session['user_id'] = user['id']
        session['user_email'] = user['email']
        session['user_name'] = user['name']

        # Log action
        db.log_action(user['id'], 'USER_LOGIN', 'user', user['id'],
                      f"User logged in: {email}", request.remote_addr)

        flash(f"Welcome back, {user['name']}!", "success")
        return redirect(url_for("dashboard"))

    return render_template("login.html")


def logout_user():
    """User logout"""
    user_id = session.get('user_id')
    if user_id:
        db.log_action(user_id, 'USER_LOGOUT', 'user', user_id,
                      "User logged out", request.remote_addr)
    session.clear()
    flash("You have been logged out", "info")
    return redirect(url_for("index"))


def dashboard():
    """User dashboard - shows certificates and files"""
    if 'user_id' not in session:
        flash("Please login first", "error")
        return redirect(url_for("login"))

    user_id = session['user_id']
    user = db.get_user_by_id(user_id)
    certificates = db.get_user_certificates(user_id)
    files = db.get_user_files(user_id)

    return render_template(
        "dashboard.html",
        user=user,
        certificates=certificates,
        files=files
    )


def view_certificate(cert_id):
    """View certificate details"""
    if 'user_id' not in session:
        flash("Please login first", "error")
        return redirect(url_for("login"))

    cert = db.get_certificate_by_id(cert_id)
    if not cert:
        flash("Certificate not found", "error")
        return redirect(url_for("dashboard"))

    # Get detailed info from PKI model
    try:
        cert_details = pki_model.get_certificate_info(cert['cert_path'])
        verification = pki_model.verify_certificate(cert['cert_path'])
    except Exception as e:
        flash(f"Error reading certificate: {e}", "error")
        return redirect(url_for("dashboard"))

    return render_template(
        "certificate_detail.html",
        cert=cert,
        cert_details=cert_details,
        verification=verification
    )


def download_certificate(cert_id):
    """Download user's certificate"""
    if 'user_id' not in session:
        flash("Please login first", "error")
        return redirect(url_for("login"))

    cert = db.get_certificate_by_id(cert_id)
    if not cert or cert['user_id'] != session['user_id']:
        flash("Certificate not found or access denied", "error")
        return redirect(url_for("dashboard"))

    return send_file(cert['cert_path'], as_attachment=True,
                     download_name=f"certificate_{cert_id}.pem")


def revoke_certificate(cert_id):
    """Revoke a certificate"""
    if 'user_id' not in session:
        flash("Please login first", "error")
        return redirect(url_for("login"))

    cert = db.get_certificate_by_id(cert_id)
    if not cert or cert['user_id'] != session['user_id']:
        flash("Certificate not found or access denied", "error")
        return redirect(url_for("dashboard"))

    reason = request.form.get("reason", "User requested revocation")
    if db.revoke_certificate(cert_id, reason):
        db.log_action(session['user_id'], 'CERT_REVOKED', 'certificate', cert_id,
                      f"Certificate revoked: {reason}", request.remote_addr)
        flash("Certificate has been revoked", "success")
    else:
        flash("Failed to revoke certificate", "error")

    return redirect(url_for("dashboard"))


def generate_new_certificate():
    """Generate a new certificate for current user"""
    if 'user_id' not in session:
        flash("Please login first", "error")
        return redirect(url_for("login"))

    user_id = session['user_id']
    user = db.get_user_by_id(user_id)

    # Generate new certificate
    cert_info = pki_model.generate_user_certificate(
        user_id=user_id,
        email=user['email'],
        common_name=user['name']
    )

    cert_info['subject'] = user['name']
    cert_info['issuer'] = 'SecureFile CA'
    db.store_certificate(user_id, cert_info)

    db.log_action(user_id, 'CERT_GENERATED', 'certificate', None,
                  "New certificate generated", request.remote_addr)

    flash("New certificate generated successfully!", "success")
    return redirect(url_for("dashboard"))


def view_ca_certificate():
    """View the CA certificate"""
    ca_cert, _ = pki_model.load_ca()
    ca_info = pki_model.get_certificate_info(pki_model.ca_cert_path)

    return render_template(
        "ca_certificate.html",
        ca_info=ca_info
    )


def audit_log():
    """View audit log (admin only for now)"""
    if 'user_id' not in session:
        flash("Please login first", "error")
        return redirect(url_for("login"))

    user_id = session['user_id']
    logs = db.get_audit_log(user_id=user_id, limit=50)

    return render_template("audit_log.html", logs=logs)
