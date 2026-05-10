# Secure File Management System

A robust, web-based platform for secure file storage and management, featuring integrated **Public Key Infrastructure (PKI)**, multi-layered encryption, and digital signatures.

![GitHub last commit](https://img.shields.io/github/last-commit/falcon1354/secure-file-management)
![GitHub license](https://img.shields.io/github/license/falcon1354/secure-file-management)

## 🌟 Key Features

### 🔐 Advanced Cryptography
*   **Symmetric Encryption**: Files are encrypted using **AES-256-CFB** for high-speed, secure data confidentiality.
*   **Asymmetric Encryption**: Leverages **RSA (2048/4096-bit)** for secure key exchange and digital signatures.
*   **Data Integrity**: Implements **SHA-256** hashing to detect unauthorized modifications to files.

### 🏛️ Public Key Infrastructure (PKI)
*   **Certificate Authority (CA)**: Built-in local CA for issuing and managing digital certificates.
*   **X.509 Certificates**: Generates and verifies standard X.509 v3 certificates for all users.
*   **Revocation (CRL)**: Full support for Certificate Revocation Lists to manage compromised keys.

### 📊 Management & Auditing
*   **User Dashboard**: Intuitive interface for managing encrypted files and digital identities.
*   **Audit Logging**: Detailed tracking of all security actions (login, encryption, revocation) with IP and timestamp logging.
*   **Secure File Storage**: Segregated storage for original, encrypted, and processed files.

## 🛠️ Tech Stack
*   **Backend**: Python, Flask
*   **Frontend**: Next.js, React, Tailwind CSS, Radix UI
*   **Database**: MySQL
*   **Security**: `cryptography` (Python library)

## 🚀 Getting Started

### Prerequisites
*   Python 3.8+
*   Node.js 18+
*   MySQL Server

### Installation

1.  **Clone the repository**:
    ```bash
    git clone https://github.com/falcon1354/secure-file-management.git
    cd secure-file-management
    ```

2.  **Setup Backend**:
    ```bash
    pip install -r requirements.txt
    ```

3.  **Setup Database**:
    *   Create a MySQL database named `secure_file_db`.
    *   Update the database configuration in `models/database.py` or set environment variables (`MYSQL_HOST`, `MYSQL_USER`, `MYSQL_PASSWORD`).
    *   The tables will be automatically initialized on the first run.

4.  **Run the Application**:
    ```bash
    python app.py
    ```
    The server will start at `http://localhost:5000`.

## 🛡️ Security Implementation Details
*   **Encryption Mode**: CFB (Cipher Feedback) ensures that even if part of a file is damaged, the rest remains recoverable while maintaining high security.
*   **Signature Standard**: Uses **PSS (Probabilistic Signature Scheme)** padding for enhanced security in digital signatures.
*   **Certificate Policy**: User certificates are valid for 1 year, while the CA root is valid for 10 years.

## 📝 License
This project is licensed under the MIT License - see the LICENSE file for details.

---
*Developed for the Semester 8 Information Security course.*
