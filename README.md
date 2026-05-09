# SecureApp — Anonymous Whistleblower & Secure Document Exchange Platform

**Course:** CSE447: Cryptography and Cryptanalysis — Spring 2026  
**Institution:** BRAC University  
**Group:** 005 | Section: 01

| # | Name | Student ID |
|---|---|---|
| 1 | A. H. B. Sirajul Monir Akib | 24241373 |
| 2 | Nusrat Jahan Madhurzo | 24241129 |

---

## Project Overview

SecureApp is a layered cryptographic web application for secure whistleblowing and document exchange. It allows users to submit anonymous or attributed reports, send confidential tips, exchange encrypted messages, and share sensitive information through secure dead drops.

All cryptographic algorithms (RSA, ECC, SHA-256, HMAC-SHA256) are implemented **entirely from scratch** without using any built-in encryption libraries or framework-provided cryptographic functions.

---

## Security Features

- **Two Asymmetric Encryption Algorithms:** RSA-1024 (user profile data, tips, dead drops) and ECC ElGamal on secp256k1 (posts, messages)
- **Password Hashing with Salt:** SHA-256 with 16-byte random salt per user
- **Two-Factor Authentication:** Email-based 6-digit OTP, hashed before storage, expires in 10 minutes
- **HMAC-SHA256 Data Integrity:** All stored records tagged and verified on every read
- **Secure Session Management:** HMAC-signed tokens, SHA-256 hash stored in DB, IP + User-Agent binding, HTTP-only cookies
- **Role-Based Access Control (RBAC):** Admin and User roles with enforced permission boundaries
- **Key Management & Rotation:** RSA and HMAC key rotation with full re-encryption/re-signing of all existing records

---

## Technology Stack

| Component | Technology |
|---|---|
| Language | Python 3.12 |
| Web Framework | Flask 3.0.0 |
| Database | SQLite 3 |
| Frontend | HTML5, CSS3, JavaScript |
| Server (production) | Gunicorn |

---

## Prerequisites

- Python 3.8 or higher
- pip (Python package manager)
- SQLite3 (included with Python)
- A working email account for 2FA (configured in `config.py`)

---

## Installation

```bash
# Clone the repository
git clone https://github.com/monirakib/SecureApp.git
cd SecureApp

# Create and activate virtual environment (recommended)
python -m venv venv

# Windows
venv\Scripts\activate

# macOS/Linux
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run the application
python app.py
```

The application will start at `http://127.0.0.1:5000`

---

## First Run Setup

On the first run, the application automatically:
- Generates a 1024-bit RSA key pair → saved to `keys/system_rsa.json`
- Generates two 256-bit HMAC keys → saved to `keys/hmac_keys.json`
- Initialises the SQLite database schema

A default admin account is created:
- **Username:** `admin`
- **Password:** `admin123`

> **Important:** Change the admin password immediately after first login.

---

## Configuration

Edit `config.py` to set:

```python
# Email settings for 2FA
MAIL_SERVER = 'smtp.gmail.com'
MAIL_PORT = 587
MAIL_USERNAME = 'your-email@gmail.com'
MAIL_PASSWORD = 'your-app-password'

# Session settings
SESSION_DURATION_HOURS = 24
```

---

## Project Structure

```
SecureApp/
│
├── app.py                  # Main Flask application entry point
├── config.py               # Configuration settings
├── database.py             # Database operations and schema
├── key_management.py       # Key generation, storage, rotation
├── email_sender.py         # Email utility for 2FA codes
├── codenames.py            # Anonymous codename generator
├── requirements.txt        # Python dependencies
├── wsgi.py                 # WSGI server entry point
├── render.yaml             # Deployment configuration
│
├── crypto/                 # Custom cryptographic implementations (all from scratch)
│   ├── rsa.py              # RSA-1024 encryption/decryption
│   ├── ecc.py              # ECC ElGamal on secp256k1
│   ├── sha256.py           # SHA-256 hashing
│   ├── hmac_custom.py      # HMAC-SHA256
│   ├── utils.py            # Prime generation, modular arithmetic
│   └── symmetric.py        # Symmetric encryption utilities
│
├── routes/                 # Flask blueprints
│   ├── auth.py             # Login, registration, 2FA, logout
│   ├── posts.py            # Post CRUD operations
│   ├── profile.py          # User profile management
│   ├── admin.py            # Admin dashboard and controls
│   ├── feed.py             # Public feed display
│   ├── messages.py         # Encrypted messaging
│   ├── tips.py             # Anonymous tip submission
│   ├── deaddrops.py        # Dead drop creation/access
│   ├── friends.py          # Friend request system
│   └── sessions.py         # Session management
│
├── templates/              # HTML templates
├── static/                 # CSS and JavaScript assets
│
├── keys/                   # Cryptographic keys — git-ignored
│   ├── system_rsa.json     # System RSA key pair
│   └── hmac_keys.json      # HMAC session and data keys
│
└── app.bd                  # SQLite database — git-ignored
```

---

## How Encryption Works

### User Profile Data (RSA-1024)
Username, email, and phone number are encrypted with the system RSA public key before storage. Decryption requires the system RSA private key held only by the server.

### Posts & Messages (ECC ElGamal — secp256k1)
Each user has a unique ECC keypair generated at registration. Post titles/content and messages are encrypted with the recipient's ECC public key. The ECC private key is stored RSA-encrypted in the database.

### Anonymous Tips & Dead Drops (RSA-1024)
Since no user account is involved, the system RSA public key is used directly. Content is decryptable only by the server.

### Passwords (SHA-256 + Salt)
Passwords are never stored. A 16-byte random salt is generated per user; `SHA-256(salt + password)` is stored. Verification re-hashes the submitted password with the stored salt.

### Session Tokens (HMAC-SHA256)
Tokens are `SHA-256(32 random bytes)`, signed with HMAC using a dedicated session key. The cookie format is `token.HMACsignature`. Only `SHA-256(token)` is stored in the database — the token itself is never persisted.

---

## Environment Requirements

- All crypto algorithms are implemented from scratch
- No use of `hashlib`, `cryptography`, `pycryptodome`, or any external crypto library
- Only Python standard library used for non-crypto operations (`os`, `json`, `datetime`, etc.)

---

## Testing

1. Register a new user account
2. Check your email for the 2FA code
3. Create a post — verify it appears encrypted in the database (`app.bd`)
4. Log in as admin (`admin` / `admin123`) to access key rotation and audit logs
5. Test HMAC rotation: rotate keys via Admin → Key Management — all existing posts remain readable

---

## Security Warnings

- This is an **educational project** — not intended for production use without additional hardening
- RSA key size is 1024-bit for performance; production systems should use 2048-bit or higher
- Email-based 2FA is less secure than TOTP — included for demonstration purposes
- The `keys/` directory must never be committed to version control

---

## License

MIT License — for educational use. All custom cryptographic implementations are for learning purposes only.

---

## Acknowledgments

- **Course:** CSE447 — Cryptography and Cryptanalysis
- **Semester:** Spring 2026
- **Institution:** BRAC University, Department of Computer Science and Engineering
