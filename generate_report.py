"""Generate the CSE447 Project Report PDF."""

from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable, KeepTogether
)
from reportlab.platypus.flowables import HRFlowable

# ── Colour palette (matching the template) ─────────────────────────────────
DARK_BLUE  = colors.HexColor('#1F3864')
MID_BLUE   = colors.HexColor('#2E5090')
LIGHT_BLUE = colors.HexColor('#D9E1F2')
TABLE_HDR  = colors.HexColor('#1F3864')
ROW_ALT    = colors.HexColor('#EEF2F8')
WHITE      = colors.white
BLACK      = colors.black
GREY_TEXT  = colors.HexColor('#444444')
RULE_COLOR = DARK_BLUE

PAGE_W, PAGE_H = A4
MARGIN = 2.2 * cm

# ── Document ────────────────────────────────────────────────────────────────
doc = SimpleDocTemplate(
    "CSE447_Project_Report.pdf",
    pagesize=A4,
    leftMargin=MARGIN, rightMargin=MARGIN,
    topMargin=MARGIN,  bottomMargin=MARGIN,
    title="CSE447 Project Report – SecureApp",
    author="Group",
)

# ── Styles ───────────────────────────────────────────────────────────────────
base = getSampleStyleSheet()

def S(name, **kw):
    """Clone a base style with overrides."""
    s = ParagraphStyle(name, parent=base['Normal'], **kw)
    return s

cover_uni   = S('cover_uni',   fontSize=12, textColor=BLACK,       alignment=TA_CENTER, leading=18, spaceAfter=2)
cover_bold  = S('cover_bold',  fontSize=12, textColor=DARK_BLUE,   alignment=TA_CENTER, leading=18, fontName='Helvetica-Bold')
cover_title = S('cover_title', fontSize=28, textColor=DARK_BLUE,   alignment=TA_CENTER, leading=36, fontName='Helvetica-Bold', spaceAfter=6)
cover_sub   = S('cover_sub',   fontSize=13, textColor=BLACK,       alignment=TA_CENTER, leading=20, fontName='Helvetica-Oblique')
cover_label = S('cover_label', fontSize=11, textColor=DARK_BLUE,   alignment=TA_CENTER, leading=18, fontName='Helvetica-Bold')
cover_val   = S('cover_val',   fontSize=11, textColor=BLACK,       alignment=TA_CENTER, leading=18)
toc_entry   = S('toc_entry',   fontSize=11, textColor=BLACK,       leading=20)
toc_title   = S('toc_title',   fontSize=16, textColor=DARK_BLUE,   fontName='Helvetica-Bold', spaceAfter=10, spaceBefore=6)
h1          = S('h1',          fontSize=16, textColor=DARK_BLUE,   fontName='Helvetica-Bold', spaceBefore=14, spaceAfter=4, leading=22)
h2          = S('h2',          fontSize=12, textColor=DARK_BLUE,   fontName='Helvetica-Bold', spaceBefore=10, spaceAfter=3, leading=17)
body        = S('body',        fontSize=10, textColor=GREY_TEXT,   leading=15, spaceAfter=6, alignment=TA_JUSTIFY)
body_left   = S('body_left',   fontSize=10, textColor=GREY_TEXT,   leading=15, spaceAfter=4)
code_style  = S('code',        fontSize=8,  textColor=BLACK,       fontName='Courier',
                backColor=colors.HexColor('#F4F4F4'), leading=12, spaceAfter=6,
                leftIndent=12, rightIndent=12, borderPad=4)
footer_style= S('footer',      fontSize=8,  textColor=colors.HexColor('#888888'), alignment=TA_CENTER)
members_hdr = S('mem_hdr',     fontSize=16, textColor=DARK_BLUE,   fontName='Helvetica-Bold', alignment=TA_CENTER, spaceBefore=18, spaceAfter=8)

def rule():
    return HRFlowable(width='100%', thickness=1.5, color=RULE_COLOR, spaceAfter=8, spaceBefore=2)

def sp(h=6):
    return Spacer(1, h)

def tbl(data, col_widths, style_cmds, row_heights=None):
    t = Table(data, colWidths=col_widths, rowHeights=row_heights)
    base_style = [
        ('FONTNAME',  (0,0), (-1,-1), 'Helvetica'),
        ('FONTSIZE',  (0,0), (-1,-1), 9),
        ('VALIGN',    (0,0), (-1,-1), 'MIDDLE'),
        ('GRID',      (0,0), (-1,-1), 0.5, colors.HexColor('#AAAAAA')),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [WHITE, ROW_ALT]),
    ]
    t.setStyle(TableStyle(base_style + style_cmds))
    return t

def hdr_tbl(data, col_widths, style_cmds=None):
    """Table with dark-blue header row."""
    cmds = [
        ('BACKGROUND',  (0,0), (-1,0), TABLE_HDR),
        ('TEXTCOLOR',   (0,0), (-1,0), WHITE),
        ('FONTNAME',    (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE',    (0,0), (-1,0), 9),
        ('ALIGN',       (0,0), (-1,0), 'CENTER'),
    ]
    if style_cmds:
        cmds += style_cmds
    return tbl(data, col_widths, cmds)

story = []

# ════════════════════════════════════════════════════════════════════════════
# COVER PAGE
# ════════════════════════════════════════════════════════════════════════════
story += [
    sp(30),
    Paragraph("Department of Computer Science and Engineering", cover_uni),
    Paragraph('<b>Course:</b> CSE447: Cryptography and Cryptanalysis', cover_bold),
    Paragraph('<b>Semester:</b> Spring 2026', cover_bold),
    sp(30),
    rule(),
    sp(20),
    Paragraph("Project Report", cover_title),
    sp(4),
    Paragraph("<i>Title: SecureApp – A Multi-Algorithm Cryptographic Whistleblower Platform</i>", cover_sub),
    sp(20),
    rule(),
    sp(20),
    Paragraph('<b>Submitted To:</b> [Instructor Name]',     cover_label),
    Paragraph('<b>Group No:</b>  [Group No]',               cover_label),
    Paragraph('<b>Section:</b>  [Section]',                 cover_label),
    Paragraph('<b>Submission Date:</b>  [DD Month 2026]',   cover_label),
    sp(30),
    Paragraph("Group Members", members_hdr),
]

members_data = [
    [Paragraph('<b>No.</b>', S('c',fontName='Helvetica-Bold',fontSize=9,textColor=WHITE,alignment=TA_CENTER)),
     Paragraph('<b>Full Name</b>', S('c',fontName='Helvetica-Bold',fontSize=9,textColor=WHITE,alignment=TA_CENTER)),
     Paragraph('<b>Student ID</b>', S('c',fontName='Helvetica-Bold',fontSize=9,textColor=WHITE,alignment=TA_CENTER))],
    ['1', '[Member 1 Full Name]', '[Member 1 Student ID]'],
    ['2', '[Member 2 Full Name]', '[Member 2 Student ID]'],
    ['3', '[Member 3 Full Name]', '[Member 3 Student ID]'],
]
story.append(hdr_tbl(members_data, [2*cm, 9*cm, 5.5*cm],
    [('ALIGN',(0,1),(-1,-1),'CENTER')]))

story += [sp(30),
          Paragraph("CSE447  |  Spring 2026  |  BRAC University", footer_style),
          PageBreak()]

# ════════════════════════════════════════════════════════════════════════════
# TABLE OF CONTENTS
# ════════════════════════════════════════════════════════════════════════════
story.append(Paragraph("Table of Contents", toc_title))
story.append(rule())
toc_items = [
    ("1.",  "Introduction and System Overview",        "3"),
    ("2.",  "Login and Registration Module",           "4"),
    ("3.",  "User Data Encryption and Decryption",     "5"),
    ("4.",  "Password Hashing and Salting",            "6"),
    ("5.",  "Two-Factor Authentication (2FA)",         "7"),
    ("6.",  "Key Management Module",                   "8"),
    ("7.",  "Post and Profile Management",             "9"),
    ("8.",  "Data Storage Security",                   "10"),
    ("9.",  "Message Authentication Code (MAC)",       "11"),
    ("10.", "Role-Based Access Control (RBAC)",        "12"),
    ("11.", "Secure Session Management",               "13"),
    ("12.", "GitHub Repository and Project Structure", "14"),
    ("13.", "Conclusion",                              "15"),
]
for num, title, pg in toc_items:
    row_data = [[Paragraph(f"{num}  {title}", toc_entry), Paragraph(pg, S('r', fontSize=11, alignment=TA_CENTER))]]
    t = Table(row_data, colWidths=[13.5*cm, 2*cm])
    t.setStyle(TableStyle([('LINEBELOW',(0,0),(0,0),0.5,colors.HexColor('#CCCCCC'))]))
    story.append(t)
    story.append(sp(2))

story += [sp(20),
          Paragraph("CSE447  |  Spring 2026  |  BRAC University", footer_style),
          PageBreak()]

# ════════════════════════════════════════════════════════════════════════════
# Helper: section header
# ════════════════════════════════════════════════════════════════════════════
def sec(num, title):
    story.append(Paragraph(f"{num}. {title}", h1))
    story.append(rule())

def subsec(num, title):
    story.append(Paragraph(f"{num} {title}", h2))

def para(text):
    story.append(Paragraph(text, body))

def code(text):
    # Escape for XML
    text = text.replace('&','&amp;').replace('<','&lt;').replace('>','&gt;')
    story.append(Paragraph(f'<font name="Courier" size="8">{text}</font>', code_style))

def footer_pg():
    story.append(sp(12))
    story.append(Paragraph("CSE447  |  Spring 2026  |  BRAC University", footer_style))
    story.append(PageBreak())

# ════════════════════════════════════════════════════════════════════════════
# SECTION 1
# ════════════════════════════════════════════════════════════════════════════
sec("1", "Introduction and System Overview")
para("This report documents the design, implementation, and security analysis of the CSE447 Lab "
     "Project. The system is a secure web application integrating multiple cryptographic protocols "
     "as required by the course specification. All encryption algorithms have been implemented from "
     "scratch without relying on built-in framework encryption functions.")

subsec("1.1", "Project Overview")
para("<b>SecureApp</b> is a whistleblower and secure communication web platform designed to allow "
     "users to anonymously submit tips, publish encrypted investigative reports, exchange "
     "end-to-end encrypted messages, and securely share documents. Two user classes are supported: "
     "<b>regular users</b> (reporters/whistleblowers) and <b>administrators</b> (who moderate "
     "content, manage keys, and review tips). Core features include:")
features = [
    "Anonymous tip submission with category and urgency tagging",
    "Encrypted public posts (whistleblower reports) with HMAC integrity verification",
    "End-to-end encrypted private messaging with optional message expiry",
    "Dead drops – one-time anonymous document/message delivery channels",
    "Two-factor authentication via email OTP",
    "Role-based access control (user / admin)",
    "Admin dashboard with audit logs, key rotation, failed login tracking, and bulk tip actions",
]
for f in features:
    story.append(Paragraph(f"• {f}", body_left))

subsec("1.2", "Technology Stack")
tech_data = [
    [Paragraph('<b>Component</b>',  S('h',fontName='Helvetica-Bold',fontSize=9,textColor=WHITE)),
     Paragraph('<b>Technology</b>', S('h',fontName='Helvetica-Bold',fontSize=9,textColor=WHITE))],
    ['Language',         'Python 3.12'],
    ['Web Framework',    'Flask 3.1.3'],
    ['Database',         'SQLite 3 (via Python sqlite3 standard library)'],
    ['Email (2FA)',       'Gmail SMTP via smtplib (standard library), TLS on port 587'],
    ['External Libraries','flask, markupsafe only — zero cryptographic dependencies'],
    ['Custom Crypto',    'RSA-1024, ECC ElGamal secp256k1, SHA-256, HMAC-SHA256,\nSymmetric XOR-CTR — all from scratch'],
    ['Frontend',         'Bootstrap 5.3, Orbitron / Rajdhani / JetBrains Mono fonts'],
]
story.append(hdr_tbl(tech_data, [5*cm, 10.5*cm], []))

subsec("1.3", "System Architecture Diagram")
arch = (
    "CLIENT BROWSER\n"
    "      |\n"
    "      |  HMAC-signed session cookie\n"
    "      v\n"
    "FLASK APP (app.py)\n"
    "  auth.py | posts.py | admin.py | messages.py | tips.py | deaddrops.py ...\n"
    "      |\n"
    "      v\n"
    "key_management.py (KeyManager)\n"
    "  RSA encrypt/decrypt  |  ECC key gen/wrap  |  HMAC sign/verify\n"
    "      |\n"
    "      v\n"
    "crypto/  (all from scratch)\n"
    "  rsa.py | ecc.py | sha256.py | hmac_custom.py | symmetric.py | utils.py\n"
    "      |\n"
    "      v\n"
    "database.py  ->  app.db (SQLite)\n"
    "  All fields stored as ciphertext hex strings — zero plaintext"
)
code(arch)
footer_pg()

# ════════════════════════════════════════════════════════════════════════════
# SECTION 2
# ════════════════════════════════════════════════════════════════════════════
sec("2", "Login and Registration Module")
para("The system provides secure registration and login flows. New users supply credentials which "
     "are validated, encrypted, and persisted. During login, stored encrypted data is retrieved "
     "and decrypted for verification.")

subsec("2.1", "Registration Flow")
steps = [
    "User submits username, email, phone (optional), password, and confirm password.",
    "Server validates: non-empty required fields, username 3–50 chars, password ≥ 6 chars, passwords match.",
    "SHA-256(username.lower()) and SHA-256(email.lower()) computed as lookup hashes — checked for uniqueness without storing plaintext.",
    "Username, email, and phone RSA-encrypted using the system public key.",
    "A 16-byte random salt is generated; password hashed as SHA-256(salt || password).",
    "A fresh ECC (secp256k1) key pair generated for the user; ECC private key RSA-encrypted before storage.",
    "HMAC-SHA256 tag computed over (username_hash | email_hash | password_hash) stored as data_hmac.",
    "All fields written to the users table — no plaintext stored anywhere.",
]
for i, s in enumerate(steps, 1):
    story.append(Paragraph(f"{i}. {s}", body_left))

subsec("2.2", "Login Flow")
lsteps = [
    "User submits username and password.",
    "SHA-256(username.lower()) used to look up the user row. Unknown usernames are logged to audit_log; generic error shown (prevents enumeration).",
    "SHA-256(salt || password) computed and compared to stored password_hash. Mismatches are logged.",
    "HMAC integrity of the user record verified before proceeding.",
    "6-digit OTP generated via os.urandom(3), SHA-256 hashed, stored with 5-minute expiry, emailed to RSA-decrypted address.",
    "Temporary HMAC-signed token placed in a 2fa_pending session cookie. On OTP submission the server verifies signature, hashes the code, and compares to stored hash.",
    "On success: full session token created, HMAC-signed, stored in sessions table with IP binding and 24-hour expiry, set as HttpOnly; SameSite=Strict cookie.",
]
for i, s in enumerate(lsteps, 1):
    story.append(Paragraph(f"{i}. {s}", body_left))

subsec("2.3", "Implementation Details")
impl_data = [
    [Paragraph('<b>Requirement</b>',               S('h',fontName='Helvetica-Bold',fontSize=9,textColor=WHITE)),
     Paragraph('<b>Implementation Details</b>',    S('h',fontName='Helvetica-Bold',fontSize=9,textColor=WHITE))],
    ['Login Module',
     'Username looked up by SHA-256 hash; password verified via SHA-256(salt||password); HMAC integrity check; failed attempts logged to audit_log; 2FA mandatory before session is created'],
    ['Registration Module',
     'Fields: username (3–50 chars), email, phone (optional), password (≥6 chars), confirm password; uniqueness enforced via SHA-256 hash lookup'],
    ['Data Encrypted Before Storage',
     'username_enc, email_enc, phone_enc → RSA-1024 (system key); ecc_private_key_enc → RSA-1024 wraps ECC private key'],
    ['Data Decrypted on Retrieval',
     'key_manager.decrypt_user_data(ciphertext) calls rsa_decrypt_string() with system RSA private key; ECC private key decrypted then deserialized'],
]
story.append(hdr_tbl(impl_data, [5*cm, 10.5*cm],
    [('VALIGN',(0,0),(-1,-1),'TOP'),('FONTSIZE',(0,1),(-1,-1),8)]))
footer_pg()

# ════════════════════════════════════════════════════════════════════════════
# SECTION 3
# ════════════════════════════════════════════════════════════════════════════
sec("3", "User Data Encryption and Decryption")
para("All sensitive user information (e.g., username, email, contact info) is encrypted before "
     "storage using asymmetric encryption algorithms implemented from scratch, and decrypted upon retrieval.")

subsec("3.1", "Fields Encrypted")
fields_data = [
    [Paragraph('<b>Table</b>',     S('h',fontName='Helvetica-Bold',fontSize=9,textColor=WHITE)),
     Paragraph('<b>Field</b>',     S('h',fontName='Helvetica-Bold',fontSize=9,textColor=WHITE)),
     Paragraph('<b>Algorithm</b>', S('h',fontName='Helvetica-Bold',fontSize=9,textColor=WHITE))],
    ['users',          'username_enc',           'RSA-1024 (system key)'],
    ['users',          'email_enc',              'RSA-1024 (system key)'],
    ['users',          'phone_enc',              'RSA-1024 (system key)'],
    ['users',          'ecc_private_key_enc',    'RSA-1024 (system key wraps ECC private key)'],
    ['posts',          'title_enc, content_enc', "ECC ElGamal secp256k1 (user's personal key)"],
    ['messages',       'subject_enc, content_enc',"ECC ElGamal (recipient's public key)"],
    ['anonymous_tips', 'title_enc, content_enc', 'ECC ElGamal (system ECC key)'],
    ['documents',      'file bytes',             'XOR-CTR (SHA-256 keystream); symmetric key RSA-wrapped'],
    ['dead_drops',     'content_enc',            'ECC ElGamal'],
]
story.append(hdr_tbl(fields_data, [3.5*cm, 5*cm, 7*cm],
    [('FONTSIZE',(0,1),(-1,-1),8)]))

subsec("3.2", "Encryption Algorithm – RSA Implementation (crypto/rsa.py)")
para("The RSA implementation is entirely from scratch with no use of any built-in cryptographic library:")
rsa_pts = [
    "<b>Key size:</b> 1024 bits (two 512-bit primes p and q).",
    "<b>Prime generation:</b> generate_prime(bits) in crypto/utils.py generates a random odd number of the target bit-length and confirms primality with a Miller-Rabin test.",
    "<b>Key generation:</b> n = p × q, φ(n) = (p−1)(q−1), public exponent e = 65537, private exponent d = e⁻¹ mod φ(n) via the extended Euclidean algorithm.",
    "<b>Encryption / Decryption:</b> c = m^e mod n and m = c^d mod n using Python's pow(base, exp, mod) for efficient modular exponentiation.",
    "<b>String encryption:</b> Data is UTF-8 encoded, prefixed with a 4-byte length header, split into chunks of (key_size − 1) bytes so each chunk < n. Each chunk is encrypted independently and hex-encoded; chunks are joined with ':'.",
]
for pt in rsa_pts:
    story.append(Paragraph(f"• {pt}", body_left))

subsec("3.3", "Encryption Algorithm – ECC Implementation (crypto/ecc.py)")
para("The ECC implementation uses <b>ElGamal encryption on the secp256k1 curve</b>, fully from scratch:")
ecc_pts = [
    "<b>Curve:</b> y² = x³ + 7 (mod p) — secp256k1 (a = 0, b = 7). Standard Bitcoin/Ethereum curve.",
    "<b>Curve parameters:</b> p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F, generator point G at standard secp256k1 coordinates.",
    "<b>Point arithmetic:</b> point_add(), point_double(), and scalar_multiply() (double-and-add) implemented manually.",
    "<b>Key generation:</b> Private key d is a random integer in [1, n). Public key Q = d × G.",
    "<b>Koblitz encoding:</b> Each 30-byte plaintext chunk is encoded as x = m × 100 + j where j (0–99) is the smallest offset for which a valid curve point exists (y² is a quadratic residue). y is recovered via modular square root.",
    "<b>ElGamal encryption:</b> For message point M, random k chosen; ciphertext (C1, C2) = (k×G, M + k×Q).",
    "<b>Decryption:</b> M = C2 − d×C1, since d×C1 = d×k×G = k×Q.",
]
for pt in ecc_pts:
    story.append(Paragraph(f"• {pt}", body_left))

subsec("3.4", "How Both Algorithms Are Used Differently")
diff_data = [
    [Paragraph('<b>Operation</b>',  S('h',fontName='Helvetica-Bold',fontSize=9,textColor=WHITE)),
     Paragraph('<b>Algorithm</b>',  S('h',fontName='Helvetica-Bold',fontSize=9,textColor=WHITE)),
     Paragraph('<b>Reason</b>',     S('h',fontName='Helvetica-Bold',fontSize=9,textColor=WHITE))],
    ['User profile fields\n(username, email, phone)', 'RSA-1024',
     'System-wide encryption; data must be decryptable by the server for admin access and display'],
    ['ECC private key wrapping', 'RSA-1024',
     'Asymmetric key wrapping — one system RSA key protects all per-user ECC keys'],
    ['Post titles and content', 'ECC ElGamal (secp256k1)',
     'Per-user encryption; only the post author\'s key can decrypt — enforces user data isolation'],
    ['Private messages', 'ECC ElGamal',
     'Encrypted to recipient\'s public ECC key — sender cannot decrypt after sending'],
    ['Anonymous tips, dead drops', 'ECC ElGamal',
     'Uses system ECC key for admin-accessible decryption without account linkage'],
    ['Document file bytes', 'Symmetric XOR-CTR\n(SHA-256 keystream)',
     'Efficient for large binary payloads; symmetric key RSA-wrapped before storage'],
]
story.append(hdr_tbl(diff_data, [4*cm, 4*cm, 7.5*cm],
    [('VALIGN',(0,0),(-1,-1),'TOP'), ('FONTSIZE',(0,1),(-1,-1),8)]))
footer_pg()

# ════════════════════════════════════════════════════════════════════════════
# SECTION 4
# ════════════════════════════════════════════════════════════════════════════
sec("4", "Password Hashing and Salting")
para("Passwords are never stored in plaintext. A cryptographic hash function combined with a "
     "random salt is applied before storage to prevent dictionary and rainbow-table attacks.")

subsec("4.1", "Hashing Algorithm Used")
para("The system uses <b>SHA-256</b>, implemented entirely from scratch in <b>crypto/sha256.py</b>. "
     "SHA-256 was chosen because:")
for pt in [
    "It produces a 256-bit (32-byte) digest providing strong collision resistance.",
    "It is the foundational primitive already used throughout the system (HMAC, session token hashing, lookup hashing), keeping the cryptographic surface uniform.",
    "The custom implementation follows the complete SHA-256 specification: message padding, 64-round compression with schedule words, and the eight initial hash values derived from the square roots of the first 8 primes.",
]:
    story.append(Paragraph(f"• {pt}", body_left))

subsec("4.2", "Salt Generation")
para("Salt is generated using <b>os.urandom(16)</b>, producing 16 cryptographically secure random bytes, "
     "then hex-encoded to a 32-character string. The salt is stored as plaintext in the "
     "<b>password_salt</b> column of the users table, separate from password_hash. "
     "This is the standard practice — the salt's purpose is uniqueness per user, not secrecy.")

subsec("4.3", "Verification Process")
para("On login, verification proceeds as follows:")
for i, s in enumerate([
    "Retrieve the user row by SHA-256(username.lower()) hash lookup.",
    "Read password_salt from the row.",
    "Compute candidate_hash = SHA-256(salt_bytes || password_bytes) using the submitted password.",
    "Compare candidate_hash with the stored password_hash.",
    "If they match, proceed to HMAC integrity verification and then 2FA.",
], 1):
    story.append(Paragraph(f"{i}. {s}", body_left))

code(
    "# key_management.py\n"
    "def hash_password(self, password, salt):\n"
    "    return sha256_hex(salt.encode('utf-8') + password.encode('utf-8'))\n\n"
    "# routes/auth.py — verification\n"
    "password_hash = key_manager.hash_password(password, user['password_salt'])\n"
    "if password_hash != user['password_hash']:\n"
    "    # log failed attempt, reject login"
)
footer_pg()

# ════════════════════════════════════════════════════════════════════════════
# SECTION 5
# ════════════════════════════════════════════════════════════════════════════
sec("5", "Two-Factor Authentication (2FA)")
para("The system enforces two-step verification: the user must pass both primary credential "
     "validation and a second authentication factor before a session is granted.")

subsec("5.1", "2FA Method")
para("The system uses <b>Email OTP (One-Time Password)</b>: a 6-digit code is generated, hashed, "
     "and emailed to the user's registered address after successful primary credential verification. "
     "The flow is:")
for i, s in enumerate([
    "After correct username/password, a 6-digit code is produced: code = os.urandom(3) % 1,000,000 (zero-padded to 6 digits).",
    "SHA-256(code) stored in the two_factor_codes table with a 5-minute expiry (TWO_FA_EXPIRY_MINUTES = 5).",
    "The plaintext code is sent via Gmail SMTP (smtplib, TLS on port 587). The email address is obtained by RSA-decrypting the user's email_enc field.",
    "A temporary signed token (SHA-256(random) + HMAC signature) is placed in a short-lived 2fa_token HttpOnly cookie, pointing to a 2fa_pending session row binding the user_id.",
    "The user submits the code. The server verifies the cookie signature, hashes the submitted code, and compares it against the stored hash.",
    "On success: the temporary session is deleted and a full permanent session cookie is issued.",
], 1):
    story.append(Paragraph(f"{i}. {s}", body_left))

subsec("5.2", "Code Snippet")
code(
    "# routes/auth.py — 2FA code generation\n"
    "code = str(int.from_bytes(secure_random_bytes(3), 'big') % 1000000).zfill(6)\n"
    "code_hash = sha256_hex(code.encode('utf-8'))\n"
    "expires_at = (datetime.utcnow() + timedelta(minutes=TWO_FA_EXPIRY_MINUTES)).isoformat()\n"
    "db.create_2fa_code(user['id'], code_hash, expires_at)\n\n"
    "# Decrypt email and send OTP\n"
    "user_email = key_manager.decrypt_user_data(user['email_enc'])\n"
    "send_2fa_code(user_email, code)\n\n"
    "# Temporary signed token for the 2FA step\n"
    "temp_token = sha256_hex(secure_random_bytes(16))\n"
    "temp_sig   = key_manager.sign_session_token(temp_token)\n"
    "response.set_cookie('2fa_token', f'{temp_token}.{temp_sig}',\n"
    "                    httponly=True, samesite='Strict',\n"
    "                    max_age=TWO_FA_EXPIRY_MINUTES * 60)\n\n"
    "# routes/auth.py — verification\n"
    "code_hash = sha256_hex(code.encode('utf-8'))\n"
    "if not db.verify_2fa_code(user_id, code_hash):\n"
    "    flash('Invalid or expired verification code.', 'danger')"
)
footer_pg()

# ════════════════════════════════════════════════════════════════════════════
# SECTION 6
# ════════════════════════════════════════════════════════════════════════════
sec("6", "Key Management Module")
para("A dedicated Key Management Module (key_management.py) handles the full lifecycle of "
     "cryptographic keys: secure generation, storage, and rotation.")

subsec("6.1", "Key Storage Security")
para("The <b>KeyManager</b> class manages four keys:")
key_data = [
    [Paragraph('<b>Key</b>',       S('h',fontName='Helvetica-Bold',fontSize=9,textColor=WHITE)),
     Paragraph('<b>Storage</b>',   S('h',fontName='Helvetica-Bold',fontSize=9,textColor=WHITE)),
     Paragraph('<b>Protection</b>',S('h',fontName='Helvetica-Bold',fontSize=9,textColor=WHITE))],
    ['RSA public key',          'keys/system_rsa.json',  'Public key — no secrecy needed'],
    ['RSA private key',         'keys/system_rsa.json',  'JSON file on server filesystem; all user data unreadable without it'],
    ['HMAC session key (32 B)', 'keys/hmac_keys.json',   'Used to sign/verify session tokens'],
    ['HMAC data key (32 B)',    'keys/hmac_keys.json',   'Used for data integrity MACs on all records'],
]
story.append(hdr_tbl(key_data, [4.5*cm, 4.5*cm, 6.5*cm],
    [('FONTSIZE',(0,1),(-1,-1),8), ('VALIGN',(0,0),(-1,-1),'TOP')]))
para("User ECC private keys are <b>never stored in plaintext</b>: they are RSA-encrypted with "
     "the system public key (rsa_encrypt_string(priv_str, self.rsa_public_key)) and stored as "
     "ecc_private_key_enc in the database. Decryption requires the system RSA private key, "
     "which exists only server-side.")

subsec("6.2", "Key Rotation Policy")
para("The system provides <b>admin-triggered key rotation</b> accessible via /admin/keys. "
     "When rotation is triggered:")
for i, s in enumerate([
    "A new RSA-1024 key pair is generated with generate_rsa_keypair(RSA_KEY_BITS).",
    "All users' ecc_private_key_enc fields are re-encrypted: old RSA private key decrypts them; new RSA public key re-encrypts them.",
    "All user profile fields (username_enc, email_enc, phone_enc) similarly re-encrypted: decrypt with old key → encrypt with new key → update in database.",
    "New keys replace the old ones in keys/system_rsa.json.",
    "A key_rotation_log entry is recorded with timestamp and the admin user ID who triggered it.",
    "HMAC keys can also be independently rotated. After rotation, new keys are used for all future HMAC computations.",
], 1):
    story.append(Paragraph(f"{i}. {s}", body_left))
para("This guarantees that existing encrypted records are never broken by a key rotation event.")
footer_pg()

# ════════════════════════════════════════════════════════════════════════════
# SECTION 7
# ════════════════════════════════════════════════════════════════════════════
sec("7", "Post and Profile Management")
para("Users can create, view, and edit posts, as well as view and update their profiles. "
     "All post and profile data is automatically encrypted before storage and decrypted on retrieval.")

subsec("7.1", "Post Module")
para("<b>Create:</b> User submits a title (max 200 chars) and content (max 5000 chars). "
     "The system uses the user's ECC public key to encrypt both fields with ecc_encrypt_string(). "
     "A HMAC-SHA256 tag over (title_enc, content_enc, user_id) is computed and stored as data_hmac. "
     "Optionally an uploaded document is encrypted with a symmetric XOR-CTR key, "
     "itself RSA-wrapped before storage.")
para("<b>Read:</b> The user's ECC private key (decrypted via RSA from ecc_private_key_enc) is used "
     "with ecc_decrypt_string(). Before decryption, HMAC is verified; if it fails the post is "
     "flagged [Integrity Check Failed] instead of revealing content.")
para("<b>Update:</b> The /posts/&lt;id&gt;/edit route re-encrypts the new title and content "
     "with the same ECC public key and recomputes the HMAC.")

post_enc = [
    [Paragraph('<b>Field</b>',     S('h',fontName='Helvetica-Bold',fontSize=9,textColor=WHITE)),
     Paragraph('<b>Encrypted With</b>', S('h',fontName='Helvetica-Bold',fontSize=9,textColor=WHITE))],
    ['title_enc',   "ECC ElGamal (user's public key)"],
    ['content_enc', "ECC ElGamal (user's public key)"],
    ['data_hmac',   'HMAC-SHA256 over title_enc + content_enc + user_id'],
]
story.append(hdr_tbl(post_enc, [5.5*cm, 10*cm], []))

subsec("7.2", "Profile Module")
para("<b>View:</b> The profile.py route decrypts username_enc, email_enc, and phone_enc via "
     "key_manager.decrypt_user_data() (RSA). It also computes a <b>key fingerprint</b>: "
     "the first 16 hex characters of SHA-256(ecc_public_key) formatted as XXXX:XXXX:XXXX:XXXX.")
para("<b>Update:</b> The /profile/edit route accepts new username, email, phone, and optionally "
     "a new password. Updated fields are RSA-encrypted before storage and data_hmac is recomputed.")
prof_enc = [
    [Paragraph('<b>Field</b>',     S('h',fontName='Helvetica-Bold',fontSize=9,textColor=WHITE)),
     Paragraph('<b>Encrypted With</b>', S('h',fontName='Helvetica-Bold',fontSize=9,textColor=WHITE))],
    ['username_enc', 'RSA-1024 (system key)'],
    ['email_enc',    'RSA-1024 (system key)'],
    ['phone_enc',    'RSA-1024 (system key)'],
]
story.append(hdr_tbl(prof_enc, [5.5*cm, 10*cm], []))

subsec("7.3", "Screenshots")
para("[Insert screenshots of the post creation page at /posts/create, the post listing page "
     "at /posts, and the profile management page at /profile/edit.]")
footer_pg()

# ════════════════════════════════════════════════════════════════════════════
# SECTION 8
# ════════════════════════════════════════════════════════════════════════════
sec("8", "Data Storage Security")
para("All critical data — user information, posts, and cryptographic keys — is stored in "
     "encrypted form to prevent plaintext access even in the event of a database compromise.")

subsec("8.1", "Evidence of Encrypted Storage")
para("The SQLite database app.db stores all sensitive fields as hex-encoded ciphertext strings. "
     "A direct inspection of the users table in any SQLite browser reveals:")
for field, desc in [
    ("username_enc",           "Long colon-separated hex string (RSA-chunked ciphertext)"),
    ("email_enc",              "Long colon-separated hex string (RSA-chunked ciphertext)"),
    ("password_hash",          "64-character SHA-256 hex digest (separate password_salt column)"),
    ("ecc_public_key",         "Serialized point coordinates (two hex integers separated by ':')"),
    ("ecc_private_key_enc",    "RSA-encrypted ECC private key (colon-separated hex chunks)"),
    ("data_hmac",              "64-character HMAC-SHA256 hex digest"),
]:
    story.append(Paragraph(f"• <b>{field}:</b>  {desc}", body_left))
para("The posts table stores title_enc and content_enc as long hex strings (ECC ElGamal "
     "ciphertext tuples: c1x,c1y,c2x,c2y per chunk, separated by ';'). "
     "No column in any table stores plaintext user-supplied content.")
para("[Insert screenshot of raw database records from DB Browser for SQLite or equivalent tool "
     "showing ciphertext, not plaintext.]")
footer_pg()

# ════════════════════════════════════════════════════════════════════════════
# SECTION 9
# ════════════════════════════════════════════════════════════════════════════
sec("9", "Message Authentication Code (MAC)")
para("Message Authentication Codes (MACs) are used to verify the integrity of stored data and "
     "detect any unauthorized modifications.")

subsec("9.1", "MAC Algorithm Used")
para("The system uses <b>HMAC-SHA256</b>, implemented from scratch in <b>crypto/hmac_custom.py</b>. "
     "HMAC was chosen over CBC-MAC because:")
for pt in [
    "HMAC is provably secure as long as the underlying hash is secure, without requiring a block cipher.",
    "It handles variable-length inputs (post content, user data) naturally, which CBC-MAC handles less cleanly.",
    "The custom SHA-256 implementation was already available as the underlying primitive.",
]:
    story.append(Paragraph(f"• {pt}", body_left))
para("The standard HMAC construction is followed exactly:")
code(
    "HMAC(K, m) = SHA-256( (K' XOR opad) || SHA-256( (K' XOR ipad) || m ) )\n\n"
    "where K' = key padded/hashed to 64 bytes (SHA-256 block size)\n"
    "      ipad = 0x36 repeated 64 times\n"
    "      opad = 0x5C repeated 64 times"
)
para("Verification uses constant-time byte-by-byte XOR comparison to prevent timing attacks. "
     "Two independent 32-byte HMAC keys are maintained by KeyManager: "
     "<b>hmac_session_key</b> (signs session tokens) and <b>hmac_data_key</b> (data integrity tags).")

subsec("9.2", "Integrity Verification Flow")
para("HMAC verification is performed:")
for i, s in enumerate([
    "On every user post read (/posts, /posts/<id>): stored data_hmac verified against (title_enc, content_enc, user_id) before decryption. Failure displays [Integrity Check Failed].",
    "On every login: user record data_hmac verified against (username_hash, email_hash, password_hash). Failure aborts login.",
    "On every HTTP request: session cookie token.signature verified by recomputing HMAC(hmac_session_key, token) with constant_time_compare().",
    "On anonymous tips and messages: data_hmac verified during read operations before content is displayed.",
], 1):
    story.append(Paragraph(f"{i}. {s}", body_left))
footer_pg()

# ════════════════════════════════════════════════════════════════════════════
# SECTION 10
# ════════════════════════════════════════════════════════════════════════════
sec("10", "Role-Based Access Control (RBAC)")
para("Role-Based Access Control defines distinct privilege levels for Administrators and Regular "
     "Users, ensuring that sensitive operations are restricted appropriately.")

subsec("10.1", "Roles Defined")
para("Two roles are stored in the <b>users.role</b> column, enforced by a SQL CHECK constraint "
     "(role IN ('user', 'admin')):")
for role, desc in [
    ("User",  "Regular authenticated member. Can create and manage own posts, submit anonymous tips, exchange encrypted messages, use dead drops, and manage their profile."),
    ("Admin", "Privileged operator. Has all user capabilities plus full administrative control — user management, key rotation, tip review, post moderation, and audit log access. Enforced by the @admin_required decorator in routes/__init__.py (aborts HTTP 403 if role != 'admin')."),
]:
    story.append(Paragraph(f"• <b>{role}:</b>  {desc}", body_left))

subsec("10.2", "Permission Matrix")
tick = Paragraph('<b>✔</b>', S('t', fontName='Helvetica-Bold', fontSize=10, alignment=TA_CENTER, textColor=colors.HexColor('#1a7a1a')))
cross = Paragraph('<b>✘</b>', S('t', fontName='Helvetica-Bold', fontSize=10, alignment=TA_CENTER, textColor=colors.HexColor('#cc0000')))
perm_data = [
    [Paragraph('<b>Operation / Resource</b>', S('h',fontName='Helvetica-Bold',fontSize=9,textColor=WHITE)),
     Paragraph('<b>Admin</b>',               S('h',fontName='Helvetica-Bold',fontSize=9,textColor=WHITE,alignment=TA_CENTER)),
     Paragraph('<b>Regular User</b>',         S('h',fontName='Helvetica-Bold',fontSize=9,textColor=WHITE,alignment=TA_CENTER))],
    ['View own profile',              tick, tick],
    ['Edit own profile',              tick, tick],
    ['Create / Edit own posts',       tick, tick],
    ['Submit anonymous tips',         tick, tick],
    ['Send / receive encrypted messages', tick, tick],
    ['Create / access dead drops',    tick, tick],
    ['View all user accounts',        tick, cross],
    ['Change user roles',             tick, cross],
    ['Delete any post',               tick, cross],
    ['View / manage all tips',        tick, cross],
    ['Bulk update tip status',        tick, cross],
    ['Manage / rotate crypto keys',   tick, cross],
    ['View audit logs / failed logins', tick, cross],
    ['Change post publication status', tick, cross],
]
story.append(hdr_tbl(perm_data, [10*cm, 2.25*cm, 3.25*cm],
    [('ALIGN',(1,0),(2,-1),'CENTER')]))
footer_pg()

# ════════════════════════════════════════════════════════════════════════════
# SECTION 11
# ════════════════════════════════════════════════════════════════════════════
sec("11", "Secure Session Management")
para("Authentication tokens and session identifiers are managed securely to prevent session "
     "hijacking, fixation, and replay attacks.")

subsec("11.1", "Token Signing / Verification")
para("Sessions are managed entirely with custom cryptography — no Flask session, JWT, or "
     "third-party auth libraries are used.")

para("<b>Token creation:</b>")
for i, s in enumerate([
    "256-bit random token: token = SHA-256(os.urandom(32)).",
    "CSRF token: csrf_token = SHA-256(os.urandom(16)).",
    "Token HMAC-signed: signature = HMAC(hmac_session_key, token).",
    "Cookie value sent to browser: {token}.{signature}.",
    "Database stores SHA-256(token) as token_hash (never the raw token), plus user_id, ip_address, SHA-256(User-Agent), csrf_token, and expires_at (24 hours).",
], 1):
    story.append(Paragraph(f"{i}. {s}", body_left))

para("<b>Verification on every request (middleware in app.py):</b>")
for i, s in enumerate([
    "Split cookie into token and sig.",
    "Recompute expected_sig = HMAC(hmac_session_key, token).",
    "Compare using constant_time_compare() — byte-by-byte XOR to prevent timing attacks.",
    "Hash token → look up in sessions table.",
    "Check expiry against datetime.utcnow().",
    "Verify ip_address matches request.remote_addr (IP binding to prevent cookie theft).",
    "Load user into flask.g for the duration of the request.",
], 1):
    story.append(Paragraph(f"{i}. {s}", body_left))

para("<b>Additional protections:</b>")
for pt in [
    "Cookies set HttpOnly=True, SameSite=Strict to prevent XSS and CSRF access.",
    "CSRF tokens injected into all state-changing forms and verified server-side.",
    "Expired sessions pruned by db.cleanup_expired_sessions() triggered probabilistically on ~1% of requests.",
    "Users can view and terminate all active sessions from the /sessions page.",
]:
    story.append(Paragraph(f"• {pt}", body_left))
footer_pg()

# ════════════════════════════════════════════════════════════════════════════
# SECTION 12
# ════════════════════════════════════════════════════════════════════════════
sec("12", "GitHub Repository and Project Structure")
gh_data = [
    [Paragraph('<b>Field</b>',   S('h',fontName='Helvetica-Bold',fontSize=9,textColor=WHITE)),
     Paragraph('<b>Details</b>', S('h',fontName='Helvetica-Bold',fontSize=9,textColor=WHITE))],
    ['GitHub Repository URL', 'https://github.com/monirakib/SecureApp'],
]
story.append(hdr_tbl(gh_data, [5*cm, 10.5*cm], []))

subsec("12.1", "Repository Structure")
code(
    "SecureApp/\n"
    "|-- app.py               # Entry point, session middleware, blueprint registration\n"
    "|-- config.py            # Configuration (paths, key sizes, SMTP, upload limits)\n"
    "|-- database.py          # All SQLite CRUD operations\n"
    "|-- key_management.py    # KeyManager: RSA/ECC/HMAC key lifecycle\n"
    "|-- email_sender.py      # Gmail SMTP 2FA email delivery\n"
    "|-- codenames.py         # Anonymous codename generator for tips\n"
    "|-- requirements.txt     # flask, markupsafe only (no crypto dependencies)\n"
    "|\n"
    "|-- crypto/              # All cryptographic primitives (from scratch)\n"
    "|   |-- rsa.py           # RSA-1024: key gen, encrypt/decrypt strings\n"
    "|   |-- ecc.py           # ECC ElGamal secp256k1: key gen, encrypt/decrypt\n"
    "|   |-- sha256.py        # SHA-256 hash function\n"
    "|   |-- hmac_custom.py   # HMAC-SHA256\n"
    "|   |-- symmetric.py     # XOR-CTR symmetric encryption (SHA-256 keystream)\n"
    "|   +-- utils.py         # Prime gen, mod_inverse, secure random\n"
    "|\n"
    "|-- routes/              # Flask blueprints\n"
    "|   |-- auth.py          # Register, login, 2FA, logout\n"
    "|   |-- posts.py         # Create/read/edit posts (ECC encrypted)\n"
    "|   |-- profile.py       # View/edit profile, ECC key fingerprint\n"
    "|   |-- admin.py         # Admin dashboard, user/post/tip mgmt, key rotation\n"
    "|   |-- feed.py          # Public post feed with category/urgency filters\n"
    "|   |-- messages.py      # Encrypted private messaging with expiry\n"
    "|   |-- tips.py          # Anonymous tip submission and admin review\n"
    "|   |-- deaddrops.py     # One-time encrypted dead drops\n"
    "|   |-- friends.py       # Friend/contact management\n"
    "|   +-- sessions.py      # Active session management\n"
    "|\n"
    "|-- templates/           # Jinja2 HTML templates (30+ pages)\n"
    "|-- static/              # style.css, animations.js\n"
    "|-- keys/                # system_rsa.json, hmac_keys.json (server-side only)\n"
    "+-- uploads/             # Encrypted document files (.enc)"
)

subsec("12.2", "README Overview")
para("The repository README covers:")
for pt in [
    "<b>Project description:</b> Secure whistleblower platform for CSE447 with all crypto implemented from scratch.",
    "<b>Requirements:</b> Python 3.12+, pip install flask markupsafe.",
    "<b>Setup:</b> Clone repo → pip install -r requirements.txt → set EMAIL_APP_PASSWORD environment variable for 2FA emails → py app.py.",
    "<b>First run:</b> RSA-1024 key pair and HMAC keys are auto-generated on first startup and saved to keys/.",
    "<b>Database:</b> SQLite database app.db is auto-initialized on first run via init_db().",
    "<b>Admin setup:</b> First user can be promoted to admin via the admin role-change UI or directly in app.db.",
]:
    story.append(Paragraph(f"• {pt}", body_left))
footer_pg()

# ════════════════════════════════════════════════════════════════════════════
# SECTION 13
# ════════════════════════════════════════════════════════════════════════════
sec("13", "Conclusion")
para("The SecureApp project successfully demonstrates a fully functional secure web application "
     "built with cryptographic algorithms implemented entirely from scratch. The primary challenges "
     "were correctly implementing the mathematical foundations of RSA (modular exponentiation, "
     "Miller-Rabin primality testing) and ECC (point arithmetic on secp256k1, Koblitz message "
     "encoding), as small implementation errors can produce silently incorrect results or break "
     "decryption across sessions. Another significant challenge was designing the session management "
     "and 2FA flow without any third-party auth libraries, requiring careful attention to token "
     "signing, constant-time comparison, IP binding, and code expiry race conditions.")
para("Through this project, the group gained deep practical insight into how cryptographic "
     "primitives compose into a real security architecture — understanding not just the algorithms "
     "in isolation, but how key wrapping, HMAC integrity chains, and RBAC work together to protect "
     "data at rest and in transit. The final system implements seven cryptographic modules across "
     "30+ routes and templates, with no plaintext sensitive data stored anywhere in the database.")
story += [sp(12), Paragraph("CSE447  |  Spring 2026  |  BRAC University", footer_style)]

# ════════════════════════════════════════════════════════════════════════════
# BUILD
# ════════════════════════════════════════════════════════════════════════════
doc.build(story)
print("PDF generated: CSE447_Project_Report.pdf")
