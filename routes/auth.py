"""
Authentication routes - Login, Registration, 2FA, Logout.
Implements secure session management with HMAC-signed tokens.
"""

import os
from datetime import datetime, timedelta
from flask import Blueprint, render_template, request, redirect, url_for, flash, g, make_response

import database as db
from key_management import key_manager
from crypto.sha256 import sha256_hex
from crypto.utils import secure_random_bytes
from config import SESSION_DURATION_HOURS, TWO_FA_EXPIRY_MINUTES
from email_sender import send_2fa_code

auth_bp = Blueprint('auth', __name__)


def _create_session_cookie(user_id):
    """Create a signed session cookie after successful authentication."""
    token = sha256_hex(secure_random_bytes(32))
    token_hash = sha256_hex(token.encode('utf-8'))
    csrf_token = sha256_hex(secure_random_bytes(16))
    expires_at = (datetime.utcnow() + timedelta(hours=SESSION_DURATION_HOURS)).isoformat()

    db.create_session(
        token_hash=token_hash,
        user_id=user_id,
        ip_address=request.remote_addr,
        user_agent_hash=sha256_hex(request.headers.get('User-Agent', '').encode('utf-8')),
        csrf_token=csrf_token,
        expires_at=expires_at
    )

    # Sign token with HMAC
    signature = key_manager.sign_session_token(token)
    return f"{token}.{signature}"


def _mask_email(email):
    """Mask an email for display: 'user@gmail.com' -> 'u***r@gmail.com'."""
    try:
        local, domain = email.split('@')
        if len(local) <= 2:
            masked = local[0] + '***'
        else:
            masked = local[0] + '***' + local[-1]
        return f"{masked}@{domain}"
    except Exception:
        return '***@***'


@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if g.user:
        return redirect(url_for('posts.my_posts'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        phone = request.form.get('phone', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')

        # Validation
        if not username or not email or not password:
            flash('Username, email, and password are required.', 'danger')
            return render_template('register.html')

        if len(username) < 3 or len(username) > 50:
            flash('Username must be 3-50 characters.', 'danger')
            return render_template('register.html')

        if len(password) < 6:
            flash('Password must be at least 6 characters.', 'danger')
            return render_template('register.html')

        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('register.html')

        # Check if username or email already exists
        username_hash = key_manager.hash_for_lookup(username.lower())
        email_hash = key_manager.hash_for_lookup(email.lower())

        if db.get_user_by_username_hash(username_hash):
            flash('Username already taken.', 'danger')
            return render_template('register.html')

        if db.get_user_by_email_hash(email_hash):
            flash('Email already registered.', 'danger')
            return render_template('register.html')

        # Encrypt user data with RSA
        username_enc = key_manager.encrypt_user_data(username)
        email_enc = key_manager.encrypt_user_data(email)
        phone_enc = key_manager.encrypt_user_data(phone) if phone else ''

        # Hash and salt password
        salt = secure_random_bytes(16).hex()
        password_hash = key_manager.hash_password(password, salt)

        # Generate ECC key pair for user
        ecc_pub_str, ecc_priv_enc = key_manager.generate_user_ecc_keys()

        # Compute data integrity HMAC
        data_hmac = key_manager.compute_data_hmac(
            username_hash, email_hash, password_hash
        )

        # Store user
        user_id = db.create_user(
            username_hash=username_hash,
            username_enc=username_enc,
            email_hash=email_hash,
            email_enc=email_enc,
            phone_enc=phone_enc,
            password_hash=password_hash,
            password_salt=salt,
            role='user',
            ecc_public_key=ecc_pub_str,
            ecc_private_key_enc=ecc_priv_enc,
            data_hmac=data_hmac
        )

        if user_id:
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('auth.login'))
        else:
            flash('Registration failed. Username or email may already exist.', 'danger')

    return render_template('register.html')


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if g.user:
        return redirect(url_for('posts.my_posts'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        if not username or not password:
            flash('Please enter username and password.', 'danger')
            return render_template('login.html')

        # Look up user by username hash
        username_hash = key_manager.hash_for_lookup(username.lower())
        user = db.get_user_by_username_hash(username_hash)

        if not user:
            flash('Invalid username or password.', 'danger')
            return render_template('login.html')

        # Verify password
        password_hash = key_manager.hash_password(password, user['password_salt'])
        if password_hash != user['password_hash']:
            flash('Invalid username or password.', 'danger')
            return render_template('login.html')

        # Verify data integrity HMAC
        if user['data_hmac']:
            if not key_manager.verify_data_hmac(
                user['data_hmac'],
                user['username_hash'], user['email_hash'], user['password_hash']
            ):
                flash('Data integrity check failed. Account may be compromised.', 'danger')
                return render_template('login.html')

        # Generate 2FA code
        code = str(int.from_bytes(secure_random_bytes(3), 'big') % 1000000).zfill(6)
        code_hash = sha256_hex(code.encode('utf-8'))
        expires_at = (datetime.utcnow() + timedelta(minutes=TWO_FA_EXPIRY_MINUTES)).isoformat()

        db.create_2fa_code(user['id'], code_hash, expires_at)

        # Decrypt user's email to send the 2FA code
        user_email = key_manager.decrypt_user_data(user['email_enc'])
        email_sent = send_2fa_code(user_email, code)

        # Store user_id in a temporary signed cookie for 2FA step
        temp_token = sha256_hex(secure_random_bytes(16))
        temp_sig = key_manager.sign_session_token(temp_token)

        # Store mapping: temp_token -> user_id (use session table with short expiry)
        db.create_session(
            token_hash=sha256_hex(temp_token.encode('utf-8')),
            user_id=user['id'],
            ip_address=request.remote_addr,
            user_agent_hash='2fa_pending',
            csrf_token='',
            expires_at=expires_at
        )

        response = make_response(render_template('verify_2fa.html', email_sent=email_sent, email_hint=_mask_email(user_email)))
        response.set_cookie(
            '2fa_token',
            f"{temp_token}.{temp_sig}",
            httponly=True,
            samesite='Strict',
            max_age=TWO_FA_EXPIRY_MINUTES * 60
        )
        return response

    return render_template('login.html')


@auth_bp.route('/verify-2fa', methods=['POST'])
def verify_2fa():
    code = request.form.get('code', '').strip()

    if not code:
        flash('Please enter the verification code.', 'danger')
        return render_template('verify_2fa.html')

    # Get 2FA token from cookie
    token_cookie = request.cookies.get('2fa_token', '')
    parts = token_cookie.split('.')
    if len(parts) != 2:
        flash('Invalid session. Please log in again.', 'danger')
        return redirect(url_for('auth.login'))

    temp_token, sig = parts
    expected_sig = key_manager.sign_session_token(temp_token)

    # Verify signature
    from crypto.utils import constant_time_compare
    if not constant_time_compare(sig, expected_sig):
        flash('Invalid session. Please log in again.', 'danger')
        return redirect(url_for('auth.login'))

    # Look up temp session
    token_hash = sha256_hex(temp_token.encode('utf-8'))
    temp_session = db.get_session(token_hash)

    if not temp_session or temp_session['user_agent_hash'] != '2fa_pending':
        flash('Session expired. Please log in again.', 'danger')
        return redirect(url_for('auth.login'))

    user_id = temp_session['user_id']

    # Verify 2FA code
    code_hash = sha256_hex(code.encode('utf-8'))
    if not db.verify_2fa_code(user_id, code_hash):
        flash('Invalid or expired verification code.', 'danger')
        return render_template('verify_2fa.html')

    # Clean up temp session
    db.delete_session(token_hash)

    # Create real session
    session_cookie = _create_session_cookie(user_id)

    response = make_response(redirect(url_for('posts.my_posts')))
    response.set_cookie(
        'session_token',
        session_cookie,
        httponly=True,
        samesite='Strict',
        max_age=SESSION_DURATION_HOURS * 3600
    )
    response.delete_cookie('2fa_token')
    flash('Login successful!', 'success')
    return response


@auth_bp.route('/logout')
def logout():
    cookie = request.cookies.get('session_token', '')
    parts = cookie.split('.')
    if len(parts) == 2:
        token = parts[0]
        token_hash = sha256_hex(token.encode('utf-8'))
        db.delete_session(token_hash)

    response = make_response(redirect(url_for('auth.login')))
    response.delete_cookie('session_token')
    flash('You have been logged out.', 'info')
    return response
