"""
SecureApp - CSE447 Lab Project
Flask web application with end-to-end encryption, 2FA, RBAC, and HMAC integrity.

Encryption algorithms implemented from scratch:
  - RSA (1024-bit) for user profile data
  - ECC ElGamal (secp256k1) for post data
  - SHA-256 for password hashing
  - HMAC-SHA256 for data integrity
"""

import os
from datetime import datetime
from flask import Flask, g, request, redirect, url_for, render_template
from markupsafe import Markup

import config
import database as db
from key_management import key_manager
from crypto.sha256 import sha256_hex
from crypto.utils import constant_time_compare, secure_random_bytes

from routes.auth import auth_bp
from routes.posts import posts_bp
from routes.profile import profile_bp
from routes.admin import admin_bp
from routes.feed import feed_bp
from routes.tips import tips_bp
from routes.messages import messages_bp
from routes.deaddrops import deaddrops_bp


def create_app():
    app = Flask(__name__)
    app.secret_key = config.FLASK_SECRET

    # Register blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(posts_bp)
    app.register_blueprint(profile_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(feed_bp)
    app.register_blueprint(tips_bp)
    app.register_blueprint(messages_bp)
    app.register_blueprint(deaddrops_bp)

    # Custom template filter for newlines
    @app.template_filter('nl2br')
    def nl2br_filter(s):
        if not s:
            return s
        from markupsafe import escape
        return Markup(str(escape(s)).replace('\n', '<br>'))

    # Session validation middleware
    @app.before_request
    def load_user():
        g.user = None
        g.csrf_token = None
        g.user_display_name = None

        # Skip session check for static files
        if request.endpoint == 'static':
            return

        cookie = request.cookies.get('session_token', '')
        if not cookie:
            return

        parts = cookie.split('.')
        if len(parts) != 2:
            return

        token, sig = parts

        # Verify HMAC signature
        expected_sig = key_manager.sign_session_token(token)
        if not constant_time_compare(sig, expected_sig):
            return

        # Look up session in database
        token_hash = sha256_hex(token.encode('utf-8'))
        session = db.get_session(token_hash)
        if not session:
            return

        # Check expiry
        try:
            expires = datetime.fromisoformat(session['expires_at'])
            if expires < datetime.utcnow():
                db.delete_session(token_hash)
                return
        except (ValueError, TypeError):
            return

        # Verify IP binding
        if session['ip_address'] != request.remote_addr:
            return

        # Skip user-agent check for 2FA pending sessions
        if session['user_agent_hash'] == '2fa_pending':
            return

        # Load user
        user = db.get_user_by_id(session['user_id'])
        if user:
            g.user = user
            g.csrf_token = session['csrf_token']
            # Decrypt display name
            try:
                g.user_display_name = key_manager.decrypt_user_data(user['username_enc'])
            except Exception:
                g.user_display_name = 'User'
            # Unread message count for navbar
            g.unread_count = db.count_unread_messages(user['id'])

    # Cleanup expired sessions periodically
    @app.before_request
    def periodic_cleanup():
        # Run cleanup roughly every 100 requests
        if int.from_bytes(os.urandom(1), 'big') < 3:
            db.cleanup_expired_sessions()

    # Root route
    @app.route('/')
    def index():
        if g.user:
            return redirect(url_for('feed.public_feed'))
        return render_template('index.html')

    # Error handlers
    @app.errorhandler(403)
    def forbidden(e):
        return render_template('403.html'), 403

    @app.errorhandler(404)
    def not_found(e):
        return render_template('404.html'), 404

    return app


def initialize():
    """Initialize the application: keys, database, admin account."""
    print("=" * 50)
    print("SecureApp - Initialization")
    print("=" * 50)

    # Initialize key manager (generates keys on first run)
    key_manager.initialize()

    # Initialize database
    print("[Database] Initializing tables...")
    db.init_db()

    # Create default admin if no users exist
    if db.count_users() == 0:
        print("[Setup] Creating default admin account...")
        admin_username = 'admin'
        admin_email = 'admin@secureapp.local'
        admin_password = 'admin123'

        username_hash = key_manager.hash_for_lookup(admin_username.lower())
        email_hash = key_manager.hash_for_lookup(admin_email.lower())
        username_enc = key_manager.encrypt_user_data(admin_username)
        email_enc = key_manager.encrypt_user_data(admin_email)

        salt = secure_random_bytes(16).hex()
        password_hash = key_manager.hash_password(admin_password, salt)

        ecc_pub_str, ecc_priv_enc = key_manager.generate_user_ecc_keys()

        data_hmac = key_manager.compute_data_hmac(username_hash, email_hash, password_hash)

        db.create_user(
            username_hash=username_hash,
            username_enc=username_enc,
            email_hash=email_hash,
            email_enc=email_enc,
            phone_enc='',
            password_hash=password_hash,
            password_salt=salt,
            role='admin',
            ecc_public_key=ecc_pub_str,
            ecc_private_key_enc=ecc_priv_enc,
            data_hmac=data_hmac
        )
        print("[Setup] Admin account created: username='admin', password='admin123'")

    print("=" * 50)
    print("Initialization complete. Starting server...")
    print("=" * 50)


if __name__ == '__main__':
    initialize()
    app = create_app()
    app.run(debug=True, host='127.0.0.1', port=5000)
