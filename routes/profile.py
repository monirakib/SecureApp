"""
Profile routes - View and update user profile.
Profile data is encrypted with RSA and decrypted on retrieval.
"""

from flask import Blueprint, render_template, request, redirect, url_for, flash, g, abort

import database as db
from key_management import key_manager
from crypto.utils import secure_random_bytes
from routes import login_required

profile_bp = Blueprint('profile', __name__)


@profile_bp.route('/profile')
@login_required
def view_profile():
    """View current user's profile (decrypted)."""
    user = g.user

    # Decrypt user data
    try:
        username = key_manager.decrypt_user_data(user['username_enc'])
        email = key_manager.decrypt_user_data(user['email_enc'])
        phone = key_manager.decrypt_user_data(user['phone_enc']) if user['phone_enc'] else ''
    except Exception:
        flash('Error decrypting profile data.', 'danger')
        username = '[Decryption Error]'
        email = '[Decryption Error]'
        phone = ''

    profile = {
        'username': username,
        'email': email,
        'phone': phone,
        'role': user['role'],
        'created_at': user['created_at']
    }

    return render_template('profile.html', profile=profile)


@profile_bp.route('/profile/edit', methods=['GET', 'POST'])
@login_required
def edit_profile():
    """Edit user profile."""
    user = g.user

    if request.method == 'POST':
        csrf = request.form.get('csrf_token', '')
        if csrf != g.csrf_token:
            abort(403)

        email = request.form.get('email', '').strip()
        phone = request.form.get('phone', '').strip()
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')
        current_password = request.form.get('current_password', '')

        if not email:
            flash('Email is required.', 'danger')
            return redirect(url_for('profile.edit_profile'))

        # Verify current password
        if not current_password:
            flash('Current password is required to make changes.', 'danger')
            return redirect(url_for('profile.edit_profile'))

        password_hash = key_manager.hash_password(current_password, user['password_salt'])
        if password_hash != user['password_hash']:
            flash('Current password is incorrect.', 'danger')
            return redirect(url_for('profile.edit_profile'))

        # Prepare updates
        updates = {}

        # Update email
        email_hash = key_manager.hash_for_lookup(email.lower())
        if email_hash != user['email_hash']:
            # Check if new email is taken
            existing = db.get_user_by_email_hash(email_hash)
            if existing and existing['id'] != user['id']:
                flash('Email already in use.', 'danger')
                return redirect(url_for('profile.edit_profile'))
            updates['email_hash'] = email_hash
            updates['email_enc'] = key_manager.encrypt_user_data(email)

        # Update phone
        phone_enc = key_manager.encrypt_user_data(phone) if phone else ''
        updates['phone_enc'] = phone_enc

        # Update password if provided
        if new_password:
            if len(new_password) < 6:
                flash('New password must be at least 6 characters.', 'danger')
                return redirect(url_for('profile.edit_profile'))
            if new_password != confirm_password:
                flash('New passwords do not match.', 'danger')
                return redirect(url_for('profile.edit_profile'))

            salt = secure_random_bytes(16).hex()
            updates['password_salt'] = salt
            updates['password_hash'] = key_manager.hash_password(new_password, salt)

        # Recompute HMAC
        final_username_hash = user['username_hash']
        final_email_hash = updates.get('email_hash', user['email_hash'])
        final_password_hash = updates.get('password_hash', user['password_hash'])
        updates['data_hmac'] = key_manager.compute_data_hmac(
            final_username_hash, final_email_hash, final_password_hash
        )

        db.update_user(user['id'], **updates)
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('profile.view_profile'))

    # GET: decrypt current data for form
    try:
        username = key_manager.decrypt_user_data(user['username_enc'])
        email = key_manager.decrypt_user_data(user['email_enc'])
        phone = key_manager.decrypt_user_data(user['phone_enc']) if user['phone_enc'] else ''
    except Exception:
        username = ''
        email = ''
        phone = ''

    profile = {
        'username': username,
        'email': email,
        'phone': phone
    }

    return render_template('edit_profile.html', profile=profile)
