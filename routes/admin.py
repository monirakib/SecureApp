"""
Admin routes - Admin dashboard, user management, post management, key rotation.
Implements Role-Based Access Control (RBAC) - admin only.
"""

from flask import Blueprint, render_template, request, redirect, url_for, flash, g, abort

import database as db
from key_management import key_manager
from crypto.ecc import (ecc_encrypt_string, ecc_decrypt_string,
                         deserialize_ecc_public_key, generate_ecc_keypair,
                         serialize_ecc_public_key, serialize_ecc_private_key)
from crypto.rsa import rsa_encrypt_string, rsa_decrypt_string
from routes import admin_required

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')


@admin_bp.route('/')
@admin_required
def dashboard():
    """Admin dashboard with system overview."""
    user_count = db.count_users()
    post_count = db.count_posts()
    tip_count = db.count_tips()
    new_tips = db.count_tips_by_status('new')
    doc_count = db.count_documents()
    drop_count = db.count_dead_drops()
    rotation_log = db.get_key_rotation_log()
    failed_logins = db.get_recent_failed_logins(10)

    return render_template('admin_dashboard.html',
                           user_count=user_count,
                           post_count=post_count,
                           tip_count=tip_count,
                           new_tips=new_tips,
                           doc_count=doc_count,
                           drop_count=drop_count,
                           rotation_log=rotation_log,
                           failed_logins=failed_logins)


@admin_bp.route('/users')
@admin_required
def manage_users():
    """View and manage all users."""
    users = db.get_all_users()
    decrypted_users = []

    for user in users:
        try:
            username = key_manager.decrypt_user_data(user['username_enc'])
            email = key_manager.decrypt_user_data(user['email_enc'])
        except Exception:
            username = '[Decryption Error]'
            email = '[Decryption Error]'

        decrypted_users.append({
            'id': user['id'],
            'username': username,
            'email': email,
            'role': user['role'],
            'created_at': user['created_at']
        })

    return render_template('admin_users.html', users=decrypted_users)


@admin_bp.route('/users/<int:user_id>/role', methods=['POST'])
@admin_required
def change_role(user_id):
    """Change a user's role (admin/user)."""
    csrf = request.form.get('csrf_token', '')
    if csrf != g.csrf_token:
        abort(403)

    user = db.get_user_by_id(user_id)
    if not user:
        abort(404)

    # Don't allow changing own role
    if user_id == g.user['id']:
        flash('You cannot change your own role.', 'danger')
        return redirect(url_for('admin.manage_users'))

    new_role = 'admin' if user['role'] == 'user' else 'user'
    db.update_user(user_id, role=new_role)
    flash(f'User role changed to {new_role}.', 'success')
    return redirect(url_for('admin.manage_users'))


@admin_bp.route('/users/<int:user_id>/delete', methods=['POST'])
@admin_required
def delete_user(user_id):
    """Delete a user account."""
    csrf = request.form.get('csrf_token', '')
    if csrf != g.csrf_token:
        abort(403)

    if user_id == g.user['id']:
        flash('You cannot delete your own account.', 'danger')
        return redirect(url_for('admin.manage_users'))

    user = db.get_user_by_id(user_id)
    if not user:
        abort(404)

    db.delete_user_sessions(user_id)
    db.delete_user(user_id)
    flash('User deleted.', 'info')
    return redirect(url_for('admin.manage_users'))


@admin_bp.route('/posts')
@admin_required
def manage_posts():
    """View all posts in the system."""
    posts = db.get_all_posts()
    decrypted_posts = []

    for post in posts:
        owner = db.get_user_by_id(post['user_id'])
        if owner:
            try:
                owner_name = key_manager.decrypt_user_data(owner['username_enc'])
                priv = key_manager.decrypt_user_ecc_private_key(owner['ecc_private_key_enc'])
                title = ecc_decrypt_string(post['title_enc'], priv)
            except Exception:
                owner_name = '[Error]'
                title = '[Decryption Error]'
        else:
            owner_name = '[Deleted User]'
            title = '[Cannot Decrypt]'

        decrypted_posts.append({
            'id': post['id'],
            'title': title,
            'owner_name': owner_name,
            'category': post.get('category', 'other'),
            'urgency': post.get('urgency', 'medium'),
            'status': post.get('status', 'new'),
            'is_anonymous': post.get('is_anonymous', 0),
            'created_at': post['created_at']
        })

    return render_template('admin_posts.html', posts=decrypted_posts)


@admin_bp.route('/posts/<int:post_id>/delete', methods=['POST'])
@admin_required
def admin_delete_post(post_id):
    """Admin: delete any post."""
    csrf = request.form.get('csrf_token', '')
    if csrf != g.csrf_token:
        abort(403)

    post = db.get_post_by_id(post_id)
    if not post:
        abort(404)

    db.delete_post(post_id)
    flash('Post deleted.', 'info')
    return redirect(url_for('admin.manage_posts'))


@admin_bp.route('/posts/<int:post_id>/status', methods=['POST'])
@admin_required
def update_post_status(post_id):
    """Admin: change post status."""
    csrf = request.form.get('csrf_token', '')
    if csrf != g.csrf_token:
        abort(403)

    status = request.form.get('status', 'new')
    if status not in ('new', 'reviewing', 'resolved'):
        abort(400)

    post = db.get_post_by_id(post_id)
    if not post:
        abort(404)

    db.update_post_status(post_id, status)
    db.create_audit_log(g.user['id'], 'post_status_changed',
                        f'Post #{post_id} status -> {status}', request.remote_addr)
    flash(f'Post status updated to {status}.', 'success')
    return redirect(request.referrer or url_for('posts.view_post', post_id=post_id))


@admin_bp.route('/keys')
@admin_required
def key_management_page():
    """Key management dashboard."""
    rotation_log = db.get_key_rotation_log()
    user_count = db.count_users()
    return render_template('admin_keys.html',
                           rotation_log=rotation_log,
                           user_count=user_count)


@admin_bp.route('/keys/rotate-rsa', methods=['POST'])
@admin_required
def rotate_rsa_keys():
    """Rotate system RSA keys and re-encrypt all user data."""
    csrf = request.form.get('csrf_token', '')
    if csrf != g.csrf_token:
        abort(403)

    try:
        old_public, old_private = key_manager.rotate_rsa_keys()

        # Re-encrypt all user data with new RSA keys
        users = db.get_all_users()
        for user in users:
            # Decrypt with old keys
            username = rsa_decrypt_string(user['username_enc'], old_private)
            email = rsa_decrypt_string(user['email_enc'], old_private)
            phone = rsa_decrypt_string(user['phone_enc'], old_private) if user['phone_enc'] else ''
            ecc_priv_str = rsa_decrypt_string(user['ecc_private_key_enc'], old_private)

            # Re-encrypt with new keys
            updates = {
                'username_enc': key_manager.encrypt_user_data(username),
                'email_enc': key_manager.encrypt_user_data(email),
                'phone_enc': key_manager.encrypt_user_data(phone) if phone else '',
                'ecc_private_key_enc': rsa_encrypt_string(ecc_priv_str, key_manager.rsa_public_key),
            }

            # Recompute HMAC
            updates['data_hmac'] = key_manager.compute_data_hmac(
                user['username_hash'], user['email_hash'], user['password_hash']
            )

            db.update_user(user['id'], **updates)

        db.log_key_rotation('RSA', g.user['id'])
        flash(f'RSA keys rotated. {len(users)} user records re-encrypted.', 'success')

    except Exception as e:
        flash(f'Key rotation failed: {str(e)}', 'danger')

    return redirect(url_for('admin.key_management_page'))


@admin_bp.route('/keys/rotate-hmac', methods=['POST'])
@admin_required
def rotate_hmac_keys():
    """Rotate HMAC keys and re-sign every existing record with the new key."""
    csrf = request.form.get('csrf_token', '')
    if csrf != g.csrf_token:
        abort(403)

    try:
        key_manager.rotate_hmac_keys()

        # Re-sign all users
        for user in db.get_all_users():
            new_hmac = key_manager.compute_data_hmac(
                user['username_hash'], user['email_hash'], user['password_hash']
            )
            db.update_record_hmac('users', user['id'], new_hmac)

        # Re-sign all posts
        all_posts = db.get_all_posts()
        for post in all_posts:
            new_hmac = key_manager.compute_data_hmac(
                post['title_enc'], post['content_enc'], post['user_id']
            )
            db.update_record_hmac('posts', post['id'], new_hmac)

        # Re-sign all messages
        for msg in db.get_all_messages_for_rotation():
            new_hmac = key_manager.compute_data_hmac(
                msg['subject_enc'], msg['content_enc'], msg['sender_id']
            )
            db.update_record_hmac('messages', msg['id'], new_hmac)

        # Re-sign all anonymous tips
        for tip in db.get_all_tips():
            new_hmac = key_manager.compute_data_hmac(
                tip['title_enc'], tip['content_enc'], tip['codename']
            )
            db.update_record_hmac('anonymous_tips', tip['id'], new_hmac)

        # Re-sign all dead drops
        for drop in db.get_all_dead_drops_for_rotation():
            new_hmac = key_manager.compute_data_hmac(
                drop['title_enc'], drop['content_enc'], drop['access_code_hash']
            )
            db.update_record_hmac('dead_drops', drop['id'], new_hmac)

        # Re-sign all post comments
        for comment in db.get_all_post_comments_for_rotation():
            new_hmac = key_manager.compute_data_hmac(
                comment['content_enc'], str(comment['post_id'])
            )
            db.update_record_hmac('post_comments', comment['id'], new_hmac)

        # Re-sign all documents
        for doc in db.get_all_documents_for_rotation():
            new_hmac = key_manager.compute_data_hmac(
                doc['original_filename_enc'], doc['stored_filename']
            )
            db.update_record_hmac('documents', doc['id'], new_hmac)

        db.log_key_rotation('HMAC', g.user['id'])
        flash('HMAC keys rotated and all records re-signed successfully.', 'success')
    except Exception as e:
        flash(f'HMAC key rotation failed: {str(e)}', 'danger')

    return redirect(url_for('admin.key_management_page'))


@admin_bp.route('/audit')
@admin_required
def audit_log():
    """View system audit log."""
    logs = db.get_audit_log(limit=200)
    enriched_logs = []
    for log in logs:
        if log['user_id']:
            user = db.get_user_by_id(log['user_id'])
            if user:
                try:
                    username = key_manager.decrypt_user_data(user['username_enc'])
                except Exception:
                    username = f'User #{log["user_id"]}'
            else:
                username = 'Deleted User'
        else:
            username = 'Anonymous'
        enriched_logs.append({**log, 'username': username})

    return render_template('admin_audit.html', logs=enriched_logs)
