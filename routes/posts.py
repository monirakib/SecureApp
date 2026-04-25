"""
Post routes - Create, Read, Update, Delete posts.
Posts are encrypted with user's ECC key (ElGamal on secp256k1).
"""

import os
import io
import uuid
from flask import Blueprint, render_template, request, redirect, url_for, flash, g, abort, send_file

import config
import database as db
from key_management import key_manager
from crypto.ecc import (ecc_encrypt_string, ecc_decrypt_string,
                         deserialize_ecc_public_key, serialize_ecc_public_key)
from crypto.symmetric import generate_symmetric_key, encrypt_symmetric, decrypt_symmetric
from codenames import generate_codename
from routes import login_required

posts_bp = Blueprint('posts', __name__)


def _get_user_ecc_keys(user):
    """Get the user's ECC public key and decrypted private key."""
    pub = deserialize_ecc_public_key(user['ecc_public_key'])
    priv = key_manager.decrypt_user_ecc_private_key(user['ecc_private_key_enc'])
    return pub, priv


def _decrypt_post(post, ecc_private_key):
    """Decrypt a post's title and content."""
    try:
        title = ecc_decrypt_string(post['title_enc'], ecc_private_key)
        content = ecc_decrypt_string(post['content_enc'], ecc_private_key)
        return {**post, 'title': title, 'content': content}
    except Exception:
        return {**post, 'title': '[Decryption Error]', 'content': '[Could not decrypt]'}


@posts_bp.route('/posts')
@login_required
def my_posts():
    """View all posts by the current user."""
    posts = db.get_posts_by_user(g.user['id'])
    _, priv = _get_user_ecc_keys(g.user)

    decrypted_posts = []
    for post in posts:
        # Verify HMAC integrity
        if post['data_hmac']:
            if not key_manager.verify_data_hmac(
                post['data_hmac'], post['title_enc'], post['content_enc'], post['user_id']
            ):
                decrypted_posts.append({
                    **post,
                    'title': '[Integrity Check Failed]',
                    'content': '[Data may have been tampered with]',
                    'integrity_ok': False
                })
                continue

        dp = _decrypt_post(post, priv)
        dp['integrity_ok'] = True
        decrypted_posts.append(dp)

    return render_template('my_posts.html', posts=decrypted_posts)


@posts_bp.route('/posts/create', methods=['GET', 'POST'])
@login_required
def create_post():
    """Create a new whistleblower report."""
    if request.method == 'POST':
        csrf = request.form.get('csrf_token', '')
        if csrf != g.csrf_token:
            abort(403)

        title = request.form.get('title', '').strip()
        content = request.form.get('content', '').strip()
        category = request.form.get('category', 'other')
        urgency = request.form.get('urgency', 'medium')
        is_anonymous = 1 if request.form.get('anonymous') == '1' else 0

        if not title or not content:
            flash('Title and content are required.', 'danger')
            return render_template('create_post.html')

        if len(title) > 200:
            flash('Title must be under 200 characters.', 'danger')
            return render_template('create_post.html')

        if category not in config.CATEGORIES:
            category = 'other'
        if urgency not in config.URGENCY_LEVELS:
            urgency = 'medium'

        anonymous_codename = generate_codename() if is_anonymous else ''

        # Encrypt with user's ECC public key
        pub, _ = _get_user_ecc_keys(g.user)
        title_enc = ecc_encrypt_string(title, pub)
        content_enc = ecc_encrypt_string(content, pub)

        # Compute HMAC for integrity
        data_hmac = key_manager.compute_data_hmac(title_enc, content_enc, g.user['id'])

        post_id = db.create_post(g.user['id'], title_enc, content_enc, data_hmac,
                                  category, urgency, is_anonymous, anonymous_codename)

        # Handle file upload
        _handle_file_upload(post_id=post_id)

        db.create_audit_log(g.user['id'], 'report_created',
                            f'Report #{post_id} ({category}/{urgency})',
                            request.remote_addr)

        flash('Report submitted successfully!', 'success')
        return redirect(url_for('posts.view_post', post_id=post_id))

    return render_template('create_post.html')


@posts_bp.route('/posts/<int:post_id>')
@login_required
def view_post(post_id):
    """View a single report - accessible to all authenticated users."""
    post = db.get_post_by_id(post_id)
    if not post:
        abort(404)

    # Get the post owner's ECC keys (server can decrypt via RSA)
    owner = db.get_user_by_id(post['user_id'])
    if not owner:
        abort(404)

    _, priv = _get_user_ecc_keys(owner)
    decrypted = _decrypt_post(post, priv)

    # Handle anonymous vs. named display
    if post.get('is_anonymous'):
        decrypted['owner_name'] = post.get('anonymous_codename', 'Anonymous')
    else:
        decrypted['owner_name'] = key_manager.decrypt_user_data(owner['username_enc'])

    # Get attached documents
    documents = db.get_documents_by_post(post_id)
    dec_docs = []
    for doc in documents:
        try:
            fname = key_manager.decrypt_user_data(doc['original_filename_enc'])
        except Exception:
            fname = '[Encrypted]'
        dec_docs.append({**doc, 'filename': fname})
    decrypted['documents'] = dec_docs

    return render_template('view_post.html', post=decrypted)


@posts_bp.route('/posts/<int:post_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_post(post_id):
    """Edit an existing post."""
    post = db.get_post_by_id(post_id)
    if not post:
        abort(404)

    # Only post owner can edit
    if post['user_id'] != g.user['id']:
        abort(403)

    pub, priv = _get_user_ecc_keys(g.user)

    if request.method == 'POST':
        csrf = request.form.get('csrf_token', '')
        if csrf != g.csrf_token:
            abort(403)

        title = request.form.get('title', '').strip()
        content = request.form.get('content', '').strip()

        if not title or not content:
            flash('Title and content are required.', 'danger')
            decrypted = _decrypt_post(post, priv)
            return render_template('edit_post.html', post=decrypted)

        # Re-encrypt with ECC
        title_enc = ecc_encrypt_string(title, pub)
        content_enc = ecc_encrypt_string(content, pub)
        data_hmac = key_manager.compute_data_hmac(title_enc, content_enc, g.user['id'])

        db.update_post(post_id, title_enc, content_enc, data_hmac)
        flash('Post updated successfully!', 'success')
        return redirect(url_for('posts.view_post', post_id=post_id))

    # Decrypt for editing
    decrypted = _decrypt_post(post, priv)
    return render_template('edit_post.html', post=decrypted)


@posts_bp.route('/posts/<int:post_id>/delete', methods=['POST'])
@login_required
def delete_post(post_id):
    """Delete a post."""
    post = db.get_post_by_id(post_id)
    if not post:
        abort(404)

    # Only post owner or admin can delete
    if post['user_id'] != g.user['id'] and g.user['role'] != 'admin':
        abort(403)

    csrf = request.form.get('csrf_token', '')
    if csrf != g.csrf_token:
        abort(403)

    db.delete_post(post_id)
    flash('Post deleted.', 'info')
    return redirect(url_for('posts.my_posts'))


def _handle_file_upload(post_id=None, tip_id=None):
    """Handle file upload from form, encrypt and store."""
    file = request.files.get('document')
    if not file or not file.filename:
        return None

    # Check file size
    file.seek(0, 2)
    size = file.tell()
    file.seek(0)

    if size > config.MAX_UPLOAD_SIZE:
        flash('File too large. Maximum size is 2MB.', 'warning')
        return None

    if size == 0:
        return None

    # Read file data
    file_data = file.read()

    # Generate symmetric key and encrypt
    sym_key = generate_symmetric_key()
    encrypted_data = encrypt_symmetric(file_data, sym_key)

    # Store encrypted file
    os.makedirs(config.UPLOAD_DIR, exist_ok=True)
    stored_filename = f"{uuid.uuid4().hex}.enc"
    file_path = os.path.join(config.UPLOAD_DIR, stored_filename)
    with open(file_path, 'wb') as f:
        f.write(encrypted_data)

    # Encrypt metadata with RSA
    original_filename_enc = key_manager.encrypt_user_data(file.filename)
    symmetric_key_enc = key_manager.encrypt_user_data(sym_key.hex())

    data_hmac = key_manager.compute_data_hmac(original_filename_enc, stored_filename)

    doc_id = db.create_document(
        original_filename_enc=original_filename_enc,
        stored_filename=stored_filename,
        file_size=size,
        symmetric_key_enc=symmetric_key_enc,
        uploaded_by=g.user['id'] if g.user else None,
        post_id=post_id,
        tip_id=tip_id,
        data_hmac=data_hmac
    )

    return doc_id


@posts_bp.route('/documents/<int:doc_id>/download')
@login_required
def download_document(doc_id):
    """Download and decrypt a document."""
    doc = db.get_document_by_id(doc_id)
    if not doc:
        abort(404)

    # Decrypt symmetric key
    try:
        symmetric_key_hex = key_manager.decrypt_user_data(doc['symmetric_key_enc'])
        symmetric_key = bytes.fromhex(symmetric_key_hex)
    except Exception:
        flash('Could not decrypt document.', 'danger')
        abort(500)

    # Read encrypted file
    file_path = os.path.join(config.UPLOAD_DIR, doc['stored_filename'])
    if not os.path.exists(file_path):
        abort(404)

    with open(file_path, 'rb') as f:
        encrypted_data = f.read()

    # Decrypt
    decrypted_data = decrypt_symmetric(encrypted_data, symmetric_key)

    # Decrypt original filename
    try:
        original_filename = key_manager.decrypt_user_data(doc['original_filename_enc'])
    except Exception:
        original_filename = 'document'

    return send_file(
        io.BytesIO(decrypted_data),
        download_name=original_filename,
        as_attachment=True
    )
