"""
Dead drop routes - Self-destructing encrypted messages.
Anyone can create or access a dead drop. Messages are destroyed after reading.
"""

import string
from flask import Blueprint, render_template, request, redirect, url_for, flash, g, abort

import database as db
from key_management import key_manager
from crypto.sha256 import sha256_hex
from crypto.utils import secure_random_bytes
from codenames import generate_codename

deaddrops_bp = Blueprint('deaddrops', __name__)


def _generate_access_code():
    """Generate a random 12-character alphanumeric access code."""
    chars = string.ascii_uppercase + string.digits
    code = ''
    for _ in range(12):
        idx = int.from_bytes(secure_random_bytes(1), 'big') % len(chars)
        code += chars[idx]
    # Format as XXX-XXX-XXX-XXX for readability
    return '-'.join([code[i:i+3] for i in range(0, 12, 3)])


@deaddrops_bp.route('/deaddrops', methods=['GET', 'POST'])
def dead_drops_page():
    """Dead drops landing page - create or access."""
    return render_template('deaddrops.html')


@deaddrops_bp.route('/deaddrops/create', methods=['GET', 'POST'])
def create_dead_drop():
    """Create a new dead drop."""
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        content = request.form.get('content', '').strip()
        codename = request.form.get('codename', '').strip()

        if not content:
            flash('Message content is required.', 'danger')
            return render_template('create_deaddrop.html')

        if not codename:
            codename = generate_codename()

        if not title:
            title = 'Dead Drop'

        # Generate access code
        access_code = _generate_access_code()
        access_code_hash = sha256_hex(access_code.encode('utf-8'))

        # Encrypt with system RSA
        title_enc = key_manager.encrypt_user_data(title)
        content_enc = key_manager.encrypt_user_data(content)

        data_hmac = key_manager.compute_data_hmac(title_enc, content_enc, access_code_hash)

        # Optional expiry (24 hours by default)
        from datetime import datetime, timedelta
        expires_at = (datetime.utcnow() + timedelta(hours=24)).isoformat()

        db.create_dead_drop(access_code_hash, title_enc, content_enc, codename, data_hmac, expires_at)

        db.create_audit_log(
            g.user['id'] if g.user else None,
            'dead_drop_created',
            f'Dead drop created by {codename}',
            request.remote_addr
        )

        return render_template('deaddrop_created.html', access_code=access_code, codename=codename)

    return render_template('create_deaddrop.html')


@deaddrops_bp.route('/deaddrops/access', methods=['POST'])
def access_dead_drop():
    """Access and destroy a dead drop."""
    access_code = request.form.get('access_code', '').strip().upper()

    if not access_code:
        flash('Please enter an access code.', 'danger')
        return redirect(url_for('deaddrops.dead_drops_page'))

    # Normalize: remove dashes
    access_code_clean = access_code.replace('-', '')
    # Re-add dashes for consistency
    if len(access_code_clean) == 12:
        access_code = '-'.join([access_code_clean[i:i+3] for i in range(0, 12, 3)])

    access_code_hash = sha256_hex(access_code.encode('utf-8'))
    drop = db.get_dead_drop_by_code(access_code_hash)

    if not drop:
        flash('Invalid or expired access code. The dead drop may have already been read.', 'danger')
        return redirect(url_for('deaddrops.dead_drops_page'))

    # Decrypt
    try:
        title = key_manager.decrypt_user_data(drop['title_enc'])
        content = key_manager.decrypt_user_data(drop['content_enc'])
    except Exception:
        title = '[Decryption Error]'
        content = '[Decryption Error]'

    # Mark as read (destroyed)
    db.mark_dead_drop_read(drop['id'])

    db.create_audit_log(
        g.user['id'] if g.user else None,
        'dead_drop_accessed',
        f'Dead drop #{drop["id"]} accessed and destroyed',
        request.remote_addr
    )

    decrypted = {
        'title': title,
        'content': content,
        'codename': drop['creator_codename'],
        'created_at': drop['created_at']
    }

    return render_template('view_deaddrop.html', drop=decrypted)
