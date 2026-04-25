"""
Anonymous tip routes - Submit and manage anonymous whistleblower tips.
Tips are encrypted with system RSA key. No login required for submission.
"""

from flask import Blueprint, render_template, request, redirect, url_for, flash, g, abort

import database as db
from key_management import key_manager
from codenames import generate_codename
from routes import login_required, admin_required
import config

tips_bp = Blueprint('tips', __name__)


@tips_bp.route('/tips/submit', methods=['GET', 'POST'])
def submit_tip():
    """Submit an anonymous tip - no login required."""
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        content = request.form.get('content', '').strip()
        category = request.form.get('category', 'other')
        urgency = request.form.get('urgency', 'medium')

        if not title or not content:
            flash('Title and content are required.', 'danger')
            return render_template('submit_tip.html')

        if len(title) > 200:
            flash('Title must be under 200 characters.', 'danger')
            return render_template('submit_tip.html')

        if category not in config.CATEGORIES:
            category = 'other'
        if urgency not in config.URGENCY_LEVELS:
            urgency = 'medium'

        # Generate anonymous codename
        codename = generate_codename()

        # Encrypt with system RSA
        title_enc = key_manager.encrypt_user_data(title)
        content_enc = key_manager.encrypt_user_data(content)

        # Compute HMAC
        data_hmac = key_manager.compute_data_hmac(title_enc, content_enc, codename)

        tip_id = db.create_tip(codename, category, urgency, title_enc, content_enc, data_hmac)

        # Audit log
        db.create_audit_log(None, 'tip_submitted',
                            f'Tip #{tip_id} submitted by {codename}',
                            request.remote_addr)

        flash(f'Tip submitted anonymously as {codename}. Your tip ID is #{tip_id}.', 'success')
        return redirect(url_for('tips.tip_submitted', codename=codename))

    return render_template('submit_tip.html')


@tips_bp.route('/tips/submitted')
def tip_submitted():
    """Confirmation page after submitting a tip."""
    codename = request.args.get('codename', 'Anonymous')
    return render_template('tip_submitted.html', codename=codename)


# ---- Admin tip management ----

@tips_bp.route('/admin/tips')
@admin_required
def manage_tips():
    """Admin: view all anonymous tips."""
    status_filter = request.args.get('status', '')
    tips = db.get_all_tips()

    decrypted_tips = []
    for tip in tips:
        if status_filter and tip['status'] != status_filter:
            continue
        try:
            title = key_manager.decrypt_user_data(tip['title_enc'])
            content = key_manager.decrypt_user_data(tip['content_enc'])
            admin_notes = key_manager.decrypt_user_data(tip['admin_notes_enc']) if tip['admin_notes_enc'] else ''
        except Exception:
            title = '[Decryption Error]'
            content = '[Decryption Error]'
            admin_notes = ''

        decrypted_tips.append({
            'id': tip['id'],
            'codename': tip['codename'],
            'category': tip['category'],
            'urgency': tip['urgency'],
            'title': title,
            'content': content,
            'admin_notes': admin_notes,
            'status': tip['status'],
            'created_at': tip['created_at'],
            'has_documents': len(db.get_documents_by_tip(tip['id'])) > 0
        })

    return render_template('admin_tips.html', tips=decrypted_tips, status_filter=status_filter)


@tips_bp.route('/admin/tips/<int:tip_id>')
@admin_required
def view_tip(tip_id):
    """Admin: view a single anonymous tip."""
    tip = db.get_tip_by_id(tip_id)
    if not tip:
        abort(404)

    try:
        title = key_manager.decrypt_user_data(tip['title_enc'])
        content = key_manager.decrypt_user_data(tip['content_enc'])
        admin_notes = key_manager.decrypt_user_data(tip['admin_notes_enc']) if tip['admin_notes_enc'] else ''
    except Exception:
        title = '[Decryption Error]'
        content = '[Decryption Error]'
        admin_notes = ''

    documents = db.get_documents_by_tip(tip_id)
    dec_docs = []
    for doc in documents:
        try:
            fname = key_manager.decrypt_user_data(doc['original_filename_enc'])
        except Exception:
            fname = '[Encrypted]'
        dec_docs.append({**doc, 'filename': fname})

    decrypted = {
        'id': tip['id'],
        'codename': tip['codename'],
        'category': tip['category'],
        'urgency': tip['urgency'],
        'title': title,
        'content': content,
        'admin_notes': admin_notes,
        'status': tip['status'],
        'created_at': tip['created_at'],
        'documents': dec_docs
    }

    return render_template('view_tip.html', tip=decrypted)


@tips_bp.route('/admin/tips/<int:tip_id>/status', methods=['POST'])
@admin_required
def update_tip_status(tip_id):
    """Admin: update tip status and notes."""
    csrf = request.form.get('csrf_token', '')
    if csrf != g.csrf_token:
        abort(403)

    tip = db.get_tip_by_id(tip_id)
    if not tip:
        abort(404)

    new_status = request.form.get('status', 'new')
    admin_notes = request.form.get('admin_notes', '').strip()

    if new_status not in ('new', 'reviewing', 'resolved', 'dismissed'):
        new_status = 'new'

    admin_notes_enc = key_manager.encrypt_user_data(admin_notes) if admin_notes else ''

    db.update_tip_status(tip_id, new_status, admin_notes_enc)

    db.create_audit_log(g.user['id'], 'tip_status_updated',
                        f'Tip #{tip_id} status → {new_status}',
                        request.remote_addr)

    flash(f'Tip #{tip_id} status updated to {new_status}.', 'success')
    return redirect(url_for('tips.view_tip', tip_id=tip_id))


@tips_bp.route('/admin/tips/<int:tip_id>/delete', methods=['POST'])
@admin_required
def delete_tip(tip_id):
    """Admin: delete a tip."""
    csrf = request.form.get('csrf_token', '')
    if csrf != g.csrf_token:
        abort(403)

    db.delete_tip(tip_id)
    db.create_audit_log(g.user['id'], 'tip_deleted', f'Tip #{tip_id} deleted', request.remote_addr)

    flash('Tip deleted.', 'info')
    return redirect(url_for('tips.manage_tips'))


@tips_bp.route('/admin/tips/bulk-action', methods=['POST'])
@admin_required
def bulk_action_tips():
    """Admin: bulk update tip status."""
    csrf = request.form.get('csrf_token', '')
    if csrf != g.csrf_token:
        abort(403)

    action = request.form.get('bulk_action', '')
    tip_ids = request.form.getlist('tip_ids')

    if not tip_ids:
        flash('No tips selected.', 'warning')
        return redirect(url_for('tips.manage_tips'))

    valid_statuses = {'resolve': 'resolved', 'dismiss': 'dismissed', 'review': 'reviewing'}
    if action not in valid_statuses:
        flash('Invalid action.', 'danger')
        return redirect(url_for('tips.manage_tips'))

    try:
        tip_ids_int = [int(t) for t in tip_ids]
    except ValueError:
        abort(400)

    new_status = valid_statuses[action]
    db.bulk_update_tips_status(tip_ids_int, new_status)
    db.create_audit_log(g.user['id'], 'tips_bulk_updated',
                        f'{len(tip_ids_int)} tips -> {new_status}', request.remote_addr)
    flash(f'{len(tip_ids_int)} tip(s) marked as {new_status}.', 'success')
    return redirect(url_for('tips.manage_tips'))
