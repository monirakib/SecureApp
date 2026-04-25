"""
Secure messaging routes - Encrypted messages between users.
Messages are encrypted with system RSA for server-side decryption.
"""

from flask import Blueprint, render_template, request, redirect, url_for, flash, g, abort

import database as db
from key_management import key_manager
from routes import login_required

messages_bp = Blueprint('messages', __name__)


@messages_bp.route('/messages')
@login_required
def inbox():
    """View message inbox."""
    msgs = db.get_inbox(g.user['id'])
    decrypted_msgs = []

    for msg in msgs:
        try:
            subject = key_manager.decrypt_user_data(msg['subject_enc'])
        except Exception:
            subject = '[Decryption Error]'

        # Get sender name
        if msg['sender_id']:
            sender = db.get_user_by_id(msg['sender_id'])
            if sender:
                try:
                    sender_name = key_manager.decrypt_user_data(sender['username_enc'])
                except Exception:
                    sender_name = msg.get('sender_codename', 'Unknown')
            else:
                sender_name = msg.get('sender_codename', 'Deleted User')
        else:
            sender_name = msg.get('sender_codename', 'Anonymous')

        decrypted_msgs.append({
            'id': msg['id'],
            'subject': subject,
            'sender_name': sender_name,
            'is_read': msg['is_read'],
            'created_at': msg['created_at']
        })

    unread_count = db.count_unread_messages(g.user['id'])
    return render_template('messages_inbox.html', messages=decrypted_msgs, unread_count=unread_count)


@messages_bp.route('/messages/sent')
@login_required
def sent():
    """View sent messages."""
    msgs = db.get_sent_messages(g.user['id'])
    decrypted_msgs = []

    for msg in msgs:
        try:
            subject = key_manager.decrypt_user_data(msg['subject_enc'])
        except Exception:
            subject = '[Decryption Error]'

        recipient = db.get_user_by_id(msg['recipient_id'])
        if recipient:
            try:
                recipient_name = key_manager.decrypt_user_data(recipient['username_enc'])
            except Exception:
                recipient_name = 'Unknown'
        else:
            recipient_name = 'Deleted User'

        decrypted_msgs.append({
            'id': msg['id'],
            'subject': subject,
            'recipient_name': recipient_name,
            'created_at': msg['created_at']
        })

    return render_template('messages_sent.html', messages=decrypted_msgs)


@messages_bp.route('/messages/compose', methods=['GET', 'POST'])
@login_required
def compose():
    """Compose a new encrypted message."""
    if request.method == 'POST':
        csrf = request.form.get('csrf_token', '')
        if csrf != g.csrf_token:
            abort(403)

        recipient_id = request.form.get('recipient_id', '')
        subject = request.form.get('subject', '').strip()
        content = request.form.get('content', '').strip()
        anonymous = request.form.get('anonymous', '') == '1'

        if not recipient_id or not subject or not content:
            flash('Recipient, subject, and content are required.', 'danger')
            users = _get_user_list()
            return render_template('compose_message.html', users=users)

        try:
            recipient_id = int(recipient_id)
        except ValueError:
            abort(400)

        if recipient_id == g.user['id']:
            flash('You cannot send a message to yourself.', 'danger')
            users = _get_user_list()
            return render_template('compose_message.html', users=users)

        recipient = db.get_user_by_id(recipient_id)
        if not recipient:
            flash('Recipient not found.', 'danger')
            users = _get_user_list()
            return render_template('compose_message.html', users=users)

        # Encrypt with system RSA
        subject_enc = key_manager.encrypt_user_data(subject)
        content_enc = key_manager.encrypt_user_data(content)

        from codenames import generate_codename
        sender_codename = generate_codename() if anonymous else ''

        data_hmac = key_manager.compute_data_hmac(subject_enc, content_enc, g.user['id'])

        db.create_message(
            sender_id=g.user['id'],
            recipient_id=recipient_id,
            subject_enc=subject_enc,
            content_enc=content_enc,
            sender_codename=sender_codename,
            data_hmac=data_hmac
        )

        db.create_audit_log(g.user['id'], 'message_sent',
                            f'Message to user #{recipient_id}',
                            request.remote_addr)

        flash('Message sent securely!', 'success')
        return redirect(url_for('messages.sent'))

    users = _get_user_list()
    return render_template('compose_message.html', users=users)


@messages_bp.route('/messages/<int:msg_id>')
@login_required
def view_message(msg_id):
    """View a single message."""
    msg = db.get_message_by_id(msg_id)
    if not msg:
        abort(404)

    # Only sender or recipient can view
    if msg['sender_id'] != g.user['id'] and msg['recipient_id'] != g.user['id']:
        abort(403)

    try:
        subject = key_manager.decrypt_user_data(msg['subject_enc'])
        content = key_manager.decrypt_user_data(msg['content_enc'])
    except Exception:
        subject = '[Decryption Error]'
        content = '[Decryption Error]'

    # Get sender/recipient names
    if msg['sender_id']:
        sender = db.get_user_by_id(msg['sender_id'])
        if sender and not msg.get('sender_codename'):
            try:
                sender_name = key_manager.decrypt_user_data(sender['username_enc'])
            except Exception:
                sender_name = 'Unknown'
        else:
            sender_name = msg.get('sender_codename', 'Anonymous')
    else:
        sender_name = 'Anonymous'

    recipient = db.get_user_by_id(msg['recipient_id'])
    if recipient:
        try:
            recipient_name = key_manager.decrypt_user_data(recipient['username_enc'])
        except Exception:
            recipient_name = 'Unknown'
    else:
        recipient_name = 'Deleted User'

    # Mark as read if recipient is viewing
    if msg['recipient_id'] == g.user['id'] and not msg['is_read']:
        db.mark_message_read(msg_id)

    decrypted = {
        'id': msg['id'],
        'subject': subject,
        'content': content,
        'sender_name': sender_name,
        'recipient_name': recipient_name,
        'sender_id': msg['sender_id'],
        'recipient_id': msg['recipient_id'],
        'is_read': msg['is_read'],
        'created_at': msg['created_at']
    }

    return render_template('view_message.html', message=decrypted)


@messages_bp.route('/messages/<int:msg_id>/delete', methods=['POST'])
@login_required
def delete_message(msg_id):
    """Delete a message."""
    csrf = request.form.get('csrf_token', '')
    if csrf != g.csrf_token:
        abort(403)

    msg = db.get_message_by_id(msg_id)
    if not msg:
        abort(404)

    if msg['sender_id'] != g.user['id'] and msg['recipient_id'] != g.user['id']:
        abort(403)

    db.delete_message(msg_id)
    flash('Message deleted.', 'info')
    return redirect(url_for('messages.inbox'))


def _get_user_list():
    """Get list of users for recipient selection."""
    users = db.get_all_users()
    result = []
    for u in users:
        if u['id'] == g.user['id']:
            continue
        try:
            username = key_manager.decrypt_user_data(u['username_enc'])
        except Exception:
            username = f'User #{u["id"]}'
        result.append({'id': u['id'], 'username': username})
    return result
