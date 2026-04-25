"""
Secure messaging routes - Encrypted messages between users.
Messages are encrypted with system RSA for server-side decryption.
"""

from flask import Blueprint, render_template, request, redirect, url_for, flash, g, abort

import database as db
from key_management import key_manager
from crypto.ecc import (ecc_encrypt_string, ecc_decrypt_string,
                         deserialize_ecc_public_key)
from routes import login_required
from routes.posts import _handle_file_upload

messages_bp = Blueprint('messages', __name__)


@messages_bp.route('/messages')
@login_required
def inbox():
    """View message inbox."""
    msgs = db.get_inbox(g.user['id'])
    decrypted_msgs = []

    for msg in msgs:
        try:
            s_enc = msg['subject_enc']
            if s_enc.startswith('ECC:'):
                # Decrypt ECC subject with recipient's (current user's) ECC key
                me = db.get_user_by_id(g.user['id'])
                priv = key_manager.decrypt_user_ecc_private_key(me['ecc_private_key_enc'])
                subject = ecc_decrypt_string(s_enc[4:], priv)
            else:
                subject = key_manager.decrypt_user_data(s_enc)
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
            s_enc = msg['subject_enc']
            if s_enc.startswith('ECC:'):
                # Sender cannot decrypt ECC-encrypted subjects (true E2E: only recipient can)
                subject = '[E2E Encrypted]'
            else:
                subject = key_manager.decrypt_user_data(s_enc)
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
            return render_template('compose_message.html', users=users, selected_id=None)

        try:
            recipient_id = int(recipient_id)
        except ValueError:
            abort(400)

        if recipient_id == g.user['id']:
            flash('You cannot send a message to yourself.', 'danger')
            users = _get_user_list()
            return render_template('compose_message.html', users=users, selected_id=None)

        # Only friends can message each other
        if not db.are_friends(g.user['id'], recipient_id):
            flash('You can only message users who are your friends.', 'danger')
            users = _get_user_list()
            return render_template('compose_message.html', users=users, selected_id=None)

        recipient = db.get_user_by_id(recipient_id)
        if not recipient:
            flash('Recipient not found.', 'danger')
            users = _get_user_list()
            return render_template('compose_message.html', users=users, selected_id=None)

        # Encrypt with recipient's ECC public key (E2E encryption)
        try:
            rec_pub = deserialize_ecc_public_key(recipient['ecc_public_key'])
            subject_enc = 'ECC:' + ecc_encrypt_string(subject, rec_pub)
            content_enc = 'ECC:' + ecc_encrypt_string(content, rec_pub)
        except Exception:
            # Fallback to RSA if ECC key unavailable
            subject_enc = key_manager.encrypt_user_data(subject)
            content_enc = key_manager.encrypt_user_data(content)

        from codenames import generate_codename
        sender_codename = generate_codename() if anonymous else ''

        data_hmac = key_manager.compute_data_hmac(subject_enc, content_enc, g.user['id'])

        new_msg_id = db.create_message(
            sender_id=g.user['id'],
            recipient_id=recipient_id,
            subject_enc=subject_enc,
            content_enc=content_enc,
            sender_codename=sender_codename,
            data_hmac=data_hmac
        )

        # Handle optional file attachment
        _handle_file_upload(message_id=new_msg_id)

        db.create_audit_log(g.user['id'], 'message_sent',
                            f'Message to user #{recipient_id}',
                            request.remote_addr)

        flash('Message sent securely!', 'success')
        return redirect(url_for('messages.sent'))

    users = _get_user_list()
    selected_id = request.args.get('to', type=int)
    return render_template('compose_message.html', users=users, selected_id=selected_id)


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

    # Decrypt subject/content — ECC if prefixed, else legacy RSA
    hmac_ok = None
    try:
        s_enc = msg['subject_enc']
        c_enc = msg['content_enc']

        if s_enc.startswith('ECC:') or c_enc.startswith('ECC:'):
            if msg['recipient_id'] == g.user['id']:
                # Recipient can decrypt with their own ECC private key
                me = db.get_user_by_id(g.user['id'])
                priv = key_manager.decrypt_user_ecc_private_key(me['ecc_private_key_enc'])
                subject = ecc_decrypt_string(s_enc[4:] if s_enc.startswith('ECC:') else s_enc, priv)
                content = ecc_decrypt_string(c_enc[4:] if c_enc.startswith('ECC:') else c_enc, priv)
            else:
                # Sender viewing their sent item — cannot decrypt ECC-encrypted content
                subject = '[E2E Encrypted — Only recipient can read]'
                content = 'This message was encrypted with the recipient\'s ECC public key (secp256k1 ElGamal).\nOnly the intended recipient can decrypt it.'
        else:
            subject = key_manager.decrypt_user_data(s_enc)
            content = key_manager.decrypt_user_data(c_enc)

        # HMAC integrity check over the stored (encrypted) fields
        if msg.get('data_hmac'):
            hmac_ok = key_manager.verify_data_hmac(
                msg['data_hmac'], s_enc, c_enc, msg['sender_id']
            )
    except Exception:
        subject = '[Decryption Error]'
        content = '[Decryption Error]'
        hmac_ok = False

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

    # Fetch attached documents
    raw_docs = db.get_documents_by_message(msg['id'])
    dec_docs = []
    for doc in raw_docs:
        try:
            fname = key_manager.decrypt_user_data(doc['original_filename_enc'])
        except Exception:
            fname = '[Encrypted]'
        dec_docs.append({**doc, 'filename': fname})

    return render_template('view_message.html', message=decrypted, hmac_ok=hmac_ok, documents=dec_docs)


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
    """Get list of accepted friends for recipient selection."""
    friends_raw = db.get_friends(g.user['id'])
    result = []
    for r in friends_raw:
        other_id = r['addressee_id'] if r['requester_id'] == g.user['id'] else r['requester_id']
        other = db.get_user_by_id(other_id)
        if not other:
            continue
        try:
            username = key_manager.decrypt_user_data(other['username_enc'])
        except Exception:
            username = f'User #{other["id"]}'
        result.append({'id': other['id'], 'username': username})
    return result
