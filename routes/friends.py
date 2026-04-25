"""
Friends routes - Send, accept, decline, cancel friend requests. Remove friends.
Only accepted friends can message each other.
"""

from flask import Blueprint, render_template, request, redirect, url_for, flash, g, abort

import database as db
from key_management import key_manager
from routes import login_required

friends_bp = Blueprint('friends', __name__)


def _resolve_user(user):
    """Decrypt username for display, falling back safely."""
    try:
        return key_manager.decrypt_user_data(user['username_enc'])
    except Exception:
        return f'User #{user["id"]}'


@friends_bp.route('/friends')
@login_required
def friends_page():
    """Friends list with pending requests."""
    me = g.user['id']

    # Pending requests I received
    received_raw = db.get_pending_requests_received(me)
    received = []
    for r in received_raw:
        sender = db.get_user_by_id(r['requester_id'])
        if sender:
            received.append({
                'friendship_id': r['id'],
                'user_id': sender['id'],
                'username': _resolve_user(sender),
                'created_at': r['created_at'],
            })

    # Pending requests I sent
    sent_raw = db.get_pending_requests_sent(me)
    sent = []
    for r in sent_raw:
        target = db.get_user_by_id(r['addressee_id'])
        if target:
            sent.append({
                'friendship_id': r['id'],
                'user_id': target['id'],
                'username': _resolve_user(target),
                'created_at': r['created_at'],
            })

    # Accepted friends
    friends_raw = db.get_friends(me)
    friends = []
    for r in friends_raw:
        other_id = r['addressee_id'] if r['requester_id'] == me else r['requester_id']
        other = db.get_user_by_id(other_id)
        if other:
            friends.append({
                'friendship_id': r['id'],
                'user_id': other['id'],
                'username': _resolve_user(other),
                'since': r.get('updated_at') or r['created_at'],
            })

    return render_template('friends.html',
                           received=received,
                           sent=sent,
                           friends=friends)


@friends_bp.route('/friends/add', methods=['POST'])
@login_required
def add_friend():
    """Send a friend request by username."""
    csrf = request.form.get('csrf_token', '')
    if csrf != g.csrf_token:
        abort(403)

    username = request.form.get('username', '').strip()
    if not username:
        flash('Please enter a username.', 'danger')
        return redirect(url_for('friends.friends_page'))

    username_hash = key_manager.hash_for_lookup(username.lower())
    target = db.get_user_by_username_hash(username_hash)

    if not target:
        flash('User not found.', 'danger')
        return redirect(url_for('friends.friends_page'))

    if target['id'] == g.user['id']:
        flash('You cannot add yourself as a friend.', 'danger')
        return redirect(url_for('friends.friends_page'))

    result = db.send_friend_request(g.user['id'], target['id'])

    messages = {
        'sent':            ('Friend request sent!', 'success'),
        'already_friends': ('You are already friends with this user.', 'info'),
        'already_requested': ('Friend request already sent. Waiting for their response.', 'info'),
        'pending_from_them': ('This user already sent you a friend request. Check your pending requests.', 'info'),
        'error':           ('Could not send friend request.', 'danger'),
    }
    msg, cat = messages.get(result, ('Unknown error.', 'danger'))
    flash(msg, cat)

    db.create_audit_log(g.user['id'], 'friend_request_sent',
                        f'To user #{target["id"]}', request.remote_addr)
    return redirect(url_for('friends.friends_page'))


@friends_bp.route('/friends/accept/<int:friendship_id>', methods=['POST'])
@login_required
def accept_request(friendship_id):
    csrf = request.form.get('csrf_token', '')
    if csrf != g.csrf_token:
        abort(403)

    friendship = db.get_friendship_by_id(friendship_id)
    if not friendship or friendship['addressee_id'] != g.user['id']:
        abort(403)

    db.accept_friend_request(friendship_id, g.user['id'])
    flash('Friend request accepted!', 'success')
    db.create_audit_log(g.user['id'], 'friend_request_accepted',
                        f'From user #{friendship["requester_id"]}', request.remote_addr)
    return redirect(url_for('friends.friends_page'))


@friends_bp.route('/friends/decline/<int:friendship_id>', methods=['POST'])
@login_required
def decline_request(friendship_id):
    csrf = request.form.get('csrf_token', '')
    if csrf != g.csrf_token:
        abort(403)

    friendship = db.get_friendship_by_id(friendship_id)
    if not friendship or friendship['addressee_id'] != g.user['id']:
        abort(403)

    db.decline_friend_request(friendship_id, g.user['id'])
    flash('Friend request declined.', 'info')
    return redirect(url_for('friends.friends_page'))


@friends_bp.route('/friends/cancel/<int:friendship_id>', methods=['POST'])
@login_required
def cancel_request(friendship_id):
    csrf = request.form.get('csrf_token', '')
    if csrf != g.csrf_token:
        abort(403)

    friendship = db.get_friendship_by_id(friendship_id)
    if not friendship or friendship['requester_id'] != g.user['id']:
        abort(403)

    db.cancel_friend_request(friendship_id, g.user['id'])
    flash('Friend request cancelled.', 'info')
    return redirect(url_for('friends.friends_page'))


@friends_bp.route('/friends/remove/<int:friendship_id>', methods=['POST'])
@login_required
def remove_friend(friendship_id):
    csrf = request.form.get('csrf_token', '')
    if csrf != g.csrf_token:
        abort(403)

    friendship = db.get_friendship_by_id(friendship_id)
    if not friendship:
        abort(404)
    if friendship['requester_id'] != g.user['id'] and friendship['addressee_id'] != g.user['id']:
        abort(403)

    other_id = (friendship['addressee_id']
                if friendship['requester_id'] == g.user['id']
                else friendship['requester_id'])
    db.remove_friend(g.user['id'], other_id)
    flash('Friend removed.', 'info')
    return redirect(url_for('friends.friends_page'))
