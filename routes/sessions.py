"""
Session management routes - Let users view and revoke their active sessions.
Demonstrates secure session management as per project requirements.
"""

from flask import Blueprint, render_template, request, redirect, url_for, flash, g, abort

import database as db
from routes import login_required

sessions_bp = Blueprint('sessions', __name__)


@sessions_bp.route('/sessions')
@login_required
def my_sessions():
    """View all active sessions for the current user."""
    sessions = db.get_user_sessions(g.user['id'])
    current_hash = getattr(g, 'current_session_hash', None)
    return render_template('sessions.html', sessions=sessions, current_hash=current_hash)


@sessions_bp.route('/sessions/revoke/<token_hash>', methods=['POST'])
@login_required
def revoke_session(token_hash):
    """Revoke a single session by its token hash."""
    csrf = request.form.get('csrf_token', '')
    if csrf != g.csrf_token:
        abort(403)

    # Security: only allow revoking own sessions
    sessions = db.get_user_sessions(g.user['id'])
    own_hashes = {s['token_hash'] for s in sessions}
    if token_hash not in own_hashes:
        abort(403)

    # Don't allow revoking the current session via this endpoint
    current_hash = getattr(g, 'current_session_hash', None)
    if token_hash == current_hash:
        flash('Use Logout to end your current session.', 'warning')
        return redirect(url_for('sessions.my_sessions'))

    db.delete_session(token_hash)
    db.create_audit_log(g.user['id'], 'session_revoked', 'Revoked a session', request.remote_addr)
    flash('Session revoked.', 'success')
    return redirect(url_for('sessions.my_sessions'))


@sessions_bp.route('/sessions/revoke-all', methods=['POST'])
@login_required
def revoke_all_sessions():
    """Revoke all sessions except the current one."""
    csrf = request.form.get('csrf_token', '')
    if csrf != g.csrf_token:
        abort(403)

    current_hash = getattr(g, 'current_session_hash', None)
    sessions = db.get_user_sessions(g.user['id'])
    revoked = 0
    for s in sessions:
        if s['token_hash'] != current_hash:
            db.delete_session(s['token_hash'])
            revoked += 1

    db.create_audit_log(g.user['id'], 'sessions_revoked_all',
                        f'Revoked {revoked} other sessions', request.remote_addr)
    flash(f'Revoked {revoked} other session(s). You are still logged in.', 'success')
    return redirect(url_for('sessions.my_sessions'))
