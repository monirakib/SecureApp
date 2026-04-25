"""Route utilities and decorators."""

from functools import wraps
from flask import g, redirect, url_for, abort


def login_required(f):
    """Decorator: require authenticated user."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if g.user is None:
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    """Decorator: require admin role."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if g.user is None:
            return redirect(url_for('auth.login'))
        if g.user['role'] != 'admin':
            abort(403)
        return f(*args, **kwargs)
    return decorated
