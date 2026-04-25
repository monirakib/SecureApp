"""
Feed routes - Public feed of all whistleblower reports.
Decrypts posts server-side for all authenticated users.
"""

from flask import Blueprint, render_template, request, g

import database as db
from key_management import key_manager
from crypto.ecc import ecc_decrypt_string
from routes import login_required

feed_bp = Blueprint('feed', __name__)


@feed_bp.route('/feed')
@login_required
def public_feed():
    """View all reports in the system."""
    category_filter = request.args.get('category', '')
    urgency_filter = request.args.get('urgency', '')

    posts = db.get_all_posts()
    decrypted_posts = []

    for post in posts:
        # Apply filters before decryption (optimization)
        if category_filter and post.get('category', 'other') != category_filter:
            continue
        if urgency_filter and post.get('urgency', 'medium') != urgency_filter:
            continue

        owner = db.get_user_by_id(post['user_id'])
        if not owner:
            continue

        try:
            priv = key_manager.decrypt_user_ecc_private_key(owner['ecc_private_key_enc'])
            title = ecc_decrypt_string(post['title_enc'], priv)
            content = ecc_decrypt_string(post['content_enc'], priv)

            if post.get('is_anonymous'):
                owner_name = post.get('anonymous_codename', 'Anonymous')
            else:
                owner_name = key_manager.decrypt_user_data(owner['username_enc'])
        except Exception:
            title = '[Decryption Error]'
            content = '[Could not decrypt]'
            owner_name = '[Unknown]'

        decrypted_posts.append({
            'id': post['id'],
            'title': title,
            'content': content[:200] + '...' if len(content) > 200 else content,
            'owner_name': owner_name,
            'is_anonymous': post.get('is_anonymous', 0),
            'category': post.get('category', 'other'),
            'urgency': post.get('urgency', 'medium'),
            'created_at': post['created_at'],
            'has_documents': db.count_post_documents(post['id']) > 0
        })

    return render_template('feed.html',
                           posts=decrypted_posts,
                           category_filter=category_filter,
                           urgency_filter=urgency_filter)
