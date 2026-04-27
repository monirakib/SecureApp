"""
Database module - SQLite database setup and CRUD operations.
All data is stored encrypted; this module handles raw storage/retrieval.
"""

import sqlite3
import os
from config import DB_PATH


def get_db():
    """Get a database connection."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    """Initialize database tables."""
    conn = get_db()
    cursor = conn.cursor()

    cursor.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username_hash TEXT UNIQUE NOT NULL,
            username_enc TEXT NOT NULL,
            email_hash TEXT UNIQUE NOT NULL,
            email_enc TEXT NOT NULL,
            phone_enc TEXT DEFAULT '',
            password_hash TEXT NOT NULL,
            password_salt TEXT NOT NULL,
            role TEXT DEFAULT 'user' CHECK(role IN ('user', 'admin')),
            ecc_public_key TEXT,
            ecc_private_key_enc TEXT,
            data_hmac TEXT,
            created_at TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title_enc TEXT NOT NULL,
            content_enc TEXT NOT NULL,
            data_hmac TEXT,
            created_at TEXT DEFAULT (datetime('now')),
            updated_at TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS sessions (
            token_hash TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            ip_address TEXT,
            user_agent_hash TEXT,
            csrf_token TEXT,
            created_at TEXT DEFAULT (datetime('now')),
            expires_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS two_factor_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            code_hash TEXT NOT NULL,
            created_at TEXT DEFAULT (datetime('now')),
            expires_at TEXT NOT NULL,
            used INTEGER DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS key_rotation_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key_type TEXT NOT NULL,
            rotated_at TEXT DEFAULT (datetime('now')),
            rotated_by INTEGER,
            FOREIGN KEY (rotated_by) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS anonymous_tips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            codename TEXT NOT NULL,
            category TEXT DEFAULT 'other',
            urgency TEXT DEFAULT 'medium',
            title_enc TEXT NOT NULL,
            content_enc TEXT NOT NULL,
            data_hmac TEXT,
            status TEXT DEFAULT 'new' CHECK(status IN ('new', 'reviewing', 'resolved', 'dismissed')),
            admin_notes_enc TEXT DEFAULT '',
            created_at TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            original_filename_enc TEXT NOT NULL,
            stored_filename TEXT NOT NULL,
            file_size INTEGER,
            symmetric_key_enc TEXT NOT NULL,
            uploaded_by INTEGER,
            post_id INTEGER,
            tip_id INTEGER,
            data_hmac TEXT,
            created_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (uploaded_by) REFERENCES users(id) ON DELETE SET NULL,
            FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE,
            FOREIGN KEY (tip_id) REFERENCES anonymous_tips(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id INTEGER,
            recipient_id INTEGER NOT NULL,
            subject_enc TEXT NOT NULL,
            content_enc TEXT NOT NULL,
            sender_codename TEXT DEFAULT '',
            is_read INTEGER DEFAULT 0,
            data_hmac TEXT,
            created_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (sender_id) REFERENCES users(id) ON DELETE SET NULL,
            FOREIGN KEY (recipient_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS dead_drops (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            access_code_hash TEXT UNIQUE NOT NULL,
            title_enc TEXT DEFAULT '',
            content_enc TEXT NOT NULL,
            creator_codename TEXT DEFAULT 'Anonymous',
            data_hmac TEXT,
            is_read INTEGER DEFAULT 0,
            expires_at TEXT,
            created_at TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT NOT NULL,
            details TEXT DEFAULT '',
            ip_address TEXT DEFAULT '',
            created_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
        );

        CREATE TABLE IF NOT EXISTS friendships (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            requester_id INTEGER NOT NULL,
            addressee_id INTEGER NOT NULL,
            status TEXT DEFAULT 'pending' CHECK(status IN ('pending', 'accepted', 'declined')),
            created_at TEXT DEFAULT (datetime('now')),
            updated_at TEXT,
            UNIQUE(requester_id, addressee_id),
            FOREIGN KEY (requester_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (addressee_id) REFERENCES users(id) ON DELETE CASCADE
        );
    ''')

    conn.commit()
    conn.close()

    # Migrate existing posts table - add new columns
    _migrate_posts_table()


def _migrate_posts_table():
    """Add new columns to posts table if they don't exist."""
    conn = get_db()
    migrations = [
        "ALTER TABLE posts ADD COLUMN category TEXT DEFAULT 'other'",
        "ALTER TABLE posts ADD COLUMN urgency TEXT DEFAULT 'medium'",
        "ALTER TABLE posts ADD COLUMN is_anonymous INTEGER DEFAULT 0",
        "ALTER TABLE posts ADD COLUMN anonymous_codename TEXT DEFAULT ''",
        "ALTER TABLE documents ADD COLUMN message_id INTEGER",
        "ALTER TABLE documents ADD COLUMN dead_drop_id INTEGER",
        "ALTER TABLE posts ADD COLUMN status TEXT DEFAULT 'new'",
        "ALTER TABLE messages ADD COLUMN expires_at TEXT",
        "ALTER TABLE messages ADD COLUMN is_starred INTEGER DEFAULT 0",
        "ALTER TABLE messages ADD COLUMN is_flagged INTEGER DEFAULT 0",
        "ALTER TABLE messages ADD COLUMN is_vaulted INTEGER DEFAULT 0",
        "ALTER TABLE messages ADD COLUMN sender_subject_enc TEXT DEFAULT ''",
        "ALTER TABLE messages ADD COLUMN sender_content_enc TEXT DEFAULT ''",
    ]
    for sql in migrations:
        try:
            conn.execute(sql)
        except sqlite3.OperationalError:
            pass  # Column already exists
    conn.commit()
    conn.close()

    # Ensure friendships table exists (in case DB was created before this version)
    conn = get_db()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS friendships (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            requester_id INTEGER NOT NULL,
            addressee_id INTEGER NOT NULL,
            status TEXT DEFAULT 'pending' CHECK(status IN ('pending', 'accepted', 'declined')),
            created_at TEXT DEFAULT (datetime('now')),
            updated_at TEXT,
            UNIQUE(requester_id, addressee_id),
            FOREIGN KEY (requester_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (addressee_id) REFERENCES users(id) ON DELETE CASCADE
        )
    ''')
    conn.commit()
    conn.close()

    # Create post_reactions table if it doesn't exist
    conn = get_db()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS post_reactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            post_id INTEGER NOT NULL,
            reaction_type TEXT NOT NULL CHECK(reaction_type IN ('witness', 'corroborate')),
            voter_hash TEXT NOT NULL,
            created_at TEXT DEFAULT (datetime('now')),
            UNIQUE(post_id, reaction_type, voter_hash),
            FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE
        )
    ''')
    conn.commit()
    conn.close()

    # Create post_comments table if it doesn't exist
    conn = get_db()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS post_comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            post_id INTEGER NOT NULL,
            user_id INTEGER,
            commenter_codename TEXT DEFAULT '',
            content_enc TEXT NOT NULL,
            is_anonymous INTEGER DEFAULT 0,
            data_hmac TEXT,
            created_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
        )
    ''')
    conn.commit()
    conn.close()


def create_post_comment(post_id, user_id, content_enc, is_anonymous, commenter_codename, data_hmac):
    """Save an encrypted comment on a post."""
    conn = get_db()
    conn.execute(
        '''INSERT INTO post_comments
           (post_id, user_id, content_enc, is_anonymous, commenter_codename, data_hmac)
           VALUES (?, ?, ?, ?, ?, ?)''',
        (post_id, user_id, content_enc, is_anonymous, commenter_codename, data_hmac)
    )
    conn.commit()
    comment_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.close()
    return comment_id


def get_post_comments(post_id):
    """Return all comments for a post ordered oldest-first."""
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM post_comments WHERE post_id = ? ORDER BY created_at ASC",
        (post_id,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def count_post_comments(post_id):
    conn = get_db()
    count = conn.execute(
        "SELECT COUNT(*) FROM post_comments WHERE post_id = ?", (post_id,)
    ).fetchone()[0]
    conn.close()
    return count


def create_user(username_hash, username_enc, email_hash, email_enc, phone_enc,
                password_hash, password_salt, role, ecc_public_key, ecc_private_key_enc, data_hmac):
    conn = get_db()
    try:
        conn.execute(
            '''INSERT INTO users (username_hash, username_enc, email_hash, email_enc, phone_enc,
               password_hash, password_salt, role, ecc_public_key, ecc_private_key_enc, data_hmac)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
            (username_hash, username_enc, email_hash, email_enc, phone_enc,
             password_hash, password_salt, role, ecc_public_key, ecc_private_key_enc, data_hmac)
        )
        conn.commit()
        return conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    except sqlite3.IntegrityError:
        return None
    finally:
        conn.close()


def get_user_by_username_hash(username_hash):
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE username_hash = ?", (username_hash,)).fetchone()
    conn.close()
    return dict(user) if user else None


def get_user_by_email_hash(email_hash):
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE email_hash = ?", (email_hash,)).fetchone()
    conn.close()
    return dict(user) if user else None


def get_user_by_id(user_id):
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    return dict(user) if user else None


def get_all_users():
    conn = get_db()
    users = conn.execute("SELECT * FROM users ORDER BY created_at DESC").fetchall()
    conn.close()
    return [dict(u) for u in users]


def update_user(user_id, **kwargs):
    conn = get_db()
    set_clauses = ', '.join(f"{k} = ?" for k in kwargs.keys())
    values = list(kwargs.values()) + [user_id]
    conn.execute(f"UPDATE users SET {set_clauses} WHERE id = ?", values)
    conn.commit()
    conn.close()


def delete_user(user_id):
    conn = get_db()
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()


def count_users():
    conn = get_db()
    count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    conn.close()
    return count


# ---- Post operations ----

def create_post(user_id, title_enc, content_enc, data_hmac, category='other', urgency='medium', is_anonymous=0, anonymous_codename=''):
    conn = get_db()
    conn.execute(
        """INSERT INTO posts (user_id, title_enc, content_enc, data_hmac, category, urgency, is_anonymous, anonymous_codename)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (user_id, title_enc, content_enc, data_hmac, category, urgency, is_anonymous, anonymous_codename)
    )
    conn.commit()
    post_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.close()
    return post_id


def get_post_by_id(post_id):
    conn = get_db()
    post = conn.execute("SELECT * FROM posts WHERE id = ?", (post_id,)).fetchone()
    conn.close()
    return dict(post) if post else None


def get_posts_by_user(user_id):
    conn = get_db()
    posts = conn.execute("SELECT * FROM posts WHERE user_id = ? ORDER BY created_at DESC", (user_id,)).fetchall()
    conn.close()
    return [dict(p) for p in posts]


def get_all_posts():
    conn = get_db()
    posts = conn.execute(
        "SELECT posts.*, users.username_enc FROM posts JOIN users ON posts.user_id = users.id ORDER BY posts.created_at DESC"
    ).fetchall()
    conn.close()
    return [dict(p) for p in posts]


def update_post(post_id, title_enc, content_enc, data_hmac):
    conn = get_db()
    conn.execute(
        "UPDATE posts SET title_enc = ?, content_enc = ?, data_hmac = ?, updated_at = datetime('now') WHERE id = ?",
        (title_enc, content_enc, data_hmac, post_id)
    )
    conn.commit()
    conn.close()


def delete_post(post_id):
    conn = get_db()
    conn.execute("DELETE FROM posts WHERE id = ?", (post_id,))
    conn.commit()
    conn.close()


def count_posts():
    conn = get_db()
    count = conn.execute("SELECT COUNT(*) FROM posts").fetchone()[0]
    conn.close()
    return count


# ---- Session operations ----

def create_session(token_hash, user_id, ip_address, user_agent_hash, csrf_token, expires_at):
    conn = get_db()
    conn.execute(
        '''INSERT INTO sessions (token_hash, user_id, ip_address, user_agent_hash, csrf_token, expires_at)
           VALUES (?, ?, ?, ?, ?, ?)''',
        (token_hash, user_id, ip_address, user_agent_hash, csrf_token, expires_at)
    )
    conn.commit()
    conn.close()


def get_session(token_hash):
    conn = get_db()
    session = conn.execute("SELECT * FROM sessions WHERE token_hash = ?", (token_hash,)).fetchone()
    conn.close()
    return dict(session) if session else None


def delete_session(token_hash):
    conn = get_db()
    conn.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))
    conn.commit()
    conn.close()


def delete_user_sessions(user_id):
    conn = get_db()
    conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
    conn.commit()
    conn.close()


def delete_session(token_hash):
    """Delete a single session by its token hash."""
    conn = get_db()
    conn.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))
    conn.commit()
    conn.close()


def get_user_sessions(user_id):
    """Get all active (non-expired) sessions for a user."""
    conn = get_db()
    sessions = conn.execute(
        "SELECT * FROM sessions WHERE user_id = ? AND expires_at > datetime('now') ORDER BY created_at DESC",
        (user_id,)
    ).fetchall()
    conn.close()
    return [dict(s) for s in sessions]


def cleanup_expired_sessions():
    conn = get_db()
    conn.execute("DELETE FROM sessions WHERE expires_at < datetime('now')")
    conn.commit()
    conn.close()


# ---- Two-factor operations ----

def create_2fa_code(user_id, code_hash, expires_at):
    conn = get_db()
    # Invalidate old codes
    conn.execute("UPDATE two_factor_codes SET used = 1 WHERE user_id = ? AND used = 0", (user_id,))
    conn.execute(
        "INSERT INTO two_factor_codes (user_id, code_hash, expires_at) VALUES (?, ?, ?)",
        (user_id, code_hash, expires_at)
    )
    conn.commit()
    conn.close()


def verify_2fa_code(user_id, code_hash):
    conn = get_db()
    code = conn.execute(
        '''SELECT * FROM two_factor_codes
           WHERE user_id = ? AND code_hash = ? AND used = 0 AND expires_at > datetime('now')
           ORDER BY created_at DESC LIMIT 1''',
        (user_id, code_hash)
    ).fetchone()

    if code:
        conn.execute("UPDATE two_factor_codes SET used = 1 WHERE id = ?", (code['id'],))
        conn.commit()
        conn.close()
        return True

    conn.close()
    return False


# ---- Key rotation log ----

def log_key_rotation(key_type, rotated_by):
    conn = get_db()
    conn.execute(
        "INSERT INTO key_rotation_log (key_type, rotated_by) VALUES (?, ?)",
        (key_type, rotated_by)
    )
    conn.commit()
    conn.close()


def get_key_rotation_log():
    conn = get_db()
    logs = conn.execute(
        "SELECT * FROM key_rotation_log ORDER BY rotated_at DESC LIMIT 20"
    ).fetchall()
    conn.close()
    return [dict(l) for l in logs]


# ---- Anonymous tip operations ----

def create_tip(codename, category, urgency, title_enc, content_enc, data_hmac):
    conn = get_db()
    conn.execute(
        """INSERT INTO anonymous_tips (codename, category, urgency, title_enc, content_enc, data_hmac)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (codename, category, urgency, title_enc, content_enc, data_hmac)
    )
    conn.commit()
    tip_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.close()
    return tip_id


def get_all_tips():
    conn = get_db()
    tips = conn.execute("SELECT * FROM anonymous_tips ORDER BY created_at DESC").fetchall()
    conn.close()
    return [dict(t) for t in tips]


def get_tip_by_id(tip_id):
    conn = get_db()
    tip = conn.execute("SELECT * FROM anonymous_tips WHERE id = ?", (tip_id,)).fetchone()
    conn.close()
    return dict(tip) if tip else None


def update_tip_status(tip_id, status, admin_notes_enc=''):
    conn = get_db()
    conn.execute(
        "UPDATE anonymous_tips SET status = ?, admin_notes_enc = ? WHERE id = ?",
        (status, admin_notes_enc, tip_id)
    )
    conn.commit()
    conn.close()


def delete_tip(tip_id):
    conn = get_db()
    conn.execute("DELETE FROM anonymous_tips WHERE id = ?", (tip_id,))
    conn.commit()
    conn.close()


def count_tips():
    conn = get_db()
    count = conn.execute("SELECT COUNT(*) FROM anonymous_tips").fetchone()[0]
    conn.close()
    return count


def count_tips_by_status(status):
    conn = get_db()
    count = conn.execute("SELECT COUNT(*) FROM anonymous_tips WHERE status = ?", (status,)).fetchone()[0]
    conn.close()
    return count


# ---- Document operations ----

def create_document(original_filename_enc, stored_filename, file_size, symmetric_key_enc,
                    uploaded_by=None, post_id=None, tip_id=None, message_id=None,
                    dead_drop_id=None, data_hmac=''):
    conn = get_db()
    conn.execute(
        """INSERT INTO documents (original_filename_enc, stored_filename, file_size, symmetric_key_enc,
           uploaded_by, post_id, tip_id, message_id, dead_drop_id, data_hmac)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (original_filename_enc, stored_filename, file_size, symmetric_key_enc,
         uploaded_by, post_id, tip_id, message_id, dead_drop_id, data_hmac)
    )
    conn.commit()
    doc_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.close()
    return doc_id


def get_documents_by_post(post_id):
    conn = get_db()
    docs = conn.execute("SELECT * FROM documents WHERE post_id = ? ORDER BY created_at DESC", (post_id,)).fetchall()
    conn.close()
    return [dict(d) for d in docs]


def get_documents_by_tip(tip_id):
    conn = get_db()
    docs = conn.execute("SELECT * FROM documents WHERE tip_id = ? ORDER BY created_at DESC", (tip_id,)).fetchall()
    conn.close()
    return [dict(d) for d in docs]


def get_documents_by_message(message_id):
    conn = get_db()
    docs = conn.execute("SELECT * FROM documents WHERE message_id = ? ORDER BY created_at DESC", (message_id,)).fetchall()
    conn.close()
    return [dict(d) for d in docs]


def get_documents_by_dead_drop(dead_drop_id):
    conn = get_db()
    docs = conn.execute("SELECT * FROM documents WHERE dead_drop_id = ? ORDER BY created_at DESC", (dead_drop_id,)).fetchall()
    conn.close()
    return [dict(d) for d in docs]


def get_document_by_id(doc_id):
    conn = get_db()
    doc = conn.execute("SELECT * FROM documents WHERE id = ?", (doc_id,)).fetchone()
    conn.close()
    return dict(doc) if doc else None


def delete_document(doc_id):
    conn = get_db()
    conn.execute("DELETE FROM documents WHERE id = ?", (doc_id,))
    conn.commit()
    conn.close()


def count_post_documents(post_id):
    conn = get_db()
    count = conn.execute("SELECT COUNT(*) FROM documents WHERE post_id = ?", (post_id,)).fetchone()[0]
    conn.close()
    return count


def count_documents():
    conn = get_db()
    count = conn.execute("SELECT COUNT(*) FROM documents").fetchone()[0]
    conn.close()
    return count


# ---- Message operations ----

def create_message(sender_id, recipient_id, subject_enc, content_enc, sender_codename='', data_hmac='', expires_at=None,
                   sender_subject_enc='', sender_content_enc=''):
    conn = get_db()
    conn.execute(
        """INSERT INTO messages (sender_id, recipient_id, subject_enc, content_enc, sender_codename, data_hmac, expires_at,
                                  sender_subject_enc, sender_content_enc)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (sender_id, recipient_id, subject_enc, content_enc, sender_codename, data_hmac, expires_at,
         sender_subject_enc, sender_content_enc)
    )
    conn.commit()
    msg_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.close()
    return msg_id


def get_inbox(user_id):
    conn = get_db()
    msgs = conn.execute(
        """SELECT * FROM messages WHERE recipient_id = ?
           AND (expires_at IS NULL OR expires_at > datetime('now'))
           ORDER BY created_at DESC""",
        (user_id,)
    ).fetchall()
    conn.close()
    return [dict(m) for m in msgs]


def get_sent_messages(user_id):
    conn = get_db()
    msgs = conn.execute(
        "SELECT * FROM messages WHERE sender_id = ? ORDER BY created_at DESC", (user_id,)
    ).fetchall()
    conn.close()
    return [dict(m) for m in msgs]


def get_message_by_id(msg_id):
    conn = get_db()
    msg = conn.execute("SELECT * FROM messages WHERE id = ?", (msg_id,)).fetchone()
    conn.close()
    return dict(msg) if msg else None


def mark_message_read(msg_id):
    conn = get_db()
    conn.execute("UPDATE messages SET is_read = 1 WHERE id = ?", (msg_id,))
    conn.commit()
    conn.close()


def count_unread_messages(user_id):
    conn = get_db()
    count = conn.execute(
        """SELECT COUNT(*) FROM messages WHERE recipient_id = ? AND is_read = 0
           AND (expires_at IS NULL OR expires_at > datetime('now'))""",
        (user_id,)
    ).fetchone()[0]
    conn.close()
    return count


def delete_message(msg_id):
    conn = get_db()
    conn.execute("DELETE FROM messages WHERE id = ?", (msg_id,))
    conn.commit()
    conn.close()


def toggle_message_flag(msg_id, field):
    """Toggle is_starred, is_flagged, or is_vaulted. Returns new value."""
    assert field in ('is_starred', 'is_flagged', 'is_vaulted')
    conn = get_db()
    current = conn.execute(f"SELECT {field} FROM messages WHERE id = ?", (msg_id,)).fetchone()
    if not current:
        conn.close()
        return 0
    new_val = 0 if current[0] else 1
    conn.execute(f"UPDATE messages SET {field} = ? WHERE id = ?", (new_val, msg_id))
    conn.commit()
    conn.close()
    return new_val


def get_starred_messages(user_id):
    conn = get_db()
    msgs = conn.execute(
        """SELECT * FROM messages WHERE recipient_id = ? AND is_starred = 1
           AND (expires_at IS NULL OR expires_at > datetime('now'))
           ORDER BY created_at DESC""", (user_id,)
    ).fetchall()
    conn.close()
    return [dict(m) for m in msgs]


def get_flagged_messages(user_id):
    conn = get_db()
    msgs = conn.execute(
        """SELECT * FROM messages WHERE recipient_id = ? AND is_flagged = 1
           AND (expires_at IS NULL OR expires_at > datetime('now'))
           ORDER BY created_at DESC""", (user_id,)
    ).fetchall()
    conn.close()
    return [dict(m) for m in msgs]


def get_vaulted_messages(user_id):
    conn = get_db()
    msgs = conn.execute(
        """SELECT * FROM messages WHERE recipient_id = ? AND is_vaulted = 1
           AND (expires_at IS NULL OR expires_at > datetime('now'))
           ORDER BY created_at DESC""", (user_id,)
    ).fetchall()
    conn.close()
    return [dict(m) for m in msgs]


def count_starred_messages(user_id):
    conn = get_db()
    c = conn.execute(
        "SELECT COUNT(*) FROM messages WHERE recipient_id = ? AND is_starred = 1", (user_id,)
    ).fetchone()[0]
    conn.close()
    return c


def count_flagged_messages(user_id):
    conn = get_db()
    c = conn.execute(
        "SELECT COUNT(*) FROM messages WHERE recipient_id = ? AND is_flagged = 1", (user_id,)
    ).fetchone()[0]
    conn.close()
    return c


def count_vaulted_messages(user_id):
    conn = get_db()
    c = conn.execute(
        "SELECT COUNT(*) FROM messages WHERE recipient_id = ? AND is_vaulted = 1", (user_id,)
    ).fetchone()[0]
    conn.close()
    return c


def update_post_status(post_id, status):
    conn = get_db()
    conn.execute("UPDATE posts SET status = ? WHERE id = ?", (status, post_id))
    conn.commit()
    conn.close()


def get_post_reactions(post_id):
    """Return dict of {reaction_type: count} for a post."""
    conn = get_db()
    rows = conn.execute(
        "SELECT reaction_type, COUNT(*) as cnt FROM post_reactions WHERE post_id = ? GROUP BY reaction_type",
        (post_id,)
    ).fetchall()
    conn.close()
    return {row['reaction_type']: row['cnt'] for row in rows}


def add_post_reaction(post_id, reaction_type, voter_hash):
    """Add a reaction. Returns True if added, False if duplicate."""
    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO post_reactions (post_id, reaction_type, voter_hash) VALUES (?, ?, ?)",
            (post_id, reaction_type, voter_hash)
        )
        conn.commit()
        conn.close()
        return True
    except sqlite3.IntegrityError:
        conn.close()
        return False


def bulk_update_tips_status(tip_ids, status):
    if not tip_ids:
        return
    conn = get_db()
    placeholders = ','.join('?' * len(tip_ids))
    conn.execute(
        f"UPDATE anonymous_tips SET status = ? WHERE id IN ({placeholders})",
        [status] + list(tip_ids)
    )
    conn.commit()
    conn.close()


def get_recent_failed_logins(limit=20):
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM audit_log WHERE action = 'login_failed' ORDER BY created_at DESC LIMIT ?",
        (limit,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ---- Dead drop operations ----

def create_dead_drop(access_code_hash, title_enc, content_enc, creator_codename, data_hmac, expires_at=None):
    conn = get_db()
    conn.execute(
        """INSERT INTO dead_drops (access_code_hash, title_enc, content_enc, creator_codename, data_hmac, expires_at)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (access_code_hash, title_enc, content_enc, creator_codename, data_hmac, expires_at)
    )
    conn.commit()
    drop_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.close()
    return drop_id


def get_dead_drop_by_code(access_code_hash):
    conn = get_db()
    drop = conn.execute(
        "SELECT * FROM dead_drops WHERE access_code_hash = ? AND is_read = 0", (access_code_hash,)
    ).fetchone()
    conn.close()
    if drop:
        d = dict(drop)
        # Check expiry
        if d.get('expires_at'):
            from datetime import datetime
            try:
                if datetime.fromisoformat(d['expires_at']) < datetime.utcnow():
                    delete_dead_drop(d['id'])
                    return None
            except (ValueError, TypeError):
                pass
        return d
    return None


def mark_dead_drop_read(drop_id):
    conn = get_db()
    conn.execute("UPDATE dead_drops SET is_read = 1 WHERE id = ?", (drop_id,))
    conn.commit()
    conn.close()


def delete_dead_drop(drop_id):
    conn = get_db()
    conn.execute("DELETE FROM dead_drops WHERE id = ?", (drop_id,))
    conn.commit()
    conn.close()


def count_dead_drops():
    conn = get_db()
    count = conn.execute("SELECT COUNT(*) FROM dead_drops WHERE is_read = 0").fetchone()[0]
    conn.close()
    return count


# ---- Audit log operations ----

def create_audit_log(user_id, action, details='', ip_address=''):
    conn = get_db()
    conn.execute(
        "INSERT INTO audit_log (user_id, action, details, ip_address) VALUES (?, ?, ?, ?)",
        (user_id, action, details, ip_address)
    )
    conn.commit()
    conn.close()


def get_audit_log(limit=100):
    conn = get_db()
    logs = conn.execute(
        "SELECT * FROM audit_log ORDER BY created_at DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return [dict(l) for l in logs]


def count_audit_entries():
    conn = get_db()
    count = conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
    conn.close()
    return count


# ---- Friendship operations ----

def send_friend_request(requester_id, addressee_id):
    """Send a friend request. Returns a status string."""
    conn = get_db()
    # Check for any existing relationship in either direction
    existing = conn.execute(
        """SELECT * FROM friendships
           WHERE (requester_id = ? AND addressee_id = ?)
              OR (requester_id = ? AND addressee_id = ?)""",
        (requester_id, addressee_id, addressee_id, requester_id)
    ).fetchone()

    if existing:
        existing = dict(existing)
        conn.close()
        if existing['status'] == 'accepted':
            return 'already_friends'
        if existing['status'] == 'pending':
            if existing['requester_id'] == requester_id:
                return 'already_requested'
            else:
                return 'pending_from_them'
        if existing['status'] == 'declined':
            # Allow re-requesting if previously declined
            conn = get_db()
            conn.execute(
                """UPDATE friendships SET requester_id=?, addressee_id=?, status='pending',
                   updated_at=datetime('now')
                   WHERE (requester_id=? AND addressee_id=?) OR (requester_id=? AND addressee_id=?)""",
                (requester_id, addressee_id, requester_id, addressee_id, addressee_id, requester_id)
            )
            conn.commit()
            conn.close()
            return 'sent'

    try:
        conn.execute(
            "INSERT INTO friendships (requester_id, addressee_id) VALUES (?, ?)",
            (requester_id, addressee_id)
        )
        conn.commit()
        conn.close()
        return 'sent'
    except Exception:
        conn.close()
        return 'error'


def accept_friend_request(friendship_id, addressee_id):
    """Accept a pending friend request. Only the addressee can accept."""
    conn = get_db()
    conn.execute(
        """UPDATE friendships SET status='accepted', updated_at=datetime('now')
           WHERE id=? AND addressee_id=? AND status='pending'""",
        (friendship_id, addressee_id)
    )
    conn.commit()
    conn.close()


def decline_friend_request(friendship_id, addressee_id):
    """Decline a pending friend request."""
    conn = get_db()
    conn.execute(
        """UPDATE friendships SET status='declined', updated_at=datetime('now')
           WHERE id=? AND addressee_id=? AND status='pending'""",
        (friendship_id, addressee_id)
    )
    conn.commit()
    conn.close()


def cancel_friend_request(friendship_id, requester_id):
    """Cancel an outgoing pending friend request."""
    conn = get_db()
    conn.execute(
        "DELETE FROM friendships WHERE id=? AND requester_id=? AND status='pending'",
        (friendship_id, requester_id)
    )
    conn.commit()
    conn.close()


def remove_friend(user_id1, user_id2):
    """Remove an accepted friendship."""
    conn = get_db()
    conn.execute(
        """DELETE FROM friendships
           WHERE status='accepted'
             AND ((requester_id=? AND addressee_id=?) OR (requester_id=? AND addressee_id=?))""",
        (user_id1, user_id2, user_id2, user_id1)
    )
    conn.commit()
    conn.close()


def get_friendship_by_id(friendship_id):
    conn = get_db()
    row = conn.execute("SELECT * FROM friendships WHERE id=?", (friendship_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def get_pending_requests_received(user_id):
    """Get all pending friend requests sent TO this user."""
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM friendships WHERE addressee_id=? AND status='pending' ORDER BY created_at DESC",
        (user_id,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_pending_requests_sent(user_id):
    """Get all pending friend requests sent BY this user."""
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM friendships WHERE requester_id=? AND status='pending' ORDER BY created_at DESC",
        (user_id,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_friends(user_id):
    """Get all accepted friends of a user."""
    conn = get_db()
    rows = conn.execute(
        """SELECT * FROM friendships
           WHERE status='accepted'
             AND (requester_id=? OR addressee_id=?)
           ORDER BY updated_at DESC""",
        (user_id, user_id)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def are_friends(user_id1, user_id2):
    """Return True if the two users have an accepted friendship."""
    conn = get_db()
    row = conn.execute(
        """SELECT id FROM friendships
           WHERE status='accepted'
             AND ((requester_id=? AND addressee_id=?) OR (requester_id=? AND addressee_id=?))""",
        (user_id1, user_id2, user_id2, user_id1)
    ).fetchone()
    conn.close()
    return row is not None


def count_pending_friend_requests(user_id):
    """Count pending friend requests received by a user (for navbar badge)."""
    conn = get_db()
    count = conn.execute(
        "SELECT COUNT(*) FROM friendships WHERE addressee_id=? AND status='pending'",
        (user_id,)
    ).fetchone()[0]
    conn.close()
    return count
