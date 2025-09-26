import sqlite3
import threading
import secrets
from argon2 import PasswordHasher
from datetime import datetime

ph = PasswordHasher()

# Thread-local storage for database connections
local = threading.local()

ALPH = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # no I/O/0/1 to reduce confusion

def _code_block():
    return ''.join(secrets.choice(ALPH) for _ in range(4))

def generate_user_code():
    # returns a 12-char code grouped 4-4-4
    return f"{_code_block()}-{_code_block()}-{_code_block()}"

def _canonicalize(code: str) -> str:
    # normalize input so user can type with/without dashes/case
    s = ''.join(ch for ch in code.upper() if ch.isalnum())
    if len(s) != 12:
        return s  # let verification fail on length mismatch later
    return f"{s[0:4]}-{s[4:8]}-{s[8:12]}"

def _pair_order(u1: str, u2: str):
    a, b = sorted([u1, u2])
    return a, b, f"{a}||{b}"

def _dm_session_key(u1: str, u2: str) -> str:
    """Stable key for a pair of users."""
    a, b = sorted([u1, u2])
    return f"{a}||{b}"


def get_db():
    """Get database connection for current thread"""
    if not hasattr(local, 'connection'):
        local.connection = sqlite3.connect('nexus_terminal.db', check_same_thread=False)
        local.connection.row_factory = sqlite3.Row
    return local.connection


def init_db():
    """Initialize database with required tables"""
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS user_codes (
        username   TEXT PRIMARY KEY,
        scheme     TEXT NOT NULL DEFAULT 'argon2',
        code_hash  TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS trust_pairs (
        pair_key     TEXT PRIMARY KEY,
        a            TEXT NOT NULL,
        b            TEXT NOT NULL,
        a_trusts_b   INTEGER DEFAULT 0,
        b_trusts_a   INTEGER DEFAULT 0,
        created_at   DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_trust_a ON trust_pairs(a)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_trust_b ON trust_pairs(b)")

    # Create messages table
    cursor.execute('''
                   CREATE TABLE IF NOT EXISTS messages
                   (
                       id
                       INTEGER
                       PRIMARY
                       KEY
                       AUTOINCREMENT,
                       username
                       TEXT
                       NOT
                       NULL,
                       basecamp
                       TEXT
                       NOT
                       NULL,
                       message
                       TEXT
                       NOT
                       NULL,
                       timestamp
                       DATETIME
                       DEFAULT
                       CURRENT_TIMESTAMP
                   )
                   ''')

    # Create user_sessions table (for tracking online users)
    cursor.execute('''
                   CREATE TABLE IF NOT EXISTS user_sessions
                   (
                       id
                       INTEGER
                       PRIMARY
                       KEY
                       AUTOINCREMENT,
                       username
                       TEXT
                       NOT
                       NULL,
                       basecamp
                       TEXT
                       NOT
                       NULL,
                       connected_at
                       DATETIME
                       DEFAULT
                       CURRENT_TIMESTAMP,
                       UNIQUE
                   (
                       username,
                       basecamp
                   )
                       )
                   ''')

    # Create basecamps table
    cursor.execute('''
                   CREATE TABLE IF NOT EXISTS basecamps
                   (
                       id
                       INTEGER
                       PRIMARY
                       KEY
                       AUTOINCREMENT,
                       code
                       TEXT
                       UNIQUE
                       NOT
                       NULL,
                       name
                       TEXT
                       NOT
                       NULL,
                       created_at
                       DATETIME
                       DEFAULT
                       CURRENT_TIMESTAMP
                   )
                   ''')

    # Insert default basecamp
    cursor.execute('''
                   INSERT
                   OR IGNORE INTO basecamps (code, name) 
        VALUES (?, ?)
                   ''', ('ALPHA-47X9', 'Alpha Base Camp - Sector 7'))

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS private_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_key TEXT NOT NULL,            -- "A||B" (sorted usernames)
            sender TEXT NOT NULL,
            recipient TEXT NOT NULL,
            message TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            read_by_recipient INTEGER DEFAULT 0
        )
    """)

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_pm_session ON private_messages(session_key, id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_pm_unread  ON private_messages(recipient, read_by_recipient)")


    conn.commit()


def add_message(username, basecamp, message):
    """Add a new message to the database"""
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute('''
                   INSERT INTO messages (username, basecamp, message)
                   VALUES (?, ?, ?)
                   ''', (username, basecamp, message))

    conn.commit()


def get_recent_messages(basecamp, limit=50):
    """Get recent messages for a basecamp"""
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute('''
                   SELECT username, message, timestamp
                   FROM messages
                   WHERE basecamp = ?
                   ORDER BY timestamp DESC
                       LIMIT ?
                   ''', (basecamp, limit))

    messages = cursor.fetchall()
    return [dict(row) for row in reversed(messages)]

def add_private_message(sender: str, recipient: str, message: str):
    conn = get_db()
    cur = conn.cursor()
    key = _dm_session_key(sender, recipient)
    cur.execute(
        "INSERT INTO private_messages (session_key, sender, recipient, message) VALUES (?,?,?,?)",
        (key, sender, recipient, message)
    )
    conn.commit()

def get_private_history(user: str, partner: str, limit: int = 200):
    """Return ordered history for the pair (oldest → newest)."""
    conn = get_db()
    cur = conn.cursor()
    key = _dm_session_key(user, partner)
    cur.execute("""
        SELECT sender, recipient, message, timestamp
        FROM private_messages
        WHERE session_key = ?
        ORDER BY id ASC
        LIMIT ?
    """, (key, limit))
    return [dict(row) for row in cur.fetchall()]

def mark_private_read(user: str, partner: str):
    """Mark all messages to 'user' from 'partner' as read."""
    conn = get_db()
    cur = conn.cursor()
    key = _dm_session_key(user, partner)
    cur.execute("""
        UPDATE private_messages
        SET read_by_recipient = 1
        WHERE session_key = ? AND recipient = ? AND read_by_recipient = 0
    """, (key, user))
    conn.commit()

def get_unread_counts(user: str):
    """Map partner → unread count for 'user'."""
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT sender AS partner, COUNT(*) AS cnt
        FROM private_messages
        WHERE recipient = ? AND read_by_recipient = 0
        GROUP BY sender
    """, (user,))
    rows = cur.fetchall()
    return {row["partner"]: row["cnt"] for row in rows}

def add_user_session(username, basecamp):
    """Add or update user session"""
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute('''
        INSERT OR REPLACE INTO user_sessions (username, basecamp, connected_at)
        VALUES (?, ?, CURRENT_TIMESTAMP)
    ''', (username, basecamp))

    conn.commit()


def remove_user_session(username, basecamp):
    """Remove user session"""
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute('''
                   DELETE
                   FROM user_sessions
                   WHERE username = ?
                     AND basecamp = ?
                   ''', (username, basecamp))

    conn.commit()


def get_online_users(basecamp):
    """Get list of online users in a basecamp"""
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute('''
                   SELECT username, connected_at
                   FROM user_sessions
                   WHERE basecamp = ?
                   ORDER BY connected_at ASC
                   ''', (basecamp,))

    users = cursor.fetchall()
    return [dict(row) for row in users]


def cleanup_old_sessions():
    """Clean up old sessions (can be called periodically)"""
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute('''
                   DELETE
                   FROM user_sessions
                   WHERE connected_at < datetime('now', '-1 hour')
                   ''')

    conn.commit()


def get_message_count(basecamp):
    """Get total message count for a basecamp"""
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute('''
                   SELECT COUNT(*) as count
                   FROM messages
                   WHERE basecamp = ?
                   ''', (basecamp,))

    result = cursor.fetchone()
    return result['count'] if result else 0

def set_user_code_hash(username: str, code_plain: str):
    """Store Argon2 hash of the canonicalized code for the user."""
    canon = _canonicalize(code_plain)
    code_hash = ph.hash(canon)
    conn = get_db(); cur = conn.cursor()
    cur.execute("""
        INSERT INTO user_codes (username, scheme, code_hash)
        VALUES (?, 'argon2', ?)
        ON CONFLICT(username) DO UPDATE SET scheme='argon2', code_hash=excluded.code_hash
    """, (username, code_hash))
    conn.commit()

def get_user_code_hash(username: str):
    conn = get_db(); cur = conn.cursor()
    cur.execute("SELECT scheme, code_hash FROM user_codes WHERE username=?", (username,))
    return cur.fetchone()  # Row or None

def verify_partner_code(username: str, code_entered: str) -> bool:
    rec = get_user_code_hash(username)
    if not rec:
        return False
    scheme = rec["scheme"]
    code_hash = rec["code_hash"]
    if scheme != "argon2":
        return False
    try:
        ph.verify(code_hash, _canonicalize(code_entered))
        return True
    except Exception:
        return False

def ensure_trust_row(u1: str, u2: str):
    a, b, key = _pair_order(u1, u2)
    conn = get_db(); cur = conn.cursor()
    cur.execute("INSERT OR IGNORE INTO trust_pairs (pair_key, a, b) VALUES (?,?,?)", (key, a, b))
    conn.commit()

def is_trusted(u1: str, u2: str) -> bool:
    a, b, key = _pair_order(u1, u2)
    conn = get_db(); cur = conn.cursor()
    cur.execute("SELECT a_trusts_b, b_trusts_a FROM trust_pairs WHERE pair_key=?", (key,))
    row = cur.fetchone()
    return bool(row and row["a_trusts_b"] and row["b_trusts_a"])

def get_trust_status(u1: str, u2: str) -> dict:
    a, b, key = _pair_order(u1, u2)
    conn = get_db(); cur = conn.cursor()
    cur.execute("SELECT a_trusts_b, b_trusts_a FROM trust_pairs WHERE pair_key=?", (key,))
    row = cur.fetchone()
    if not row:
        return {"me_trusts_partner": False, "partner_trusts_me": False, "mutual": False}
    if u1 == a:
        me, partner = row["a_trusts_b"], row["b_trusts_a"]
    else:
        me, partner = row["b_trusts_a"], row["a_trusts_b"]
    return {"me_trusts_partner": bool(me), "partner_trusts_me": bool(partner), "mutual": bool(me and partner)}

def record_trust_if_code_matches(enterer: str, partner: str, code_entered: str) -> dict:
    """Mark directional trust enterer→partner only if code matches partner's hashed code."""
    if not verify_partner_code(partner, code_entered):
        status = get_trust_status(enterer, partner)
        status.update({"ok": False, "error": "invalid_code"})
        return status
    ensure_trust_row(enterer, partner)
    a, b, key = _pair_order(enterer, partner)
    conn = get_db(); cur = conn.cursor()
    if enterer == a:
        cur.execute("UPDATE trust_pairs SET a_trusts_b=1 WHERE pair_key=?", (key,))
    else:
        cur.execute("UPDATE trust_pairs SET b_trusts_a=1 WHERE pair_key=?", (key,))
    conn.commit()
    status = get_trust_status(enterer, partner)
    status.update({"ok": True})
    return status
