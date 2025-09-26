from flask import Flask, render_template, request, jsonify, session, make_response, redirect, url_for
from flask_socketio import SocketIO, emit, join_room, leave_room, rooms
import json
import hashlib
from argon2 import PasswordHasher, exceptions as argon2_exceptions
from datetime import datetime
import db

ph = PasswordHasher()

app = Flask(__name__)
app.config['SECRET_KEY'] = 'nexus_terminal_2087_secret_key'
app.config['SESSION_PERMANENT'] = False
app.config['INACTIVITY_TIMEOUT'] = 15 * 60  # 15 minutes

from closing_session import session_bp
app.register_blueprint(session_bp)

socketio = SocketIO(app, cors_allowed_origins="*")
SID_INFO = {}

# Base camp codes (expandable for multiple camps)
# Load basecamp codes from basecamps.json. Codes (secrets) are stored as Argon2 hashes.
# The JSON structure is: { "<id>": { "name": "<display name>", "scheme":"argon2", "hash":"<argon2 hash>" }, ... }
def load_basecamps():
    try:
        with open('basecamps.json', 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        return {}

def verify_basecamp_code(candidate_code):
    """Return (basecamp_id, basecamp_name) if candidate_code matches a stored code, else (None, None)."""
    basecamps = load_basecamps()
    for bid, info in basecamps.items():
        scheme = info.get('scheme')
        h = info.get('hash')
        name = info.get('name')
        if scheme == 'argon2' and h and name:
            try:
                ph.verify(h, candidate_code)
                return bid, name
            except Exception:
                continue
        # legacy: if 'code' stored plaintext (not recommended)
        if info.get('code') and info['code'] == candidate_code:
            return bid, name
    return None, None

# Initialize database
db.init_db()


def verify_user(username, password):
    """Verify user credentials securely, supporting seamless migration.
    
    Preferred: Argon2 hash stored in users.json as: {"hash": "<argon2>", "scheme": "argon2"}.
    Legacy: SHA-256 hex in "password". We verify once then upgrade to Argon2 and
    remove any "real_password" or legacy "password" fields.
    """
    try:
        with open('users.json', 'r', encoding='utf-8') as f:
            users = json.load(f)
    except FileNotFoundError:
        return False

    user = users.get(username)
    if not user:
        return False

    # 1) Argon2 path
    if isinstance(user, dict) and user.get('scheme') == 'argon2' and 'hash' in user:
        try:
            ph.verify(user['hash'], password)
            return True
        except argon2_exceptions.VerifyMismatchError:
            return False

    # 2) Legacy SHA-256 migration path
    legacy_hash = user.get('password')
    if legacy_hash:
        candidate = hashlib.sha256(password.encode('utf-8')).hexdigest()
        if candidate == legacy_hash:
            # Migrate: replace with Argon2 and scrub legacy/plaintext fields
            try:
                user['hash'] = ph.hash(password)
                user['scheme'] = 'argon2'
                # Remove insecure fields if present
                user.pop('password', None)
                user.pop('real_password', None)
                users[username] = user
                with open('users.json', 'w', encoding='utf-8') as f:
                    json.dump(users, f, indent=2)
            except Exception:
                # Even if migration fails to write, the login itself is valid
                pass
            return True
        else:
            return False

    # 3) Absolute fallback: if (ill-advised) 'real_password' exists, allow exactly once then migrate
    real = user.get('real_password')
    if real is not None:
        if password == real:
            try:
                user['hash'] = ph.hash(password)
                user['scheme'] = 'argon2'
                user.pop('password', None)
                user.pop('real_password', None)
                users[username] = user
                with open('users.json', 'w', encoding='utf-8') as f:
                    json.dump(users, f, indent=2)
            except Exception:
                pass
            return True
        return False

    return False

#    except FileNotFoundError:
#        return False


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if verify_user(username, password):
        session['username'] = username
        session['authenticated'] = True
        session["last_activity"] = datetime.utcnow().timestamp()
        return jsonify({'success': True, 'message': f'Welcome back, {username}'})
    else:
        return jsonify({'success': False, 'message': 'Invalid credentials. Access denied.'})


@app.route('/verify_basecamp', methods=['POST'])
def verify_basecamp():
    if not session.get('authenticated'):
        return jsonify({'success': False, 'message': 'Not authenticated'}), 401

    data = request.get_json() or {}
    candidate = (data.get('basecamp_code') or '').strip()

    # Use the Argon2-backed JSON source
    basecamp_id, basecamp_name = verify_basecamp_code(candidate)

    if basecamp_id:
        session['basecamp'] = basecamp_id
        session['basecamp_name'] = basecamp_name
        return jsonify({
            'success': True,
            'message': f'Access granted to {basecamp_name}',
            'basecamp_name': basecamp_name
        }), 200

    return jsonify({'success': False, 'message': 'Invalid base camp code. Access denied.'}), 403


@app.route('/basecamp')
def basecamp():
    if not session.get('authenticated') or not session.get('basecamp'):
        return render_template('index.html')

    return render_template('basecamp.html',
                           username=session.get('username'),
                           basecamp_name=session.get('basecamp_name'),
                           basecamp_code=session.get('basecamp'))


@app.route('/logout', methods=['POST'])
def logout():
    username = session.get('username')
    basecamp = session.get('basecamp')
    if username and basecamp:
        db.remove_user_session(username, basecamp)
        socketio.emit('user_left', {
            'username': username,
            'message': f'{username} has disconnected from the network',
            'timestamp': datetime.now().strftime('%H:%M:%S')
        }, room=basecamp)

    # clear server-side session state
    session.clear()

    # send a response that *actually* clears the cookie in the browser
    resp = jsonify({'success': True, 'message': 'Disconnected from network'})
    cookie_name = app.config.get('SESSION_COOKIE_NAME', 'session')
    resp.delete_cookie(cookie_name)
    return resp

@app.route('/end_chat', methods=['POST'])
def end_chat():
    session.pop('basecamp', None)
    session.pop('basecamp_name', None)
    return jsonify({'success': True, 'message': 'Chat session terminated'})


# Socket.IO events for real-time chat
@socketio.on('connect')
def on_connect():
    if session.get('authenticated') and session.get('basecamp'):
        username = session.get('username')
        basecamp = session.get('basecamp')

        # Track this connection by sid
        SID_INFO[request.sid] = {"username": username, "basecamp": basecamp}

        join_room(basecamp)
        join_room(f"user:{username}")
        db.add_user_session(username, basecamp)

        emit('user_joined', {
            'username': username,
            'message': f'{username} has connected to the network',
            'timestamp': datetime.now().strftime('%H:%M:%S')
        }, room=basecamp, include_self=False)

        emit('system_message', {
            'message': f'Connected to {session.get("basecamp_name")}. Communication channel open.',
            'timestamp': datetime.now().strftime('%H:%M:%S')
        })
        emit('unread_counts', db.get_unread_counts(username))


@socketio.on('disconnect')
def on_disconnect():
    # DON'T use session here; it might be cleared already.
    info = SID_INFO.pop(request.sid, None)
    if not info:
        return
    username = info.get('username')
    basecamp = info.get('basecamp')
    if basecamp and username:
        db.remove_user_session(username, basecamp)
        emit('user_left', {
            'username': username,
            'message': f'{username} has disconnected from the network',
            'timestamp': datetime.now().strftime('%H:%M:%S')
        }, room=basecamp, include_self=False)
        # no need to leave_room on disconnect; socket is closed anyway


@socketio.on('leave_basecamp')
def leave_basecamp():
    info = SID_INFO.get(request.sid)
    if not info:
        return
    username = info.get('username')
    basecamp = info.get('basecamp')
    if not basecamp or not username:
        return

    leave_room(basecamp)
    db.remove_user_session(username, basecamp)
    emit('user_left', {
        'username': username,
        'message': f'{username} has left the basecamp',
        'timestamp': datetime.now().strftime('%H:%M:%S')
    }, room=basecamp, include_self=False)

    # mark this sid as no longer in a basecamp
    info['basecamp'] = None


@socketio.on('request_trust_status')
def request_trust_status(data):
    if not session.get('authenticated'): 
        return
    me = session.get('username')
    partner = (data.get('with') or '').strip()
    if not partner:
        return
    status = db.get_trust_status(me, partner)
    emit('trust_status', {'with': partner, **status})


@socketio.on('submit_partner_code')
def submit_partner_code(data):
    if not session.get('authenticated'):
        return
    me = session.get('username')
    partner = (data.get('with') or '').strip()
    code = (data.get('code') or '').strip()
    if not partner or not code:
        return

    status = db.record_trust_if_code_matches(me, partner, code)  # -> ok / invalid_code + status flags
    emit('trust_status', {'with': partner, **status})

    # Let partner’s client update if they’re online
    emit('trust_status', {'with': me, **db.get_trust_status(partner, me)}, room=f"user:{partner}")


@socketio.on('send_message')
def handle_message(data):
    if session.get('authenticated') and session.get('basecamp'):
        username = session.get('username')
        basecamp = session.get('basecamp')
        message = data.get('message', '').strip()

        if message:
            # Store message in database
            db.add_message(username, basecamp, message)

            # Broadcast to all users in the same basecamp
            emit('new_message', {
                'username': username,
                'message': message,
                'timestamp': datetime.now().strftime('%H:%M:%S')
            }, room=basecamp)

@socketio.on('send_private_message')
def send_private_message(data):
    if not session.get('authenticated') or not session.get('basecamp'):
        return
    sender = session.get('username')
    recipient = (data.get('to') or '').strip()
    message = (data.get('message') or '').strip()
    if not recipient or not message:
        return

    # Enforce: cannot DM until mutual trust established
    if not db.is_trusted(sender, recipient):
        emit('trust_required', {'with': recipient, **db.get_trust_status(sender, recipient)})
        return

    # Your normal send path...
    db.add_private_message(sender, recipient, message)
    ts = datetime.now().strftime('%H:%M:%S')
    payload = {'from': sender, 'to': recipient, 'message': message, 'timestamp': ts}
    emit('private_message', payload, room=f"user:{recipient}")
    emit('private_message', payload, room=f"user:{sender}")
    emit('unread_counts', db.get_unread_counts(recipient), room=f"user:{recipient}")


@socketio.on('fetch_private_history')
def fetch_private_history(data):
    if not session.get('authenticated'):
        return
    me = session.get('username')
    partner = (data.get('with') or '').strip()
    if not partner:
        return

    status = db.get_trust_status(me, partner)
    if not status['mutual']:
        emit('private_history', {'with': partner, 'messages': [], 'trust': status})
        return

    history = db.get_private_history(me, partner, limit=200)
    out = [{'from': h['sender'], 'to': h['recipient'], 'message': h['message'], 'timestamp': h['timestamp']} for h in history]
    emit('private_history', {'with': partner, 'messages': out, 'trust': status})


@socketio.on('mark_private_read')
def mark_private_read(data):
    if not session.get('authenticated'):
        return
    user = session.get('username')
    partner = (data.get('with') or '').strip()
    if not partner:
        return
    db.mark_private_read(user, partner)
    # send the caller their new unread map
    emit('unread_counts', db.get_unread_counts(user))

@socketio.on('get_unread_counts')
def get_unread_counts():
    if not session.get('authenticated'):
        return
    user = session.get('username')
    emit('unread_counts', db.get_unread_counts(user))

@socketio.on('get_online_users')
def get_online_users():
    if session.get('authenticated') and session.get('basecamp'):
        basecamp = session.get('basecamp')
        users = db.get_online_users(basecamp)
        emit('online_users_update', {'users': users})


if __name__ == '__main__':
    socketio.run(app, debug=True, host='0.0.0.0', port=5000, allow_unsafe_werkzeug=True)