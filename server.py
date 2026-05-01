"""
Kavi Labs Kanban — Flask Backend
Routes: /auth/*, /board, /cards/*, /columns/*, /jobs/*
"""
import os
import sqlite3
import uuid
import hashlib
import secrets
import time
import json
from functools import wraps
from datetime import datetime, timezone

from flask import Flask, request, jsonify, g
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'kanban.db')
PORT = int(os.environ.get('PORT', 9002))

# Agent account configuration
AGENT_EMAIL = 'agent@kavilabs.dev'
AGENT_PASSWORD = 'agent-kanban-18190'
# Pre-computed bcrypt hash for the agent password
AGENT_PASSWORD_HASH = '$2b$12$ThcDBHGCrUqXQvH1.zujQ.bd/aLurX3ezYggwb4Xmoi7wmxasguwu'

# ── DB ────────────────────────────────────────────────────────────────────────

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DB_PATH, check_same_thread=False)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    db = g.pop('db', None)
    if db is not None:
        db.commit()
        db.close()

def init_db():
    db = sqlite3.connect(DB_PATH)
    db.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            email TEXT,
            password_hash TEXT NOT NULL,
            created_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS auth_tokens (
            token TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            expires_at INTEGER NOT NULL,
            created_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS columns (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            title TEXT NOT NULL,
            color TEXT NOT NULL DEFAULT '#8b7cf8',
            position INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS cards (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            column_id TEXT NOT NULL,
            title TEXT NOT NULL DEFAULT '',
            description TEXT NOT NULL DEFAULT '',
            is_job INTEGER NOT NULL DEFAULT 0,
            agent_name TEXT,
            agent_status TEXT DEFAULT 'pending',
            agent_instructions TEXT DEFAULT '',
            attachments TEXT NOT NULL DEFAULT '[]',
            audio_count INTEGER NOT NULL DEFAULT 0,
            position INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            comments TEXT NOT NULL DEFAULT '[]',
            labels TEXT NOT NULL DEFAULT '[]',
            priority TEXT NOT NULL DEFAULT 'medium',
            due_date TEXT
        );
        CREATE TABLE IF NOT EXISTS jobs (
            id TEXT PRIMARY KEY,
            card_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            instructions TEXT NOT NULL DEFAULT '',
            result TEXT NOT NULL DEFAULT '',
            created_at INTEGER NOT NULL,
            picked_up_at INTEGER,
            completed_at INTEGER
        );
        CREATE INDEX IF NOT EXISTS idx_cards_user ON cards(user_id);
        CREATE INDEX IF NOT EXISTS idx_cards_col ON cards(column_id);
        CREATE INDEX IF NOT EXISTS idx_jobs_user ON jobs(user_id);
        CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status);
    ''')
    db.commit()

    # Add new columns to CARDS table if they don't exist (for existing databases)
    try:
        db.execute("ALTER TABLE cards ADD COLUMN comments TEXT NOT NULL DEFAULT '[]'")
    except sqlite3.OperationalError:
        pass  # Column already exists

    try:
        db.execute("ALTER TABLE cards ADD COLUMN labels TEXT NOT NULL DEFAULT '[]'")
    except sqlite3.OperationalError:
        pass  # Column already exists

    try:
        db.execute("ALTER TABLE cards ADD COLUMN priority TEXT NOT NULL DEFAULT 'medium'")
    except sqlite3.OperationalError:
        pass  # Column already exists

    try:
        db.execute("ALTER TABLE cards ADD COLUMN due_date TEXT")
    except sqlite3.OperationalError:
        pass  # Column already exists

    db.commit()

    # Ensure agent account exists with the correct password
    existing_agent = db.execute(
        'SELECT id FROM users WHERE email = ?',
        (AGENT_EMAIL,)
    ).fetchone()

    if not existing_agent:
        # Create agent user with bcrypt hash
        agent_id = str(uuid.uuid4())
        now = int(time.time())
        db.execute(
            'INSERT INTO users (id, email, password_hash, created_at) VALUES (?, ?, ?, ?)',
            (agent_id, AGENT_EMAIL, AGENT_PASSWORD_HASH, now)
        )
        db.commit()

        # Create default columns for agent
        default_cols = [
            ('ideas', 'Ideas', '#8b7cf8', 0),
            ('todo', 'To Do', '#ff6b8a', 1),
            ('doing', 'In Progress', '#ffd060', 2),
            ('done', 'Done', '#5de8a0', 3),
        ]
        for col_id, title, color, pos in default_cols:
            db.execute(
                'INSERT INTO columns (id, user_id, title, color, position, created_at) VALUES (?, ?, ?, ?, ?, ?)',
                (col_id, agent_id, title, color, pos, now)
            )
        db.commit()

    db.close()

# ── AUTH HELPERS ──────────────────────────────────────────────────────────────
def hash_password(pw: str) -> str:
    """Legacy hash function for backward compatibility."""
    return hashlib.sha256(pw.encode()).hexdigest()

def generate_token() -> str:
    return secrets.token_urlsafe(32)

def check_password(password: str, stored_hash: str) -> bool:
    """Check password against stored hash. Supports both bcrypt and legacy SHA256."""
    if stored_hash.startswith('$2b$') or stored_hash.startswith('$2a$') or stored_hash.startswith('$2y$'):
        # bcrypt hash
        try:
            import bcrypt
            return bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8'))
        except ImportError:
            # bcrypt not available, fall back to legacy comparison
            return hash_password(password) == stored_hash
    else:
        # Legacy SHA256 hash
        return hash_password(password) == stored_hash

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get('Authorization', '')
        if not auth.startswith('Bearer '):
            return jsonify({'error': 'Missing authorization'}), 401
        token = auth[7:]
        db = get_db()
        row = db.execute(
            'SELECT user_id, expires_at FROM auth_tokens WHERE token = ?',
            (token,)
        ).fetchone()
        if not row:
            return jsonify({'error': 'Invalid token'}), 401
        if row['expires_at'] < time.time():
            db.execute('DELETE FROM auth_tokens WHERE token = ?', (token,))
            return jsonify({'error': 'Token expired'}), 401
        g.user_id = row['user_id']
        return f(*args, **kwargs)
    return decorated

# ── AUTH ROUTES ───────────────────────────────────────────────────────────────

@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.get_json() or {}
    password = data.get('password', '')
    email = data.get('email', '')

    if len(password) < 8:
        return jsonify({'error': 'Password must be at least 8 characters'}), 400

    db = get_db()
    existing = db.execute('SELECT id FROM users LIMIT 1').fetchone()
    if existing:
        return jsonify({'error': 'An account already exists. Please sign in.'}), 409

    user_id = str(uuid.uuid4())
    now = int(time.time())

    # Use bcrypt for new users if available, otherwise fall back to legacy
    try:
        import bcrypt
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode()
    except ImportError:
        password_hash = hash_password(password)

    db.execute(
        'INSERT INTO users (id, email, password_hash, created_at) VALUES (?, ?, ?, ?)',
        (user_id, email, password_hash, now)
    )
    db.commit()

    # Create default columns for new user
    default_cols = [
        ('ideas', 'Ideas', '#8b7cf8', 0),
        ('todo', 'To Do', '#ff6b8a', 1),
        ('doing', 'In Progress', '#ffd060', 2),
        ('done', 'Done', '#5de8a0', 3),
    ]
    for col_id, title, color, pos in default_cols:
        db.execute(
            'INSERT INTO columns (id, user_id, title, color, position, created_at) VALUES (?, ?, ?, ?, ?, ?)',
            (col_id, user_id, title, color, pos, now)
        )
    db.commit()

    token = generate_token()
    expires_at = now + (30 * 24 * 3600)  # 30 days
    db.execute(
        'INSERT INTO auth_tokens (token, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)',
        (token, user_id, expires_at, now)
    )
    db.commit()

    return jsonify({'token': token, 'user_id': user_id})

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json() or {}
    password = data.get('password', '')
    email = data.get('email', None)

    db = get_db()
    user = None

    if email:
        # Backward compatible: look up by email
        user = db.execute('SELECT id, email, password_hash FROM users WHERE email = ?', (email,)).fetchone()
    else:
        # New mode: look up the single existing user (no email required)
        user = db.execute('SELECT id, email, password_hash FROM users LIMIT 1').fetchone()

    if not user:
        return jsonify({'error': 'Invalid credentials'}), 401

    if not check_password(password, user['password_hash']):
        return jsonify({'error': 'Invalid password'}), 401

    now = int(time.time())
    token = generate_token()
    expires_at = now + (30 * 24 * 3600)
    # Rotate token
    db.execute('DELETE FROM auth_tokens WHERE user_id = ?', (user['id'],))
    db.execute(
        'INSERT INTO auth_tokens (token, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)',
        (token, user['id'], expires_at, now)
    )
    db.commit()

    return jsonify({'token': token, 'user_id': user['id']})

# ── BOARD ROUTE ───────────────────────────────────────────────────────────────

def init_default_board(db, uid):
    """Create 4 default columns if user has none."""
    existing = db.execute(
        'SELECT COUNT(*) FROM columns WHERE user_id = ?', (uid,)
    ).fetchone()[0]
    if existing > 0:
        return
    defaults = [
        ('Ideas', '#8b7cf8'),
        ('To Do', '#ff6b8a'),
        ('In Progress', '#ffd060'),
        ('Done', '#5de8a0'),
    ]
    now = int(time.time())
    for pos, (title, color) in enumerate(defaults):
        col_id = str(uuid.uuid4())[:8]  # unique per user, no collision
        db.execute(
            'INSERT INTO columns (id, user_id, title, color, position, created_at) VALUES (?, ?, ?, ?, ?, ?)',
            (col_id, uid, title, color, pos, now)
        )

@app.route('/api/board', methods=['GET'])
@require_auth
def get_board():
    db = get_db()
    uid = g.user_id

    init_default_board(db, uid)

    columns = db.execute(
        'SELECT id, title, color FROM columns WHERE user_id = ? ORDER BY position',
        (uid,)
    ).fetchall()

    result = []
    for col in columns:
        cards = db.execute(
            '''SELECT id, title, description, is_job, agent_name, agent_status,
                      agent_instructions, attachments, audio_count, position, created_at, updated_at, column_id,
                      comments, labels, priority, due_date
               FROM cards WHERE user_id = ? AND column_id = ? ORDER BY position''',
            (uid, col['id'])
        ).fetchall()

        card_list = []
        for c in cards:
            card_list.append({
                'id': c['id'],
                'title': c['title'],
                'description': c['description'],
                'is_job': bool(c['is_job']),
                'agent_name': c['agent_name'],
                'agent_status': c['agent_status'],
                'agent_instructions': c['agent_instructions'],
                'attachments': json.loads(c['attachments'] or '[]'),
                'audio_count': c['audio_count'],
                'position': c['position'],
                'created_at': c['created_at'],
                'updated_at': c['updated_at'],
                'column_id': c['column_id'],
                'comments': json.loads(c['comments'] or '[]'),
                'labels': json.loads(c['labels'] or '[]'),
                'priority': c['priority'] or 'medium',
                'due_date': c['due_date'],
            })

        result.append({
            'id': col['id'],
            'title': col['title'],
            'color': col['color'],
            'cards': card_list,
        })

    return jsonify({'columns': result})

# ── CARD ROUTES ────────────────────────────────────────────────────────────────

@app.route('/api/cards', methods=['POST'])
@require_auth
def create_card():
    db = get_db()
    uid = g.user_id
    data = request.get_json() or {}
    now = int(time.time())
    card_id = 'c' + str(uuid.uuid4())[:8]
    title = data.get('title', '')
    description = data.get('description', '')
    column_id = data.get('column_id', 'todo')
    is_job = 1 if data.get('is_job') else 0
    agent_instructions = data.get('agent_instructions', '')
    attachments = json.dumps(data.get('attachments', []))
    audio_count = data.get('audio_count', 0)
    comments = json.dumps(data.get('comments', []))
    labels = json.dumps(data.get('labels', []))
    priority = data.get('priority', 'medium')
    due_date = data.get('due_date', None)

    # Position = end of column
    pos_row = db.execute(
        'SELECT COALESCE(MAX(position), -1) + 1 as next_pos FROM cards WHERE user_id = ? AND column_id = ?',
        (uid, column_id)
    ).fetchone()
    position = pos_row['next_pos']

    db.execute('''INSERT INTO cards (id, user_id, column_id, title, description, is_job, agent_instructions,
                          attachments, audio_count, position, created_at, updated_at, comments, labels, priority, due_date)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                (card_id, uid, column_id, title, description, is_job, agent_instructions,
                 attachments, audio_count, position, now, now, comments, labels, priority, due_date)
    )

    # If it's a job, also create a job record
    if is_job:
        job_id = 'j' + str(uuid.uuid4())[:8]
        db.execute('''INSERT INTO jobs (id, card_id, user_id, status, instructions, created_at)
                      VALUES (?, ?, ?, 'pending', ?, ?)''',
                   (job_id, card_id, uid, agent_instructions, now)
        )

    db.commit()
    return jsonify({'id': card_id, 'status': 'ok'})

@app.route('/api/cards/<card_id>', methods=['PUT'])
@require_auth
def update_card(card_id):
    db = get_db()
    uid = g.user_id
    data = request.get_json() or {}
    now = int(time.time())

    card = db.execute('SELECT id FROM cards WHERE id = ? AND user_id = ?', (card_id, uid)).fetchone()
    if not card:
        return jsonify({'error': 'Card not found'}), 404

    updates = []
    params = []

    for field in ['title', 'description', 'column_id', 'attachments', 'audio_count']:
        if field in data:
            val = json.dumps(data[field]) if field == 'attachments' else data[field]
            updates.append(f'{field} = ?')
            params.append(val)

    if 'is_job' in data:
        updates.append('is_job = ?')
        params.append(1 if data['is_job'] else 0)

    if 'agent_instructions' in data:
        updates.append('agent_instructions = ?')
        params.append(data['agent_instructions'])

    if 'agent_name' in data:
        updates.append('agent_name = ?')
        params.append(data['agent_name'])

    if 'agent_status' in data:
        updates.append('agent_status = ?')
        params.append(data['agent_status'])

    # Handle new card fields
    if 'comments' in data:
        updates.append('comments = ?')
        params.append(json.dumps(data['comments']))

    if 'labels' in data:
        updates.append('labels = ?')
        params.append(json.dumps(data['labels']))

    if 'priority' in data:
        updates.append('priority = ?')
        params.append(data['priority'])

    if 'due_date' in data:
        updates.append('due_date = ?')
        params.append(data['due_date'])

    updates.append('updated_at = ?')
    params.append(now)
    params.append(card_id)

    db.execute(f"UPDATE cards SET {', '.join(updates)} WHERE id = ?", params)
    db.commit()

    return jsonify({'status': 'ok'})

@app.route('/api/cards/<card_id>', methods=['DELETE'])
@require_auth
def delete_card(card_id):
    db = get_db()
    uid = g.user_id
    db.execute('DELETE FROM cards WHERE id = ? AND user_id = ?', (card_id, uid))
    db.execute('DELETE FROM jobs WHERE card_id = ?', (card_id,))
    db.commit()
    return jsonify({'status': 'ok'})

@app.route('/api/cards/<card_id>/comments', methods=['GET'])
@require_auth
def get_card_comments(card_id):
    """Get all comments for a card."""
    db = get_db()
    uid = g.user_id

    card = db.execute('SELECT comments FROM cards WHERE id = ? AND user_id = ?', (card_id, uid)).fetchone()
    if not card:
        return jsonify({'error': 'Card not found'}), 404

    comments = json.loads(card['comments'] or '[]')
    return jsonify({'comments': comments})

@app.route('/api/cards/<card_id>/comments', methods=['POST'])
@require_auth
def add_card_comment(card_id):
    """Add a comment to a card. Accepts {"content": "...", "author": "..."}."""
    db = get_db()
    uid = g.user_id
    data = request.get_json() or {}
    content = data.get('content', '')
    author = data.get('author', 'User')

    if not content:
        return jsonify({'error': 'Comment content is required'}), 400

    card = db.execute('SELECT comments FROM cards WHERE id = ? AND user_id = ?', (card_id, uid)).fetchone()
    if not card:
        return jsonify({'error': 'Card not found'}), 404

    now = int(time.time())
    comments = json.loads(card['comments'] or '[]')

    # Append new comment
    new_comment = {
        'content': content,
        'timestamp': now,
        'author': author
    }
    comments.append(new_comment)

    # Update card
    db.execute(
        'UPDATE cards SET comments = ?, updated_at = ? WHERE id = ?',
        (json.dumps(comments), now, card_id)
    )
    db.commit()

    return jsonify({'status': 'ok', 'comment': new_comment, 'comments': comments})

# ── COLUMN ROUTES ─────────────────────────────────────────────────────────────

@app.route('/api/columns', methods=['POST'])
@require_auth
def create_column():
    db = get_db()
    uid = g.user_id
    data = request.get_json() or {}
    now = int(time.time())

    col_id = 'col' + str(uuid.uuid4())[:8]
    title = data.get('title', 'New Column')
    color = data.get('color', '#8b7cf8')

    pos_row = db.execute(
        'SELECT COALESCE(MAX(position), -1) + 1 as next_pos FROM columns WHERE user_id = ?',
        (uid,)
    ).fetchone()
    position = pos_row['next_pos']

    db.execute(
        'INSERT INTO columns (id, user_id, title, color, position, created_at) VALUES (?, ?, ?, ?, ?, ?)',
        (col_id, uid, title, color, position, now)
    )
    db.commit()

    return jsonify({'id': col_id})

@app.route('/api/columns/<col_id>', methods=['PUT'])
@require_auth
def update_column(col_id):
    db = get_db()
    uid = g.user_id
    data = request.get_json() or {}

    db.execute(
        'UPDATE columns SET title = COALESCE(?, title), color = COALESCE(?, color) WHERE id = ? AND user_id = ?',
        (data.get('title'), data.get('color'), col_id, uid)
    )
    db.commit()
    return jsonify({'status': 'ok'})

@app.route('/api/columns/<col_id>', methods=['DELETE'])
@require_auth
def delete_column(col_id):
    db = get_db()
    uid = g.user_id
    db.execute('DELETE FROM columns WHERE id = ? AND user_id = ?', (col_id, uid))
    db.execute('DELETE FROM cards WHERE column_id = ? AND user_id = ?', (col_id, uid))
    db.commit()
    return jsonify({'status': 'ok'})

# ── JOB ROUTES (for agent polling) ─────────────────────────────────────────────

@app.route('/api/jobs/pending', methods=['GET'])
@require_auth
def get_pending_jobs():
    """Agent polls this to see unclaimed jobs."""
    db = get_db()
    uid = g.user_id

    jobs = db.execute('''
        SELECT j.id, j.card_id, j.instructions, j.created_at,
               c.title, c.description, c.attachments, c.audio_count
        FROM jobs j
        JOIN cards c ON c.id = j.card_id
        WHERE j.user_id = ? AND j.status = 'pending'
        ORDER BY j.created_at
    ''', (uid,)).fetchall()

    return jsonify({
        'jobs': [{
            'id': j['id'],
            'card_id': j['card_id'],
            'instructions': j['instructions'],
            'title': j['title'],
            'description': j['description'],
            'attachments': json.loads(j['attachments'] or '[]'),
            'audio_count': j['audio_count'],
            'created_at': j['created_at'],
        } for j in jobs]
    })

@app.route('/api/jobs/claim', methods=['POST'])
@require_auth
def claim_job():
    """Agent claims a job before working on it."""
    db = get_db()
    uid = g.user_id
    data = request.get_json() or {}
    job_id = data.get('job_id')
    agent_name = data.get('agent_name', 'Hermes')

    if not job_id:
        return jsonify({'error': 'job_id required'}), 400

    job = db.execute(
        'SELECT id, card_id FROM jobs WHERE id = ? AND user_id = ? AND status = ?',
        (job_id, uid, 'pending')
    ).fetchone()

    if not job:
        return jsonify({'error': 'Job not found or already claimed'}), 404

    now = int(time.time())
    db.execute(
        'UPDATE jobs SET status = ?, picked_up_at = ? WHERE id = ?',
        ('working', now, job_id)
    )
    db.execute(
        'UPDATE cards SET agent_name = ?, agent_status = ?, updated_at = ? WHERE id = ?',
        (agent_name, 'working', now, job['card_id'])
    )
    db.commit()
    return jsonify({'status': 'ok', 'job_id': job_id})

@app.route('/api/jobs/complete', methods=['POST'])
@require_auth
def complete_job():
    """Agent marks a job as done."""
    db = get_db()
    uid = g.user_id
    data = request.get_json() or {}
    job_id = data.get('job_id')
    result = data.get('result', '')
    success = data.get('success', True)

    if not job_id:
        return jsonify({'error': 'job_id required'}), 400

    job = db.execute(
        'SELECT card_id FROM jobs WHERE id = ? AND user_id = ?',
        (job_id, uid)
    ).fetchone()

    if not job:
        return jsonify({'error': 'Job not found'}), 404

    now = int(time.time())
    status = 'completed' if success else 'failed'
    db.execute(
        'UPDATE jobs SET status = ?, result = ?, completed_at = ? WHERE id = ?',
        (status, result, now, job_id)
    )
    db.execute(
        'UPDATE cards SET agent_status = ?, updated_at = ? WHERE id = ?',
        (status, now, job['card_id'])
    )
    db.commit()
    return jsonify({'status': 'ok'})

# ── HEALTH ────────────────────────────────────────────────────────────────────

@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok', 'time': int(time.time())})

# ── INIT ──────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=PORT, debug=False)
