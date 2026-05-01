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
            updated_at INTEGER NOT NULL
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
    db.close()

# ── AUTH HELPERS ──────────────────────────────────────────────────────────────

def hash_password(pw: str) -> str:
    return hashlib.sha256(pw.encode()).hexdigest()

def generate_token() -> str:
    return secrets.token_urlsafe(32)

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

@app.route('/auth/register', methods=['POST'])
def register():
    data = request.get_json() or {}
    password = data.get('password', '')
    if len(password) < 8:
        return jsonify({'error': 'Password must be at least 8 characters'}), 400

    db = get_db()
    existing = db.execute('SELECT id FROM users LIMIT 1').fetchone()
    if existing:
        return jsonify({'error': 'An account already exists. Please sign in.'}), 409

    user_id = str(uuid.uuid4())
    password_hash = hash_password(password)
    now = int(time.time())

    db.execute(
        'INSERT INTO users (id, password_hash, created_at) VALUES (?, ?, ?)',
        (user_id, password_hash, now)
    )
    db.commit()

    # Create default columns for new user
    default_cols = [
        ('ideas',    'Ideas',       '#8b7cf8', 0),
        ('todo',     'To Do',       '#ff6b8a', 1),
        ('doing',    'In Progress', '#ffd060', 2),
        ('done',     'Done',        '#5de8a0', 3),
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

@app.route('/auth/login', methods=['POST'])
def login():
    data = request.get_json() or {}
    password = data.get('password', '')

    db = get_db()
    user = db.execute('SELECT id, password_hash FROM users LIMIT 1').fetchone()
    if not user or user['password_hash'] != hash_password(password):
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

@app.route('/board', methods=['GET'])
@require_auth
def get_board():
    db = get_db()
    uid = g.user_id

    columns = db.execute(
        'SELECT id, title, color FROM columns WHERE user_id = ? ORDER BY position',
        (uid,)
    ).fetchall()

    result = []
    for col in columns:
        cards = db.execute(
            '''SELECT id, title, description, is_job, agent_name, agent_status,
                      agent_instructions, attachments, audio_count, position, created_at, updated_at, column_id
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
            })

        result.append({
            'id': col['id'],
            'title': col['title'],
            'color': col['color'],
            'cards': card_list,
        })

    return jsonify({'columns': result})

# ── CARD ROUTES ────────────────────────────────────────────────────────────────

@app.route('/cards', methods=['POST'])
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

    # Position = end of column
    pos_row = db.execute(
        'SELECT COALESCE(MAX(position), -1) + 1 as next_pos FROM cards WHERE user_id = ? AND column_id = ?',
        (uid, column_id)
    ).fetchone()
    position = pos_row['next_pos']

    db.execute('''
        INSERT INTO cards (id, user_id, column_id, title, description, is_job, agent_instructions,
                          attachments, audio_count, position, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
        (card_id, uid, column_id, title, description, is_job, agent_instructions,
         attachments, audio_count, position, now, now)
    )

    # If it's a job, also create a job record
    if is_job:
        job_id = 'j' + str(uuid.uuid4())[:8]
        db.execute('''
            INSERT INTO jobs (id, card_id, user_id, status, instructions, created_at)
            VALUES (?, ?, ?, 'pending', ?, ?)''',
            (job_id, card_id, uid, agent_instructions, now)
        )

    db.commit()
    return jsonify({'id': card_id, 'status': 'ok'})

@app.route('/cards/<card_id>', methods=['PUT'])
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

    updates.append('updated_at = ?')
    params.append(now)
    params.append(card_id)

    db.execute(f"UPDATE cards SET {', '.join(updates)} WHERE id = ?", params)
    db.commit()

    return jsonify({'status': 'ok'})

@app.route('/cards/<card_id>', methods=['DELETE'])
@require_auth
def delete_card(card_id):
    db = get_db()
    uid = g.user_id
    db.execute('DELETE FROM cards WHERE id = ? AND user_id = ?', (card_id, uid))
    db.execute('DELETE FROM jobs WHERE card_id = ?', (card_id,))
    db.commit()
    return jsonify({'status': 'ok'})

# ── COLUMN ROUTES ─────────────────────────────────────────────────────────────

@app.route('/columns', methods=['POST'])
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

@app.route('/columns/<col_id>', methods=['PUT'])
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

@app.route('/columns/<col_id>', methods=['DELETE'])
@require_auth
def delete_column(col_id):
    db = get_db()
    uid = g.user_id
    db.execute('DELETE FROM columns WHERE id = ? AND user_id = ?', (col_id, uid))
    db.execute('DELETE FROM cards WHERE column_id = ? AND user_id = ?', (col_id, uid))
    db.commit()
    return jsonify({'status': 'ok'})

# ── JOB ROUTES (for agent polling) ─────────────────────────────────────────────

@app.route('/jobs/pending', methods=['GET'])
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

@app.route('/jobs/claim', methods=['POST'])
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

@app.route('/jobs/complete', methods=['POST'])
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

@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok', 'time': int(time.time())})

# ── INIT ──────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=PORT, debug=False)
