from flask import Flask, request, jsonify, send_from_directory
import sqlite3
import hashlib
import os

app = Flask(__name__)

# Setup SQLite
DB_PATH = "keys.db"

def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS activation_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key TEXT NOT NULL UNIQUE,
                is_active INTEGER DEFAULT 0
            )
        """)
    print("Database initialized!")

init_db()

# API Routes
@app.route('/', methods=['GET'])
def home():
    """Home route"""
    return jsonify({"message": "Welcome to the Activation Key API!"}), 200

@app.route('/favicon.ico')
def favicon():
    """Handle favicon requests"""
    return '', 204

@app.route('/activate', methods=['POST'])
def activate_key():
    """Activate a key"""
    data = request.json
    key = data.get('key')

    if not key:
        return jsonify({"error": "Missing key"}), 400

    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT is_active FROM activation_keys WHERE key = ?", (key,))
        row = cursor.fetchone()

        if row is None:
            return jsonify({"error": "Invalid key"}), 404
        elif row[0] == 1:
            return jsonify({"error": "Key already activated"}), 400
        else:
            cursor.execute("UPDATE activation_keys SET is_active = 1 WHERE key = ?", (key,))
            conn.commit()
            return jsonify({"message": "Key activated successfully!"}), 200

@app.route('/check/<key>', methods=['GET'])
def check_key(key):
    """Check if a key is valid and active"""
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT is_active FROM activation_keys WHERE key = ?", (key,))
        row = cursor.fetchone()

        if row is None:
            return jsonify({"error": "Invalid key"}), 404
        return jsonify({"is_active": bool(row[0])}), 200

@app.route('/create', methods=['POST'])
def create_key():
    """Create a new key (Admin only)"""
    admin_token = os.getenv("ADMIN_TOKEN", "secret")
    if request.headers.get("Authorization") != f"Bearer {admin_token}":
        return jsonify({"error": "Unauthorized"}), 403

    data = request.json
    key = data.get('key')
    if not key:
        return jsonify({"error": "Missing key"}), 400

    hashed_key = hashlib.sha256(key.encode()).hexdigest()

    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        try:
            cursor.execute("INSERT INTO activation_keys (key) VALUES (?)", (hashed_key,))
            conn.commit()
            return jsonify({"message": "Key created successfully!"}), 201
        except sqlite3.IntegrityError:
            return jsonify({"error": "Key already exists"}), 400

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
