from flask import Flask, request, jsonify
import sqlite3
import hashlib
import os
from datetime import datetime, timedelta

app = Flask(__name__)

DB_PATH = "keys.db"

# Initialisation de la base de données
def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS activation_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key TEXT NOT NULL UNIQUE,
                is_active INTEGER DEFAULT 0,
                is_created INTEGER DEFAULT 1,  # Nouveau champ pour marquer si la clé a été créée
                activation_date DATETIME,
                expiration_date DATETIME
            )
        """)
    print("Database initialized!")

init_db()

# Fonctions utilitaires
def hash_key(key):
    return hashlib.sha256(key.encode()).hexdigest()

def query_db(query, args=(), one=False):
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(query, args)
        result = cursor.fetchall()
        conn.commit()
        return (result[0] if result else None) if one else result

# Routes API
@app.route("/", methods=["GET"])
def home():
    return jsonify({"message": "Welcome to the Advanced Activation Key API!"}), 200

@app.route("/allkeys", methods=["GET"])
def get_all_keys():
    keys = query_db("SELECT id, key, is_active, is_created, activation_date, expiration_date FROM activation_keys")
    return jsonify([{
        "id": row[0],
        "key": row[1],
        "is_active": bool(row[2]),
        "is_created": bool(row[3]),
        "activation_date": row[4],
        "expiration_date": row[5]
    } for row in keys]), 200

@app.route("/create", methods=["POST"])
def create_key():
    admin_token = os.getenv("ADMIN_TOKEN", "secret")
    if request.headers.get("Authorization") != f"Bearer {admin_token}":
        return jsonify({"error": "Unauthorized"}), 403

    data = request.json
    key = data.get("key")
    if not key:
        return jsonify({"error": "Missing key"}), 400

    hashed_key = hash_key(key)
    try:
        # Création de la clé avec is_active = 0 et is_created = 1
        query_db("INSERT INTO activation_keys (key, is_active, is_created) VALUES (?, 0, 1)", (hashed_key,))
        
        # Vérification de l'état de la clé après la création
        row = query_db("SELECT is_active, is_created FROM activation_keys WHERE key = ?", (hashed_key,), one=True)
        print(f"Clé {key} créée avec is_active = {row[0]}, is_created = {row[1]}")  # Log de l'état de la clé
        
        return jsonify({"message": "Key created successfully but is not usable until activation!"}), 201
    except sqlite3.IntegrityError:
        return jsonify({"error": "Key already exists"}), 400


@app.route("/activate", methods=["POST"])
def activate_key():
    data = request.json
    key = data.get("key")
    duration = data.get("duration")

    if not key or not duration:
        return jsonify({"error": "Missing key or duration"}), 400

    hashed_key = hash_key(key)
    row = query_db("SELECT is_active, is_created FROM activation_keys WHERE key = ?", (hashed_key,), one=True)

    if not row:
        return jsonify({"error": "Invalid key"}), 404
    elif row[0] == 1:
        return jsonify({"error": "Key already activated"}), 400
    elif row[1] == 1:
        return jsonify({"error": "Key is created but not activated. Please activate the key first."}), 403

    now = datetime.utcnow()
    expiration = now
    if duration.endswith("w"):
        expiration += timedelta(weeks=int(duration[:-1]))
    elif duration.endswith("m"):
        expiration += timedelta(days=30 * int(duration[:-1]))
    elif duration.endswith("y"):
        expiration += timedelta(days=365 * int(duration[:-1]))
    else:
        return jsonify({"error": "Invalid duration format"}), 400

    # Activation de la clé et mise à jour de la date d'expiration
    query_db("""
        UPDATE activation_keys
        SET is_active = 1, is_created = 0, activation_date = ?, expiration_date = ?
        WHERE key = ?
    """, (now, expiration, hashed_key))

    return jsonify({"message": "Key activated successfully!", "expires_at": expiration.isoformat()}), 200

@app.route("/deactivate", methods=["POST"])
def deactivate_key():
    data = request.json
    key = data.get("key")

    if not key:
        return jsonify({"error": "Missing key"}), 400

    hashed_key = hash_key(key)
    row = query_db("SELECT is_active FROM activation_keys WHERE key = ?", (hashed_key,), one=True)

    if not row:
        return jsonify({"error": "Invalid key"}), 404
    elif row[0] == 0:
        return jsonify({"error": "Key is already inactive"}), 400

    # Désactivation de la clé
    query_db("""
        UPDATE activation_keys
        SET is_active = 0, activation_date = NULL, expiration_date = NULL
        WHERE key = ?
    """, (hashed_key,))

    # Vérification de la désactivation de la clé
    row = query_db("SELECT is_active FROM activation_keys WHERE key = ?", (hashed_key,), one=True)
    if row[0] == 0:
        print(f"Clé {key} a été désactivée avec succès dans la base de données.")
    
    return jsonify({"message": "Key deactivated successfully!"}), 200

@app.route("/check/<key>", methods=["GET"])
def check_key(key):
    hashed_key = hash_key(key)
    row = query_db("SELECT is_active, is_created, expiration_date FROM activation_keys WHERE key = ?", (hashed_key,), one=True)

    if not row:
        return jsonify({"error": "Invalid key"}), 404

    is_active, is_created, expiration_date = row

    # Log pour vérifier si la clé est active ou inactive
    print(f"Clé {key} - is_active: {is_active}, is_created: {is_created}, expiration_date: {expiration_date}")

    # La clé ne peut pas être utilisée si elle n'est pas activée
    if is_created == 1:
        return jsonify({"error": "Key is created but not activated. Please activate the key first."}), 403
    elif not is_active:
        return jsonify({"error": "Key is deactivated"}), 403

    if expiration_date:
        expiration_date = datetime.fromisoformat(expiration_date)
        if datetime.utcnow() > expiration_date:
            query_db("""
                UPDATE activation_keys
                SET is_active = 0, activation_date = NULL, expiration_date = NULL
                WHERE key = ?
            """, (hashed_key,))
            return jsonify({"error": "Key expired"}), 403

    return jsonify({
        "is_active": bool(is_active),
        "expires_at": expiration_date.isoformat() if expiration_date else None
    }), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
