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
    """Afficher toutes les clés avec leur statut"""
    keys = query_db("SELECT id, key, is_active, activation_date, expiration_date FROM activation_keys")
    return jsonify([{
        "id": row[0],
@@ -54,7 +53,6 @@

@app.route("/create", methods=["POST"])
def create_key():
    """Créer une nouvelle clé"""
    admin_token = os.getenv("ADMIN_TOKEN", "secret")
    if request.headers.get("Authorization") != f"Bearer {admin_token}":
        return jsonify({"error": "Unauthorized"}), 403
@@ -73,10 +71,9 @@

@app.route("/activate", methods=["POST"])
def activate_key():
    """Activer une clé pour une période définie"""
    data = request.json
    key = data.get("key")
    duration = data.get("duration")  # Exemple : "1w", "1m", "1y"
    duration = data.get("duration")

    if not key or not duration:
        return jsonify({"error": "Missing key or duration"}), 400
@@ -89,7 +86,6 @@
    elif row[0] == 1:
        return jsonify({"error": "Key already activated"}), 400

    # Calcul de la date d'expiration
    now = datetime.utcnow()
    expiration = now
    if duration.endswith("w"):
@@ -107,11 +103,10 @@
        WHERE key = ?
    """, (now, expiration, hashed_key))

    return jsonify({"message": "Key activated successfully!", "expires_at": expiration}), 200
    return jsonify({"message": "Key activated successfully!", "expires_at": expiration.isoformat()}), 200

@app.route("/deactivate", methods=["POST"])
def deactivate_key():
    """Désactiver une clé"""
    data = request.json
    key = data.get("key")

@@ -136,24 +131,28 @@

@app.route("/check/<key>", methods=["GET"])
def check_key(key):
    """Vérifier le statut d'une clé"""
    hashed_key = hash_key(key)
    row = query_db("SELECT is_active, expiration_date FROM activation_keys WHERE key = ?", (hashed_key,), one=True)

    if not row:
        return jsonify({"error": "Invalid key"}), 404
    is_active, expiration_date = row
    if is_active and expiration_date and datetime.utcnow() > datetime.fromisoformat(expiration_date):
        # Désactiver la clé si elle est expirée
        query_db("""
            UPDATE activation_keys
            SET is_active = 0, activation_date = NULL, expiration_date = NULL
            WHERE key = ?
        """, (hashed_key,))
        return jsonify({"error": "Key expired"}), 403

    return jsonify({"is_active": bool(is_active), "expires_at": expiration_date}), 200
    is_active, expiration_date = row
    if is_active and expiration_date:
        expiration_date = datetime.fromisoformat(expiration_date)
        if datetime.utcnow() > expiration_date:
            # Expire la clé si elle est hors délai
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
