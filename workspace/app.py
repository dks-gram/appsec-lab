"""
AppSec Lab — workspace/app.py
==============================
This is your working file for all labs.
Use GitHub Copilot to generate each route/function as instructed
in the challenge cards, then identify and fix the vulnerabilities.
"""

import sqlite3
import bcrypt
from flask import Flask, g, request

app = Flask(__name__)
app.config["DATABASE"] = "users.db"
app.config["SECRET_KEY"] = "change-me-in-production"


# ── Database helpers ────────────────────────────────────────────────────────

def get_db():
    """Return a database connection, creating one if needed."""
    if "db" not in g:
        database = app.config["DATABASE"]
        if database == ":memory":
            database = ":memory:"
        if database == ":memory:":
            if "_persistent_db" not in app.config:
                app.config["_persistent_db"] = sqlite3.connect(
                    database,
                    detect_types=sqlite3.PARSE_DECLTYPES
                )
                app.config["_persistent_db"].row_factory = sqlite3.Row
            g.db = app.config["_persistent_db"]
        else:
            g.db = sqlite3.connect(
                database,
                detect_types=sqlite3.PARSE_DECLTYPES
            )
            g.db.row_factory = sqlite3.Row
    return g.db


def init_db():
    """Create tables if they don't exist."""
    db = get_db()
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS invoices (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id  TEXT NOT NULL,
            amount   REAL NOT NULL,
            details  TEXT
        );
    """)
    db.commit()


@app.teardown_appcontext
def close_db(error):
    db = g.pop("db", None)
    if db is not None and db is not app.config.get("_persistent_db"):
        db.close()


# ── Lab 01: SQL Injection ────────────────────────────────────────────────────
# Ask Copilot: "Write a Flask POST /login route that checks a username
#               and password against a SQLite database called users.db"
# Paste Copilot's code below this comment, then find and fix the vulnerability.

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    if not username or not password:
        return "Unauthorized", 401

    db = get_db()
    cursor = db.execute(
        "SELECT password FROM users WHERE username = ?",
        (username,)
    )
    row = cursor.fetchone()
    if row is None:
        return "Unauthorized", 401

    stored_hash = row["password"]
    if isinstance(stored_hash, str):
        stored_hash = stored_hash.encode("utf-8")

    if bcrypt.checkpw(password.encode("utf-8"), stored_hash):
        return "OK", 200

    return "Unauthorized", 401


# ── Lab 02: Cross-Site Scripting (XSS) ──────────────────────────────────────
# Ask Copilot: "Write a Flask GET /search route that displays search results
#               for a query parameter q in an HTML response"
# Paste Copilot's code below this comment, then find and fix the vulnerability.

# YOUR CODE HERE


# ── Lab 03: Broken Authentication ────────────────────────────────────────────
# Ask Copilot: "Write a register_user(username, password) function that hashes
#               the password and stores the user in the SQLite database"
# Paste Copilot's code below this comment, then find and fix the vulnerability.

# YOUR CODE HERE


# ── Lab 04: IDOR ─────────────────────────────────────────────────────────────
# Ask Copilot: "Write a Flask GET /invoice/<invoice_id> route that returns
#               the invoice as JSON for the logged-in user"
# Paste Copilot's code below this comment, then find and fix the vulnerability.

# YOUR CODE HERE


# ── Lab 05: Sensitive Data Exposure ──────────────────────────────────────────
# Ask Copilot: "Write a Python module that connects to AWS S3 and
#               a Stripe payment API using configuration variables"
# Paste Copilot's code below this comment, then find and fix the vulnerability.

# YOUR CODE HERE


# ── Lab 06: Command Injection ────────────────────────────────────────────────
# Ask Copilot: "Write a Flask POST /ping route that pings a hostname
#               submitted by the user and returns the output"
# Paste Copilot's code below this comment, then find and fix the vulnerability.

# YOUR CODE HERE


# ── Lab 07: XXE Injection ────────────────────────────────────────────────────
# Ask Copilot: "Write a Flask POST /upload route that accepts an XML file
#               upload and returns the parsed content as JSON"
# Paste Copilot's code below this comment, then find and fix the vulnerability.

# YOUR CODE HERE


if __name__ == "__main__":
    with app.app_context():
        init_db()
    app.run(debug=True)
