"""
database.py
-------------
Handles all database operations using SQLite (a simple file-based
database, no separate database server needed).

Two tables:
1. users         - stores login accounts (username + hashed password)
2. scan_history  - stores every scan a logged-in user has run, so
                   they can look back at past results later
"""

import sqlite3
import json
from datetime import datetime

DB_FILE = "scanner.db"


def get_connection():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row  # lets us access columns by name
    return conn


def init_db():
    """Creates the tables if they don't already exist. Safe to call every time the app starts."""
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            target_url TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            severity TEXT NOT NULL,
            results_json TEXT NOT NULL,
            scanned_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    """)

    conn.commit()
    conn.close()


# ---------------- USER FUNCTIONS ----------------

def create_user(username: str, password_hash: str) -> bool:
    """Adds a new user. Returns False if the username is already taken."""
    conn = get_connection()
    try:
        conn.execute(
            "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
            (username, password_hash, datetime.now().isoformat())
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()


def get_user_by_username(username: str):
    conn = get_connection()
    user = conn.execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()
    conn.close()
    return user


# ---------------- SCAN HISTORY FUNCTIONS ----------------

def save_scan(user_id: int, target_url: str, risk_score: int, severity: str, results: dict):
    """Saves a completed scan to history for a specific user."""
    conn = get_connection()
    conn.execute(
        """INSERT INTO scan_history
           (user_id, target_url, risk_score, severity, results_json, scanned_at)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (user_id, target_url, risk_score, severity, json.dumps(results), datetime.now().isoformat())
    )
    conn.commit()
    conn.close()


def get_scan_history(user_id: int, limit: int = 20):
    """Returns a user's past scans, most recent first."""
    conn = get_connection()
    rows = conn.execute(
        """SELECT id, target_url, risk_score, severity, scanned_at
           FROM scan_history WHERE user_id = ?
           ORDER BY scanned_at DESC LIMIT ?""",
        (user_id, limit)
    ).fetchall()
    conn.close()
    return rows


def get_scan_by_id(scan_id: int, user_id: int):
    """Returns one full past scan (with full results) - only if it belongs to this user."""
    conn = get_connection()
    row = conn.execute(
        "SELECT * FROM scan_history WHERE id = ? AND user_id = ?",
        (scan_id, user_id)
    ).fetchone()
    conn.close()
    if row:
        return {
            "id": row["id"],
            "target_url": row["target_url"],
            "risk_score": row["risk_score"],
            "severity": row["severity"],
            "results": json.loads(row["results_json"]),
            "scanned_at": row["scanned_at"],
        }
    return None
