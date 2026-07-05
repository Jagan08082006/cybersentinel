"""
auth.py
---------
Simple authentication helpers: hashing passwords safely (never
store plain-text passwords) and a decorator to protect pages so
only logged-in users can access them.
"""

from functools import wraps
from flask import session, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash


def hash_password(plain_password: str) -> str:
    return generate_password_hash(plain_password)


def verify_password(plain_password: str, password_hash: str) -> bool:
    return check_password_hash(password_hash, plain_password)


def login_required(view_func):
    """
    Decorator: put @login_required above any Flask route that
    should only be accessible to logged-in users. If no one is
    logged in, it redirects them to the login page instead.
    """
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return view_func(*args, **kwargs)
    return wrapped
