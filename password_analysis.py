"""
password_analysis.py
-----------------------
Checks how strong/weak a given password is.
This does NOT try to crack or brute-force any real account -
it just analyzes the password text itself and scores it.
"""

import re

# A small list of very common/weak passwords.
# (In a real project you could load a bigger list from a .txt file)
COMMON_PASSWORDS = {
    "123456", "password", "123456789", "qwerty", "abc123",
    "111111", "12345678", "1234567", "password1", "admin",
    "letmein", "welcome", "monkey", "iloveyou", "123123",
}


def analyze_password(password: str) -> dict:
    """
    Analyzes a password and returns a strength score (0-100),
    a strength label, and reasons why it is weak (if any).
    """
    result = {
        "password_length": len(password),
        "score": 0,
        "strength": "Very Weak",
        "issues": [],
        "good_points": [],
    }

    if not password:
        result["issues"].append("Password is empty")
        return result

    score = 0

    # 1. Length check
    if len(password) >= 12:
        score += 30
        result["good_points"].append("Good length (12+ characters)")
    elif len(password) >= 8:
        score += 15
        result["good_points"].append("Acceptable length (8+ characters)")
    else:
        result["issues"].append("Too short (less than 8 characters)")

    # 2. Contains lowercase letters
    if re.search(r"[a-z]", password):
        score += 10
    else:
        result["issues"].append("No lowercase letters")

    # 3. Contains uppercase letters
    if re.search(r"[A-Z]", password):
        score += 15
    else:
        result["issues"].append("No uppercase letters")

    # 4. Contains numbers
    if re.search(r"[0-9]", password):
        score += 15
    else:
        result["issues"].append("No numbers")

    # 5. Contains special characters
    if re.search(r"[!@#$%^&*(),.?\":{}|<>_\-+=]", password):
        score += 15
    else:
        result["issues"].append("No special characters (!@#$%^&* etc.)")

    # 6. Check against common password list
    if password.lower() in COMMON_PASSWORDS:
        score = min(score, 10)  # force score down
        result["issues"].append("This is a very commonly used password")

    # 7. Check for repeated characters like "aaaa" or "1111"
    if re.search(r"(.)\1{2,}", password):
        score -= 10
        result["issues"].append("Contains repeated characters (e.g. 'aaa')")

    # Keep score within 0-100
    score = max(0, min(100, score))
    result["score"] = score

    # Decide label based on score
    if score >= 80:
        result["strength"] = "Strong"
    elif score >= 60:
        result["strength"] = "Moderate"
    elif score >= 30:
        result["strength"] = "Weak"
    else:
        result["strength"] = "Very Weak"

    return result
