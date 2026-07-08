"""
ai_password_suggester.py
---------------------------
If a user's password is Weak/Very Weak/Moderate, this generates a
strong alternative password suggestion (rule-based transformation +
random strong suffixes/tips), along with the reasons the original
password was weak.

NOTE: app.py calls this as:
    suggest_strong_password(password, password_report["strength"])
and templates/index.html reads:
    results.ai_suggestion.error
    results.ai_suggestion.suggestion
    results.ai_suggestion.tip
So this module keeps that (password, strength_label) -> {"suggestion", "tip", "error"}
contract, while using the new local generation logic instead of calling an
external AI API.
"""

import random
import string


def analyze_weakness(password):
    reasons = []

    if len(password) < 8:
        reasons.append("Too short (less than 8 characters)")
    if password.lower() in ['password', 'pass', '123456', 'admin', 'qwerty', 'letmein']:
        reasons.append("This is a very common password found in breach databases")
    if password.isdigit():
        reasons.append("Contains only numbers — very easy to brute force")
    if password.isalpha():
        reasons.append("Contains only letters — no numbers or symbols")
    if not any(c.isupper() for c in password):
        reasons.append("No uppercase letters")
    if not any(c.isdigit() for c in password):
        reasons.append("No numbers")
    if not any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in password):
        reasons.append("No special characters")

    return reasons


def transform_password(password):
    substitutions = {
        'a': '@', 'A': '@',
        'o': '0', 'O': '0',
        'i': '1', 'I': '1',
        'e': '3', 'E': '3',
        's': '$', 'S': '$',
        'l': '1', 'L': '1',
        'b': '8', 'B': '8',
        't': '7', 'T': '7',
    }

    strong_suffixes = [
        '#Secure2024!',
        '@CyberKey99!',
        '!Lock#2024',
        '$Shield77!',
        '#Guard@2024',
    ]

    result = ''
    substituted = False
    for char in password:
        if char in substitutions and not substituted:
            result += substitutions[char]
            substituted = True
        else:
            result += char

    if result and not any(c.isupper() for c in result):
        result = result[0].upper() + result[1:]

    result += random.choice(strong_suffixes)
    return result


def generate_suggestions(password):
    suggestions = []
    base = password.strip() or "user"

    suggestion1 = transform_password(base)
    suggestions.append(suggestion1)

    special_chars = ['!', '@', '#', '$', '%']
    numbers = ['2024', '99', '77', '123']
    suggestion2 = (
        base[0].upper() +
        base[1:] +
        random.choice(special_chars) +
        random.choice(numbers) +
        random.choice(special_chars)
    )
    suggestions.append(suggestion2)

    random_strong = (
        base[0].upper() +
        ''.join(random.choices(string.ascii_letters + string.digits, k=4)) +
        random.choice(['!', '@', '#', '$']) +
        base[-1] +
        str(random.randint(10, 99))
    )
    suggestions.append(random_strong)

    return suggestions


def suggest_strong_password(weak_password: str, strength_label: str = None) -> dict:
    """
    Generates a strong password suggestion locally (no external AI call).
    Returns {"suggestion": "...", "tip": "...", "error": None}
    to match what app.py / templates/index.html expect.
    """
    try:
        weak_password = (weak_password or "").strip()
        if not weak_password:
            return {"suggestion": None, "tip": None, "error": "No password provided."}

        reasons = analyze_weakness(weak_password)
        suggestions = generate_suggestions(weak_password)

        tips = [
            "Use at least 12 characters for strong security",
            "Mix uppercase, lowercase, numbers and symbols",
            "Never use your name, birthday or common words",
            "Use a different password for every account",
            "Consider using a password manager",
        ]

        # Build a single combined suggestion block (reasons + suggestions + tips)
        # so it still fits the template's single "suggestion" text field.
        lines = []
        if strength_label:
            lines.append(f"Current strength: {strength_label}")

        lines.append("Why it's weak:")
        if reasons:
            for r in reasons:
                lines.append(f"  • {r}")
        else:
            lines.append("  • Could be stronger with more complexity")

        lines.append("")
        lines.append("Suggested strong passwords:")
        for i, s in enumerate(suggestions, 1):
            lines.append(f"  {i}. {s}")

        suggestion_text = "\n".join(lines)
        tip_text = " • ".join(random.sample(tips, 2))

        return {"suggestion": suggestion_text, "tip": tip_text, "error": None}

    except Exception as e:
        return {"suggestion": None, "tip": None, "error": f"Could not generate suggestion: {str(e)}"}
