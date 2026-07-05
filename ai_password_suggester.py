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

    if not any(c.isupper() for c in result):
        result = result[0].upper() + result[1:]

    result += random.choice(strong_suffixes)
    return result

def generate_suggestions(password):
    suggestions = []
    base = password.strip()

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

def suggest_strong_password(weak_password):
    try:
        reasons = analyze_weakness(weak_password)
        suggestions = generate_suggestions(weak_password)

        tips = [
            "Use at least 12 characters for strong security",
            "Mix uppercase, lowercase, numbers and symbols",
            "Never use your name, birthday or common words",
            "Use a different password for every account",
            "Consider using a password manager"
        ]

        selected_tips = random.sample(tips, 2)

        result_text = "WHY IT'S WEAK:\n"
        if reasons:
            for r in reasons:
                result_text += f"  • {r}\n"
        else:
            result_text += "  • Could be stronger with more complexity\n"

        result_text += "\nSUGGESTED STRONG PASSWORDS:\n"
        for i, s in enumerate(suggestions, 1):
            result_text += f"  {i}. {s}\n"

        result_text += "\nSECURITY TIPS:\n"
        for tip in selected_tips:
            result_text += f"  • {tip}\n"

        return {"success": True, "suggestion": result_text}

    except Exception as e:
        return {"success": False, "suggestion": f"Could not generate suggestion: {str(e)}"}