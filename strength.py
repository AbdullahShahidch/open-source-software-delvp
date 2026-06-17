"""
strength.py
-----------
Offline password strength analysis.

No network access is used here at all -- everything is computed locally
using simple, well-known heuristics:7
  * Shannon-style entropy estimate based on character-set size
  * Rule based checks (length, character variety, repeats, common passwords)

This keeps strength checking instant and private; only the breach check
(in breach.py) needs the internet.
"""

import math
import re

# A small, illustrative list of extremely common / leaked passwords.
# Not exhaustive -- the real-world breach check (breach.py) is what
# catches passwords that have actually appeared in known leaks.
COMMON_PASSWORDS = {
    "123456", "123456789", "qwerty", "password", "111111", "12345678",
    "abc123", "1234567", "password1", "12345", "1234567890", "123123",
    "qwerty123", "1q2w3e4r", "iloveyou", "admin", "welcome", "monkey",
    "login", "letmein", "dragon", "111111111", "baseball", "football",
    "trustno1", "sunshine", "master", "hello", "freedom", "whatever",
    "qazwsx", "zaq12wsx", "passw0rd", "starwars", "654321", "superman",
}

# Labels for the 0-7 rule-based point scale used in check_strength()
_LABELS = [
    "Very Weak", "Very Weak", "Weak", "Fair",
    "Good", "Strong", "Very Strong", "Excellent",
]


def calculate_entropy(password: str) -> float:
    """Rough entropy estimate in bits, based on the size of the character
    pool the password draws from and its length. This is a simplification
    (it assumes random selection from the pool) but is good enough to give
    a relative sense of brute-force resistance."""
    if not password:
        return 0.0

    pool = 0
    if re.search(r"[a-z]", password):
        pool += 26
    if re.search(r"[A-Z]", password):
        pool += 26
    if re.search(r"[0-9]", password):
        pool += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        pool += 32  # approximate size of common symbol set

    if pool == 0:
        return 0.0

    return len(password) * math.log2(pool)


def check_strength(password: str) -> dict:
    """Analyze a password and return a dict with:
        score    -- 0-100 overall strength percentage
        label    -- human readable category
        entropy  -- estimated entropy in bits
        feedback -- list of improvement suggestions (empty if great)
    """
    if not password:
        return {
            "score": 0,
            "label": "Empty",
            "entropy": 0.0,
            "feedback": ["Enter a password to analyze."],
        }

    feedback = []
    points = 0
    length = len(password)

    if length >= 16:
        points += 2
    elif length >= 12:
        points += 1
    else:
        feedback.append("Use at least 12 characters (16+ is better).")

    if re.search(r"[a-z]", password):
        points += 1
    else:
        feedback.append("Add lowercase letters.")

    if re.search(r"[A-Z]", password):
        points += 1
    else:
        feedback.append("Add uppercase letters.")

    if re.search(r"[0-9]", password):
        points += 1
    else:
        feedback.append("Add numbers.")

    if re.search(r"[^a-zA-Z0-9]", password):
        points += 1
    else:
        feedback.append("Add symbols (e.g. ! @ # $ %).")

    if re.search(r"(.)\1\1", password):
        points = max(points - 1, 0)
        feedback.append("Avoid repeating the same character 3+ times in a row.")

    if password.lower() in COMMON_PASSWORDS:
        points = 0
        feedback = ["This is one of the most commonly used passwords. Avoid it entirely."]

    max_points = 7
    points = min(points, max_points)
    score = round((points / max_points) * 100)
    label = _LABELS[points]
    entropy = round(calculate_entropy(password), 1)

    if not feedback:
        feedback.append("Looks solid by these rules. Still check it for breaches.")

    return {
        "score": score,
        "label": label,
        "entropy": entropy,
        "feedback": feedback,
    }
