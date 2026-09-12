import hashlib
import math
import os
import re
import getpass
from datetime import datetime

COMMON_FILE = os.path.join("data", "common_passwords.txt")
LOG_FILE = os.path.join("logs", "analysis.log")


def load_common_passwords():
    with open(COMMON_FILE, "r", encoding="utf-8") as f:
        return {line.strip().lower() for line in f if line.strip()}


def calculate_entropy(password):
    pool = 0
    if re.search(r"[a-z]", password):
        pool += 26
    if re.search(r"[A-Z]", password):
        pool += 26
    if re.search(r"\d", password):
        pool += 10
    if re.search(r"[^A-Za-z0-9]", password):
        pool += 32

    if pool == 0:
        return 0.0
    return len(password) * math.log2(pool)


def strength_score(password, common):
    score = 0
    suggestions = []

    length = len(password)

    if length >= 16:
        score += 35
    elif length >= 12:
        score += 28
    elif length >= 8:
        score += 20
    elif length >= 6:
        score += 10
    else:
        suggestions.append("Use at least 12 characters.")

    if re.search(r"[a-z]", password):
        score += 10
    else:
        suggestions.append("Add lowercase letters.")

    if re.search(r"[A-Z]", password):
        score += 10
    else:
        suggestions.append("Add uppercase letters.")

    if re.search(r"\d", password):
        score += 10
    else:
        suggestions.append("Add numbers.")

    if re.search(r"[^A-Za-z0-9]", password):
        score += 15
    else:
        suggestions.append("Add special characters such as !, @, #, or $.")

    if password.lower() in common:
        score = min(score, 15)
        suggestions.append("Avoid common passwords and predictable words.")

    if re.search(r"(.)\1{2,}", password):
        score -= 10
        suggestions.append("Avoid repeated characters such as aaa or 111.")

    if re.search(r"(123|abc|qwerty|password|admin)", password.lower()):
        score -= 15
        suggestions.append("Avoid common sequences and predictable patterns.")

    score = max(0, min(100, score))

    if score < 30:
        label = "VERY WEAK"
    elif score < 50:
        label = "WEAK"
    elif score < 70:
        label = "MODERATE"
    elif score < 85:
        label = "STRONG"
    else:
        label = "VERY STRONG"

    return score, label, suggestions


def sha256_hash(password):
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def log_analysis(score, label, entropy):
    # Never save the actual password.
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(
            f"{datetime.now():%Y-%m-%d %H:%M:%S} | "
            f"Score={score}/100 | Strength={label} | Entropy={entropy:.2f} bits\n"
        )


def analyze_password():
    print("\nEnter a password to analyze (input will be hidden).")
    password = getpass.getpass("Password: ")

    if not password:
        print("Password cannot be empty.")
        return

    common = load_common_passwords()
    entropy = calculate_entropy(password)
    score, label, suggestions = strength_score(password, common)
    is_common = password.lower() in common
    digest = sha256_hash(password)

    print("\n" + "=" * 55)
    print("PASSWORD SECURITY ANALYSIS")
    print("=" * 55)
    print(f"Length             : {len(password)}")
    print(f"Entropy             : {entropy:.2f} bits")
    print(f"Strength score      : {score}/100")
    print(f"Strength            : {label}")
    print(f"Common password?    : {'YES - avoid it' if is_common else 'No'}")
    print(f"Lowercase           : {'Yes' if re.search(r'[a-z]', password) else 'No'}")
    print(f"Uppercase           : {'Yes' if re.search(r'[A-Z]', password) else 'No'}")
    print(f"Number              : {'Yes' if re.search(r'\\d', password) else 'No'}")
    print(f"Special character   : {'Yes' if re.search(r'[^A-Za-z0-9]', password) else 'No'}")

    print("\nSHA-256 demonstration:")
    print(digest)

    if suggestions:
        print("\nSuggestions:")
        for item in suggestions:
            print(f"- {item}")
    else:
        print("\nNo basic improvement suggestions.")

    log_analysis(score, label, entropy)


def view_logs():
    print("\n" + "=" * 55)
    print("ANALYSIS LOG")
    print("=" * 55)

    if not os.path.exists(LOG_FILE):
        print("No analysis has been recorded yet.")
        return

    with open(LOG_FILE, "r", encoding="utf-8") as f:
        content = f.read().strip()

    print(content or "No analysis has been recorded yet.")


def main():
    print("=" * 55)
    print("        PASSWORD STRENGTH ANALYZER")
    print("=" * 55)
    print("Educational cybersecurity project")
    print("Your password is not stored in the log.\n")

    while True:
        print("\n1. Analyze Password")
        print("2. View Analysis Log")
        print("3. Exit")

        choice = input("\nEnter choice: ").strip()

        if choice == "1":
            analyze_password()
        elif choice == "2":
            view_logs()
        elif choice == "3":
            print("Exiting...")
            break
        else:
            print("Invalid choice. Enter 1-3.")


if __name__ == "__main__":
    main()
