# Password Strength Analyzer

## Project Type
Basic Cybersecurity / Python Project

## Objective
This project analyzes password security using:
- Password length and character composition
- Entropy estimation
- Strength scoring from 0 to 100
- Common-password detection
- SHA-256 hashing demonstration
- Security suggestions
- Analysis logging without storing the original password

## Requirements
- Python 3.8 or newer
- No external Python packages

## How to Run

Open a terminal inside the project folder and run:

    python main.py

On Windows, if `python` does not work, try:

    py main.py

## Menu

1. Analyze Password
2. View Analysis Log
3. Exit

## Demonstration

### Test 1: Weak password
Try:

    password123

Expected result: weak/very weak and common-password warning.

### Test 2: Stronger password
Use a unique password containing 12+ characters, uppercase/lowercase letters, numbers, and symbols.

Do not use your real password for a college demonstration.

## Concepts Explained

### Entropy
Entropy is estimated as:

    entropy = password_length × log2(character_pool_size)

The character pool depends on whether the password contains lowercase letters, uppercase letters, digits, and symbols.

This is an educational estimate, not a complete password-cracking model.

### SHA-256
The application calculates a SHA-256 digest to demonstrate hashing. Hashing is one-way in normal use and is different from encryption.

Important: real password-storage systems should use a password-specific slow hashing function such as Argon2id, scrypt, or bcrypt with appropriate parameters rather than plain SHA-256.

## Project Structure

    Password_Strength_Analyzer/
    │
    ├── main.py
    ├── README.md
    ├── data/
    │   └── common_passwords.txt
    ├── logs/
    │   └── analysis.log
    └── screenshots/

## Limitations
- The common-password list is intentionally small for an academic project.
- Entropy is only an estimate.
- The project does not check passwords against a live breach database.
- SHA-256 is included for educational hashing concepts, not as a recommendation for password storage.

## Future Enhancements
- GUI using Tkinter
- Larger password dictionary
- HaveIBeenPwned-style breach checking using privacy-preserving APIs
- Password generator
- zxcvbn-style strength estimation
- Exportable security reports
