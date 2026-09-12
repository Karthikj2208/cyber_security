# Secure Notes / Password Vault

Basic cybersecurity project demonstrating authentication, PBKDF2 key derivation, Fernet encryption, and encrypted local storage.

## Install
```bash
pip install cryptography
```

## Run
```bash
python main.py
```

First run creates a master password. Later runs require authentication.

## Features
- Master-password authentication
- Encrypted vault
- Add, view, search, delete entries
- Hidden password input
- PBKDF2-HMAC-SHA256 key derivation with random salt
- Fernet authenticated symmetric encryption
- Security event logging

## Demonstration
Use fake data only. Add a sample account, view it, search it, delete it, then restart and test an incorrect master password.

## Structure
```text
Secure_Notes_Password_Vault/
├── main.py
├── README.md
├── requirements.txt
├── data/
├── logs/
└── screenshots/
```

Do not store real passwords. This is an educational project, not a production password manager.
