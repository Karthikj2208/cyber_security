import hashlib
import json
import os
from datetime import datetime

BASELINE = "baseline.json"
LOG_FILE = os.path.join("logs", "security.log")
DEFAULT_FOLDER = "test_files"


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def scan_folder(folder):
    result = {}
    for root, _, files in os.walk(folder):
        for name in files:
            path = os.path.join(root, name)
            result[os.path.relpath(path, folder)] = sha256_file(path)
    return result


def log_event(message):
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"{datetime.now():%Y-%m-%d %H:%M:%S} | {message}\n")


def create_baseline():
    data = scan_folder(DEFAULT_FOLDER)
    with open(BASELINE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)
    print(f"\nBaseline created. {len(data)} files recorded.")
    log_event(f"BASELINE_CREATED | {len(data)} files")


def check_integrity():
    if not os.path.exists(BASELINE):
        print("\nNo baseline found. Create one first.")
        return

    with open(BASELINE, "r", encoding="utf-8") as f:
        old = json.load(f)

    current = scan_folder(DEFAULT_FOLDER)
    old_files = set(old)
    current_files = set(current)

    print("\n--- Integrity Check ---")
    changes = 0

    for name in sorted(current_files - old_files):
        print(f"[NEW]      {name}")
        log_event(f"NEW_FILE | {name}")
        changes += 1

    for name in sorted(old_files - current_files):
        print(f"[DELETED]  {name}")
        log_event(f"DELETED_FILE | {name}")
        changes += 1

    for name in sorted(old_files & current_files):
        if old[name] != current[name]:
            print(f"[MODIFIED] {name}")
            log_event(f"MODIFIED_FILE | {name}")
            changes += 1
        else:
            print(f"[SAFE]     {name}")

    if changes == 0:
        print("\nNo changes detected.")
    else:
        print(f"\nWarning: {changes} change(s) detected.")


def view_logs():
    if not os.path.exists(LOG_FILE):
        print("\nNo logs yet.")
        return
    print("\n--- Security Log ---")
    with open(LOG_FILE, "r", encoding="utf-8") as f:
        content = f.read().strip()
    print(content or "No logs yet.")


def main():
    os.makedirs(DEFAULT_FOLDER, exist_ok=True)
    print("=" * 50)
    print("       FILE INTEGRITY MONITOR")
    print("=" * 50)
    print(f"Monitoring folder: {DEFAULT_FOLDER}/")

    while True:
        print("\n1. Create / Update Baseline")
        print("2. Check File Integrity")
        print("3. View Security Logs")
        print("4. Exit")

        choice = input("\nEnter choice: ").strip()

        if choice == "1":
            create_baseline()
        elif choice == "2":
            check_integrity()
        elif choice == "3":
            view_logs()
        elif choice == "4":
            print("Exiting...")
            break
        else:
            print("Invalid choice. Enter 1-4.")


if __name__ == "__main__":
    main()
