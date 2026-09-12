# File Integrity Monitoring System

## Objective
A beginner-friendly cybersecurity project that detects unauthorized file creation, deletion, and modification using SHA-256 cryptographic hashes.

## Requirements
- Python 3.8+
- No external libraries required

## How to Run
1. Open a terminal in this project folder.
2. Run:
   `python main.py`
3. Put files you want to monitor inside `test_files/`.
4. Select option 1 to create the baseline.
5. Modify, add, or delete a file.
6. Select option 2 to detect changes.
7. Select option 3 to view security logs.

## Example
After creating a baseline:
- Edit `test_files/file1.txt` -> MODIFIED
- Add `test_files/new.txt` -> NEW
- Delete a baseline file -> DELETED

## Cybersecurity Concepts
- SHA-256 hashing
- File integrity
- Change detection
- Security logging
- Baseline comparison

## Limitations
This is an educational project. The baseline file itself is not protected from tampering, and monitoring is manual rather than real-time.
