#!/usr/bin/env python3
"""Create a password hash for admin_users.yaml (bootstrap and rescue users).

Admin accounts normally live in the database and are managed on /admin/users
or with scripts/manage_users.py. admin_users.yaml is only read for usernames
that are not in the database: it seeds the first start and serves as a rescue
entrance (see admin_users.example.yaml).

Usage:  python3 scripts/hash_password.py
Prompts interactively for a password (not echoed) and prints the hash to paste
into admin_users.yaml:

    users:
      <username>: <hash>
"""

import getpass
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from app.auth import hash_password

if __name__ == "__main__":
    password = getpass.getpass("Password: ")
    confirm = getpass.getpass("Repeat: ")
    if password != confirm:
        sys.exit("Passwords do not match.")
    if len(password) < 8:
        sys.exit("At least 8 characters.")
    print(hash_password(password))
