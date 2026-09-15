#!/usr/bin/env python3
"""Manage admin users directly in the database — the rescue path when nobody
can log in (lost MFA device, forgotten password).

Run on the host, inside the container or with OSC_DATA_DIR pointing at the
data directory:

    python3 scripts/manage_users.py list
    python3 scripts/manage_users.py add <user> [--role admin|readonly]
    python3 scripts/manage_users.py set-password <user>
    python3 scripts/manage_users.py set-role <user> admin|readonly
    python3 scripts/manage_users.py reset-mfa <user>
    python3 scripts/manage_users.py enable <user> | disable <user> | delete <user>

Passwords are prompted for (not echoed). Every action is written to the audit log.
"""

import argparse
import getpass
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from app.auth import hash_password
from app.config import env
from app.db import DB_FILENAME, Database, migrate_database_name


def _password() -> str:
    password = getpass.getpass("Password: ")
    if password != getpass.getpass("Repeat: "):
        sys.exit("Passwords do not match.")
    if len(password) < 12:
        sys.exit("At least 12 characters.")
    return password


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--data-dir", default=env("DATA_DIR", "./data"))
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list")
    add = sub.add_parser("add")
    add.add_argument("user")
    add.add_argument("--role", default="admin", choices=Database.ROLES)
    for name in ("set-password", "reset-mfa", "enable", "disable", "delete"):
        sub.add_parser(name).add_argument("user")
    set_role = sub.add_parser("set-role")
    set_role.add_argument("user")
    set_role.add_argument("role", choices=Database.ROLES)
    args = parser.parse_args(argv)

    migrate_database_name(Path(args.data_dir))
    db = Database(Path(args.data_dir) / DB_FILENAME)
    if args.cmd == "list":
        for u in db.list_users():
            mfa = u["totp_confirmed_at"][:10] if u["totp_confirmed_at"] else "no MFA"
            print(f"{u['username']:20s} {u['role']:9s} {mfa:10s} {'disabled' if u['disabled'] else 'active'}")
        return
    if args.cmd == "add":
        db.create_user(args.user, hash_password(_password()), args.role, "cli")
    elif args.cmd == "set-password":
        db.set_password(args.user, hash_password(_password()))
        db.delete_user_sessions(args.user)
    elif args.cmd == "set-role":
        db.set_role(args.user, args.role)
    elif args.cmd == "reset-mfa":
        db.set_totp_secret(args.user, None)
        db.delete_user_sessions(args.user)
    elif args.cmd == "enable":
        db.set_disabled(args.user, False)
    elif args.cmd == "disable":
        db.set_disabled(args.user, True)
    elif args.cmd == "delete":
        db.delete_user(args.user)
    db.add_audit("cli", "-", f"user_{args.cmd.replace('-', '_')}", args.user)
    print(f"{args.cmd} {args.user}: done")


if __name__ == "__main__":
    main()
