"""Admin commands.   python manage.py init | reset-password <user> | audit [n]"""
import secrets
import sys

import app as A
from werkzeug.security import generate_password_hash


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "init":
        A.init_db()
        print("Database ready. New counselor accounts (write the passwords down, shown once):")
        A.seed()
    elif cmd == "reset-password" and len(sys.argv) > 2:
        db, pw = A.connect(), secrets.token_urlsafe(9)
        cur = db.execute("UPDATE counselors SET pw_hash=?, failed=0, locked_until=0 WHERE username=?",
                         (generate_password_hash(pw), sys.argv[2]))
        print(f"New password for {sys.argv[2]}: {pw}" if cur.rowcount else "No such user.")
    elif cmd == "audit":
        n = int(sys.argv[2]) if len(sys.argv) > 2 else 30
        for r in A.connect().execute("SELECT * FROM audit ORDER BY id DESC LIMIT ?", (n,)):
            print(r["ts"], r["actor"], r["action"], r["detail"])
    elif cmd == "users":
        db = A.connect()
    rows = db.execute(
        "SELECT username FROM counselors ORDER BY username"
    ).fetchall()

    print("\n=== COUNSELOR ACCOUNTS ===")
    for r in rows:
        print("Username:", r["username"])
    else:
        print(__doc__)


if __name__ == "__main__":
    main()
