# SPDX-License-Identifier: Apache-2.0
"""签发一枚用方 Key：明文只打印这一次，库里只存 sha256。"""
import hashlib, secrets, sys

from app import db


def main(user_id: str):
    raw = "djb_" + secrets.token_urlsafe(32)
    h = hashlib.sha256(raw.encode()).hexdigest()
    with db.conn() as c, c.cursor() as cur:
        cur.execute("INSERT INTO api_keys (user_id, key_prefix, key_hash) VALUES (%s,%s,%s)", (user_id, raw[:8], h))
    print(raw)  # 仅此一次
    print(f"# user_id={user_id} prefix={raw[:8]}", file=sys.stderr)


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "user:demo-001")
