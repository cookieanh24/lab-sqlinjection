"""
init_db.py  -  Khoi tao CSDL SQLite cho SQLi Lab

Tao file lab.db voi du lieu mau. Chay lai se xoa va tao moi.
    python3 init_db.py
"""
import os
import sqlite3

DB_PATH = os.path.join(os.path.dirname(__file__), "lab.db")


def init():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)

    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()

    # --- Bang users: muc tieu cua auth-bypass va UNION dump ---
    cur.executescript(
        """
        CREATE TABLE users (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            username    TEXT NOT NULL,
            password    TEXT NOT NULL,          -- luu plaintext co y de minh hoa
            role        TEXT NOT NULL DEFAULT 'user',
            email       TEXT,
            credit_card TEXT                     -- du lieu "nhay cam" de minh hoa impact
        );

        CREATE TABLE products (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT NOT NULL,
            category    TEXT,
            price       REAL,
            description TEXT
        );

        -- Bang feedback: dung cho stacked-query va second-order
        CREATE TABLE feedback (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            message  TEXT
        );

        -- Bang "bi mat": muc tieu cuoi cung (CTF flag) de luyen UNION/blind
        CREATE TABLE admin_secrets (
            id   INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            flag TEXT
        );
        """
    )

    cur.executemany(
        "INSERT INTO users (username, password, role, email, credit_card) VALUES (?,?,?,?,?)",
        [
            ("admin",  "S3cr3t_Admin_2024!", "admin", "admin@sqli.lab",  "4111-1111-1111-1111"),
            ("alice",  "alicepass",          "user",  "alice@sqli.lab",  "5500-0000-0000-0004"),
            ("bob",    "bobpass123",         "user",  "bob@sqli.lab",    "3400-0000-0000-009"),
            ("carol",  "carol!2024",         "user",  "carol@sqli.lab",  "6011-0000-0000-0004"),
        ],
    )

    cur.executemany(
        "INSERT INTO products (name, category, price, description) VALUES (?,?,?,?)",
        [
            ("USB Rubber Ducky", "hardware", 59.99,  "Keystroke injection tool"),
            ("WiFi Pineapple",   "hardware", 199.99, "Rogue AP / MITM platform"),
            ("Burp Suite Pro",   "software", 449.00, "Web proxy & scanner"),
            ("Kali Linux Mug",   "merch",    12.50,  "Ceramic mug, 350ml"),
            ("Faraday Pouch",    "merch",    24.00,  "RF-blocking signal pouch"),
        ],
    )

    cur.execute(
        "INSERT INTO admin_secrets (name, flag) VALUES (?, ?)",
        ("master_flag", "FLAG{m4nu4l_sql1_m4st3r}"),
    )

    con.commit()
    con.close()
    print(f"[+] Da tao CSDL: {DB_PATH}")
    print("[+] Tai khoan: admin / S3cr3t_Admin_2024!  (va alice, bob, carol)")
    print("[+] Flag muc tieu nam trong bang admin_secrets.")


if __name__ == "__main__":
    init()
