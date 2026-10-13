"""
===========================================================================
 OOB COLLECTOR  -  "server cua attacker" cho Out-of-Band SQLi (DBS401)
===========================================================================
 Mo phong Burp Collaborator / interactsh / mot DNS-HTTP server ma attacker
 kiem soat. Khi CSDL nan nhan bi ep goi ra ngoai (qua ham dns_lookup trong
 app.py), du lieu danh cap se "hien hinh" tai day — KHONG nam trong HTTP
 response cua ung dung nan nhan. Day chinh la ban chat cua OOB.

 Chay (mot cua so terminal rieng):
   python3 oob_collector.py          # lang nghe tai http://127.0.0.1:5001
 Xem du lieu bat duoc:
   http://127.0.0.1:5001/log
===========================================================================
"""
import binascii
import datetime

from flask import Flask, request

app = Flask(__name__)
HITS = []  # luu lai cac callback nhan duoc


def try_hex_decode(label):
    """Payload OOB thuong hex-encode du lieu de an toan tren DNS. Thu giai ma."""
    try:
        return binascii.unhexlify(label).decode("utf-8", "replace")
    except Exception:
        return None


@app.route("/dns")
def dns():
    """Nhan "truy van DNS" tu CSDL nan nhan. host = <du-lieu>.exfil.attacker.lab"""
    host = request.args.get("host", "")
    ts = datetime.datetime.now().strftime("%H:%M:%S")
    first_label = host.split(".")[0] if host else ""
    decoded = try_hex_decode(first_label)
    HITS.append({"ts": ts, "host": host, "label": first_label, "decoded": decoded})
    print(f"[OOB {ts}] callback nhan duoc: host={host}"
          + (f"  -> giai ma hex: {decoded!r}" if decoded else ""))
    return "", 200


@app.route("/log")
def log():
    rows = "".join(
        f"<tr><td>{h['ts']}</td><td><code>{h['host']}</code></td>"
        f"<td><code>{h['label']}</code></td>"
        f"<td><b>{h['decoded'] if h['decoded'] is not None else '(khong phai hex)'}</b></td></tr>"
        for h in reversed(HITS)
    )
    return f"""<!doctype html><html lang="vi"><meta charset="utf-8">
    <title>OOB Collector - attacker</title>
    <style>body{{font-family:system-ui;max-width:900px;margin:0 auto;padding:16px}}
    table{{border-collapse:collapse;width:100%}} th,td{{border:1px solid #8885;padding:6px}}
    .b{{background:#c0392b22;border:1px solid #c0392b;padding:8px;border-radius:6px}}</style>
    <div class="b">🎯 <b>OOB Collector (server cua attacker)</b> — du lieu danh cap xuat hien o day,
    khong nam trong response cua app nan nhan.</div>
    <h2>Callback da bat duoc ({len(HITS)})</h2>
    <table><tr><th>Thoi gian</th><th>Host nhan duoc</th><th>Label dau</th><th>Giai ma</th></tr>
    {rows or '<tr><td colspan=4>Chua co du lieu. Hay trigger OOB tu /lookup.</td></tr>'}</table>
    <p><a href="/log">Lam moi</a></p></html>"""


@app.route("/")
def index():
    return '<p>OOB collector dang chay. Xem <a href="/log">/log</a>.</p>'


if __name__ == "__main__":
    print("[*] OOB collector lang nghe tai http://127.0.0.1:5001  (xem /log)")
    app.run(host="127.0.0.1", port=5001, debug=False)
