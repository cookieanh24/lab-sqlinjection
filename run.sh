#!/usr/bin/env bash
# Khoi chay SQLi Lab. Chi chay tren localhost.
set -e
cd "$(dirname "$0")"

if [ ! -d ".venv" ]; then
  echo "[*] Tao virtualenv..."
  python3 -m venv .venv
fi
# shellcheck disable=SC1091
source .venv/bin/activate
pip install -q -r requirements.txt

if [ ! -f "lab.db" ]; then
  echo "[*] Khoi tao CSDL..."
  python3 init_db.py
fi

# Khoi dong "server cua attacker" (OOB collector) o nen cho bai OOB.
echo "[*] Khoi dong OOB collector tai http://127.0.0.1:5001  (log: /log)"
python3 oob_collector.py &
COLLECTOR_PID=$!
trap 'kill $COLLECTOR_PID 2>/dev/null' EXIT

echo "[*] Mo app nan nhan tai http://127.0.0.1:5000"
python3 app.py
