#!/bin/bash
# K9x Satan — start dashboard + fake search server

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo ""
echo " ____     _     _____     _     _   _"
echo "/ ___|   / \\   |_   _|   / \\   | \\ | |"
echo "\\___ \\  / _ \\    | |    / _ \\  |  \\| |"
echo " ___) |/ ___ \\   | |   / ___ \\ | |\\  |"
echo "|____//_/   \\_\\  |_|  /_/   \\_\\|_| \\_|"
echo ""
echo "  Security Analysis Tool for Agentic Networks"
echo "  K9-AIF Red Team Harness — k9x.ai"
echo ""

# Shared venv from k9-aif-framework
VENV_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)/k9-aif-framework/.venv"

if [ ! -d "$VENV_DIR" ]; then
  echo "[Satan] ERROR: shared venv not found at $VENV_DIR"
  echo "  Run: cd ../../k9-aif-framework && python3.11 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt"
  exit 1
fi

source "$VENV_DIR/bin/activate"

# Install Satan deps into shared venv if needed
pip install -q fastapi uvicorn requests python-multipart

# Start fake search server in background
echo "[+] Starting fake search server on port 9999..."
python -m k9x_satan.fake_search.server &
FAKE_PID=$!
sleep 1

echo "[+] Satan dashboard → http://localhost:6660"
echo "[+] Target pipeline wired with K9X Shield"
echo ""
python -m uvicorn k9x_satan.app:app --host 0.0.0.0 --port 6660 --reload

kill $FAKE_PID 2>/dev/null
