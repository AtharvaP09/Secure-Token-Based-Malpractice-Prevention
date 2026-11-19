#!/usr/bin/env bash
# ============================================================
#  setup_ubuntu.sh — One-shot Ubuntu setup for Secure Exam Monitor
#  Run from the project root:  bash setup_ubuntu.sh
# ============================================================
set -e

echo "============================================"
echo "  Secure Exam Monitor — Ubuntu Setup"
echo "============================================"
echo ""

# ── 1. System packages ────────────────────────────────────────────────────────
echo "[1/5] Installing system packages..."
sudo apt update -qq
sudo apt install -y \
    python3 python3-pip python3-venv \
    nodejs npm \
    xdotool \
    usbutils \
    pkg-config

echo "      Done."

# ── 2. Python virtual environment ─────────────────────────────────────────────
echo "[2/5] Creating Python virtual environment..."
python3 -m venv venv
source venv/bin/activate
echo "      Done."

# ── 3. Python dependencies ────────────────────────────────────────────────────
echo "[3/5] Installing Python dependencies..."
pip install --quiet --upgrade pip
pip install --quiet \
    fastapi uvicorn sqlalchemy pydantic \
    python-multipart "python-jose[cryptography]" \
    "passlib[bcrypt]" websockets dnspython \
    requests psutil cryptography pyinstaller \
    "keyboard==0.13.5" pyudev python-xlib evdev
echo "      Done."

# ── 4. Frontend dependencies ──────────────────────────────────────────────────
echo "[4/5] Installing frontend (npm) dependencies..."
cd frontend
npm install --silent
cd ..
echo "      Done."

# ── 5. Input group for keyboard hooks (no-root keyboard monitoring) ───────────
echo "[5/5] Adding $USER to 'input' group for keyboard monitoring..."
sudo usermod -aG input "$USER"
echo "      Done. ** You must log out and log back in for this to take effect. **"

echo ""
echo "============================================"
echo "  Setup complete!"
echo ""
echo "  To start the project:"
echo ""
echo "  Terminal 1 — Backend:"
echo "    source venv/bin/activate"
echo "    uvicorn backend.main:app --reload"
echo ""
echo "  Terminal 2 — Frontend:"
echo "    cd frontend && npm run dev"
echo ""
echo "  To build the Linux monitor binary:"
echo "    source venv/bin/activate"
echo "    python scripts/build_token.py"
echo "    # Binary will be at: dist/monitor"
echo ""
echo "  NOTE: If window-title tracking doesn't work,"
echo "  make sure you are using an X11 (Xorg) session,"
echo "  not Wayland. At the Ubuntu login screen, click"
echo "  the gear icon and choose 'Ubuntu on Xorg'."
echo "============================================"

