# Secure Exam Monitor

A token-based exam malpractice prevention system with a FastAPI backend, React frontend, and a cross-platform monitor agent.

**Supported platforms: Windows 10/11 · Ubuntu 20.04+ (X11)**

---

## Prerequisites

| Tool | Version |
|------|---------|
| Python | 3.8+ |
| Node.js & npm | 18+ |
| (Ubuntu only) xdotool | `sudo apt install xdotool` |

---

## Quick Start — Ubuntu

```bash
# 1. Run the one-shot setup script from the project root
bash setup_ubuntu.sh

# 2. Log out and log back in (required for keyboard monitoring without sudo)

# 3. Start the backend
source venv/bin/activate
uvicorn backend.main:app --reload

# 4. Start the frontend (new terminal)
cd frontend && npm run dev
```

> **Wayland note:** Window-title tracking requires an X11 session.  
> At the Ubuntu login screen → click the ⚙ gear → choose **"Ubuntu on Xorg"**.

---

## Quick Start — Windows

```powershell
# 1. Create and activate virtualenv
python -m venv venv
venv\Scripts\activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Backend
uvicorn backend.main:app --reload

# 4. Frontend (new terminal)
cd frontend
npm install
npm run dev
```

---

## Building the Monitor Binary

```bash
# Ubuntu → produces dist/monitor  (ELF binary)
source venv/bin/activate
python scripts/build_token.py

# Windows → produces dist/monitor.exe
venv\Scripts\activate
python scripts\build_token.py
```

---

## URLs

| Service | URL |
|---------|-----|
| Backend API | http://localhost:8000 |
| Frontend | http://localhost:5173 |
| API Docs | http://localhost:8000/docs |

Default admin credentials: **admin / 123456**

---

## Architecture

- **Backend**: FastAPI, SQLAlchemy, SQLite (`exam_monitor.db`)
- **Frontend**: React, Vite, TailwindCSS
- **Monitor**: Python, psutil, pyudev (Linux) / WMI (Windows), python-xlib (Linux) / win32gui (Windows)
