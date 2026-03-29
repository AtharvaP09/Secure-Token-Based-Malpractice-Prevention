# Secure Exam Monitor

This project consists of a FastAPI backend and a React (Vite) frontend.

## Prerequisites

- Python 3.8+
- Node.js & npm

## Backend

1.  Navigate to the root directory.
2.  Create a virtual environment (optional but recommended):
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows: venv\Scripts\activate
    ```
3.  Install dependencies:
    ```bash
    pip install -r requirements.txt
    ```
4.  Run the backend server:
    ```bash
    uvicorn backend.main:app --reload
    ```
    The API will be available at `http://localhost:8000`.

## Frontend

1.  Navigate to the `frontend` directory:
    ```bash
    cd frontend
    ```
2.  Install dependencies:
    ```bash
    npm install
    ```
3.  Run the development server:
    ```bash
    npm run dev
    ```
    The app will be available at `http://localhost:5173`.

## Architecture
- **Backend**: FastAPI, SQLAlchemy, SQLite (exam_monitor.db)
- **Frontend**: React, Vite, TailwindCSS
