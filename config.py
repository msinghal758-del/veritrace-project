import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "veritrace.db")
DATASETS_DIR = os.path.join(BASE_DIR, "datasets")

DATABASE_URL = f"sqlite:///{DB_PATH}"

# CORS Origins (allow local frontend to communicate seamlessly)
CORS_ORIGINS = [
    "http://localhost",
    "http://localhost:3000",
    "http://localhost:5000",
    "http://localhost:8000",
    "http://localhost:5500",
    "http://127.0.0.1",
    "http://127.0.0.1:3000",
    "http://127.0.0.1:5500",
    "http://127.0.0.1:8000",
    "*",  # Allow local file:// access
]
