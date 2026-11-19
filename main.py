import os
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from backend.app.config import CORS_ORIGINS
from backend.app.database import engine, Base
from backend.app.api.dataset import router as dataset_router
from backend.app.api.incidents import router as incidents_router
from backend.app.api.ml import router as ml_router
from backend.app.services.ml_service import load_model_pipeline

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# Ensure tables are created immediately
Base.metadata.create_all(bind=engine)

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Ensure database tables exist and load ML model on server startup."""
    Base.metadata.create_all(bind=engine)
    load_model_pipeline()
    yield


app = FastAPI(
    title="VeriTrace — Cyber Incident Response API",
    description=(
        "Backend REST API for VeriTrace with official UNSW-NB15 cybersecurity dataset integration, "
        "SQLite persistent storage, NIST SP 800-61 incident workflows, and tamper-evident SHA-256 evidence logging."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

# Enable CORS for communication with the frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API Routers
app.include_router(dataset_router)
app.include_router(incidents_router)
app.include_router(ml_router)


@app.get("/", tags=["Health Check"])
def root():
    """Health check endpoint to verify backend status."""
    return {
        "status": "online",
        "service": "VeriTrace Cyber Incident Response Backend",
        "frontend_app": "/app",
        "documentation": "/docs",
        "endpoints": [
            "/api/dataset/stats",
            "/api/dataset/records",
            "/api/dataset/categories",
            "/api/incidents",
            "/api/ml/status",
            "/api/ml/predict",
            "/api/ml/metrics",
        ],
    }


@app.get("/app", include_in_schema=False)
def serve_frontend():
    """Serve the complete VeriTrace frontend application."""
    index_file = os.path.join(ROOT_DIR, "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file)
    return JSONResponse(status_code=404, content={"error": "index.html not found"})


@app.get("/favicon.svg", include_in_schema=False)
def serve_favicon():
    fav_file = os.path.join(ROOT_DIR, "favicon.svg")
    if os.path.exists(fav_file):
        return FileResponse(fav_file, media_type="image/svg+xml")
    return JSONResponse(status_code=404, content={"error": "favicon.svg not found"})


@app.get("/og-image.png", include_in_schema=False)
def serve_og():
    og_file = os.path.join(ROOT_DIR, "og-image.png")
    if os.path.exists(og_file):
        return FileResponse(og_file, media_type="image/png")
    return JSONResponse(status_code=404, content={"error": "og-image.png not found"})


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Provide clean JSON error response on unexpected exceptions."""
    return JSONResponse(
        status_code=500,
        content={"error": "Internal Server Error", "detail": str(exc)},
    )
