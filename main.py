"""
PhishShield AI 2.0 - FastAPI Application Entry Point
High-performance ASGI application with async scanning, SSRF protection,
and multi-tier ML/LLM verdict engine.
"""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from pathlib import Path

from config import settings
from middleware.ssrf_guard import SSRFGuard
from api.async_routes import router as api_router
from models.inference import model_manager


# Configure structured logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] [%(levelname)s] [%(name)s]: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger('phishshield')


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan: startup and shutdown hooks."""
    # ---- Startup ----
    logger.info("PhishShield AI 2.0 starting up...")
    logger.info(f"ML Model loaded: XGBoost={model_manager.xgb_model is not None}, "
                f"Scaler={model_manager.scaler is not None}")
    logger.info(f"SSRF Protection: {'ENABLED' if settings.SSRF_BLOCK_PRIVATE else 'DISABLED'}")
    logger.info(f"Groq LLM: {'CONFIGURED' if settings.GROQ_API_KEY else 'NOT CONFIGURED'}")
    logger.info(f"Server ready on port {settings.SERVER_PORT}")

    yield

    # ---- Shutdown ----
    logger.info("PhishShield AI 2.0 shutting down...")
    from core.async_scanner import cleanup
    await cleanup()
    logger.info("Async HTTP client closed. Goodbye.")


# Resolve frontend assets relative to this file so startup is independent of cwd.
BASE_DIR = Path(__file__).resolve().parent

# Initialize FastAPI application
app = FastAPI(
    title="PhishShield AI 2.0",
    lifespan=lifespan,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

# ---- Middleware Stack (order matters: last added = first executed) ----

# 1. CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 2. SSRF Guard (validates target URLs before they reach scan handlers)
if settings.SSRF_BLOCK_PRIVATE:
    app.add_middleware(SSRFGuard)

# ---- API Routes ----
app.include_router(api_router)

# ---- Static Files & Templates ----
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
templates = Jinja2Templates(directory=BASE_DIR / "templates")

# Support Flask-style url_for('static', filename='...') in Jinja2 templates
def custom_url_for(name: str, **path_params) -> str:
    if name == 'static' and 'filename' in path_params and 'path' not in path_params:
        path_params['path'] = path_params.pop('filename')
    return app.url_path_for(name, **path_params)

templates.env.globals['url_for'] = custom_url_for


# ---- Dashboard Route ----

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    """Renders main dashboard interface."""
    return templates.TemplateResponse(request=request, name="index.html")


@app.get("/favicon.ico")
async def favicon():
    """Prevents HTTP 500 noise on browser favicon requests."""
    return JSONResponse(content={}, status_code=204)


# ---- Global Exception Handler ----

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Global exception handler — returns clean JSON errors without exposing stack traces."""
    logger.error(f"Unhandled Exception on {request.method} {request.url.path}: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            'success': False,
            'error': 'An internal server error occurred.'
        }
    )


# ---- Legacy Flask Compatibility Route (optional) ----
# The old Flask app.py is preserved but no longer the primary entry point.
# To start the server: uvicorn main:app --host 0.0.0.0 --port 8000


if __name__ == '__main__':
    import uvicorn

    print("\n=======================================================")
    print("   PhishShield AI 2.0 - Real-Time Threat Intelligence Platform")
    print(f"   FastAPI + Uvicorn ASGI Server")
    print(f"   Dashboard: http://127.0.0.1:{settings.SERVER_PORT}")
    print("=======================================================\n")

    uvicorn.run(
        "main:app",
        host=settings.SERVER_HOST,
        port=settings.SERVER_PORT,
        reload=settings.DEBUG_MODE,
        log_level="info",
    )
