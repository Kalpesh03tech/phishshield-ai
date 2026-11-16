"""
PhishShield AI 2.0 - Central Configuration Module
Defines paths, server configuration, networking timeouts, and model hyperparameters.
Uses pydantic-settings for validated environment loading with .env support.
"""

import os
from typing import Optional
from pydantic_settings import BaseSettings
from pydantic import Field


class PhishShieldSettings(BaseSettings):
    """Validated application settings loaded from environment variables and .env file."""

    # ------------------------------------------------------------------
    # LLM API Configurations (Primary: Groq API)
    # ------------------------------------------------------------------
    GROQ_API_KEY: str = ''
    GROQ_BASE_URL: str = 'https://api.groq.com/openai/v1'
    GROQ_MODEL: str = 'llama-3.3-70b-versatile'

    NVIDIA_NEMOTRON_API_KEY: str = ''
    NVIDIA_NEMOTRON_BASE_URL: str = 'https://integrate.api.nvidia.com/v1'
    NVIDIA_NEMOTRON_MODEL: str = 'nvidia/nemotron-4-340b-instruct'

    OPENROUTER_API_KEY: str = ''
    OPENROUTER_BASE_URL: str = 'https://openrouter.ai/api/v1'
    OPENROUTER_MODEL: str = 'deepseek/deepseek-chat'

    LLM_TIMEOUT: float = 8.0

    # ------------------------------------------------------------------
    # Threat Intelligence API Keys (Optional)
    # ------------------------------------------------------------------
    VIRUSTOTAL_API_KEY: str = ''
    GOOGLE_SAFE_BROWSING_API_KEY: str = ''

    # ------------------------------------------------------------------
    # Network & Scanner Timeouts (Seconds)
    # ------------------------------------------------------------------
    DNS_TIMEOUT: float = 1.5
    SSL_TIMEOUT: float = 1.5
    HTTP_TIMEOUT: float = 2.0
    MAX_BATCH_WORKERS: int = 16
    MAX_BATCH_URLS: int = 500
    SCAN_CONCURRENCY_LIMIT: int = 50

    # ------------------------------------------------------------------
    # Ensemble Model Probability Weights (Total = 1.0)
    # ------------------------------------------------------------------
    ENSEMBLE_WEIGHT_XGB: float = 0.45
    ENSEMBLE_WEIGHT_RF: float = 0.35
    ENSEMBLE_WEIGHT_MLP: float = 0.20

    # ------------------------------------------------------------------
    # Security Boundaries
    # ------------------------------------------------------------------
    QR_MAX_FILE_SIZE_MB: int = 5
    QR_MAX_PIXELS: int = 25_000_000
    SSRF_BLOCK_PRIVATE: bool = True

    # ------------------------------------------------------------------
    # Multi-Tier Verdict Thresholds
    # ------------------------------------------------------------------
    LLM_TRIGGER_LOW: float = 0.4
    LLM_TRIGGER_HIGH: float = 0.7

    # ------------------------------------------------------------------
    # Server Settings
    # ------------------------------------------------------------------
    SERVER_HOST: str = '0.0.0.0'
    SERVER_PORT: int = 8000
    DEBUG_MODE: bool = False

    model_config = {
        'env_file': os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env'),
        'env_file_encoding': 'utf-8',
        'extra': 'ignore',
    }


# Singleton settings instance
settings = PhishShieldSettings()

# ------------------------------------------------------------------
# Project Directory Structure
# ------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

MODELS_DIR = os.path.join(BASE_DIR, 'models')
LOGS_DIR = os.path.join(BASE_DIR, 'logs')
STATIC_DIR = os.path.join(BASE_DIR, 'static')
TEMPLATES_DIR = os.path.join(BASE_DIR, 'templates')
DATA_DIR = os.path.join(BASE_DIR, 'data')

    for path in [MODELS_DIR, DATA_DIR]:
    os.makedirs(path, exist_ok=True)

# ------------------------------------------------------------------
# Serialized ML Model Artifact Paths
# ------------------------------------------------------------------
XGB_MODEL_PATH = os.path.join(MODELS_DIR, 'model_xgb.joblib')
SCALER_PATH = os.path.join(MODELS_DIR, 'scaler.joblib')
METADATA_PATH = os.path.join(MODELS_DIR, 'metadata.json')

# ------------------------------------------------------------------
# Backward-compatible module-level exports
# These allow existing imports like `from config import DNS_TIMEOUT`
# to continue working without changes.
# ------------------------------------------------------------------
GROQ_API_KEY = settings.GROQ_API_KEY
GROQ_BASE_URL = settings.GROQ_BASE_URL
GROQ_MODEL = settings.GROQ_MODEL
NVIDIA_NEMOTRON_API_KEY = settings.NVIDIA_NEMOTRON_API_KEY
NVIDIA_NEMOTRON_BASE_URL = settings.NVIDIA_NEMOTRON_BASE_URL
NVIDIA_NEMOTRON_MODEL = settings.NVIDIA_NEMOTRON_MODEL
OPENROUTER_API_KEY = settings.OPENROUTER_API_KEY
OPENROUTER_BASE_URL = settings.OPENROUTER_BASE_URL
OPENROUTER_MODEL = settings.OPENROUTER_MODEL
LLM_TIMEOUT = settings.LLM_TIMEOUT

VIRUSTOTAL_API_KEY = settings.VIRUSTOTAL_API_KEY
GOOGLE_SAFE_BROWSING_API_KEY = settings.GOOGLE_SAFE_BROWSING_API_KEY

DNS_TIMEOUT = settings.DNS_TIMEOUT
SSL_TIMEOUT = settings.SSL_TIMEOUT
HTTP_TIMEOUT = settings.HTTP_TIMEOUT
MAX_BATCH_WORKERS = settings.MAX_BATCH_WORKERS
MAX_BATCH_URLS = settings.MAX_BATCH_URLS

ENSEMBLE_WEIGHT_XGB = settings.ENSEMBLE_WEIGHT_XGB
ENSEMBLE_WEIGHT_RF = settings.ENSEMBLE_WEIGHT_RF
ENSEMBLE_WEIGHT_MLP = settings.ENSEMBLE_WEIGHT_MLP

SERVER_HOST = settings.SERVER_HOST
SERVER_PORT = settings.SERVER_PORT
DEBUG_MODE = settings.DEBUG_MODE
