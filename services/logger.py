"""
PhishShield AI - Structured Logger Service
Provides application logging to console and log files.
"""

import logging


def setup_logger(name: str = 'phishshield') -> logging.Logger:
    """Configures and returns a structured logger."""
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)

    # Configure stdout without creating project files during import/startup.
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter(
            '[%(asctime)s] [%(levelname)s] [%(name)s]: %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        ))
        logger.addHandler(handler)
    return logger


logger = setup_logger()
