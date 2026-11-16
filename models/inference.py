"""
PhishShield AI 2.0 - High-Performance Singleton Inference Engine
Loads serialized XGBoost model once into memory for thread-safe inference.
"""

import os
import json
import threading
import joblib
import logging
from typing import List, Tuple

from config import XGB_MODEL_PATH, SCALER_PATH, METADATA_PATH

logger = logging.getLogger('phishshield.inference')


class ModelManager:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super(ModelManager, cls).__new__(cls)
                    cls._instance.xgb_model = None
                    cls._instance.scaler = None
                    cls._instance.metadata = {}
                    cls._instance._predict_lock = threading.Lock()
                    cls._instance._loaded = False
                    cls._instance.load_models()
        return cls._instance

    def load_models(self):
        """Loads serialized XGBoost Classifier, StandardScaler, and metadata."""
        if self._loaded:
            return

        try:
            if os.path.exists(XGB_MODEL_PATH):
                self.xgb_model = joblib.load(XGB_MODEL_PATH)
                logger.info("Loaded XGBoost Classifier artifact successfully.")

            if os.path.exists(SCALER_PATH):
                self.scaler = joblib.load(SCALER_PATH)
                logger.info("Loaded StandardScaler artifact successfully.")

            if os.path.exists(METADATA_PATH):
                with open(METADATA_PATH, 'r') as f:
                    self.metadata = json.load(f)
                logger.info("Loaded model performance metadata successfully.")

            self._loaded = True
        except Exception as e:
            logger.exception("Failed to load model artifacts")
            self.xgb_model = None
            self.scaler = None
            self.metadata = {}

    def predict(self, feature_vector: list) -> Tuple[float, float, float]:
        """
        Executes thread-safe XGBoost model inference on a normalized feature vector.
        Returns: (xgb_prob, xgb_prob, xgb_prob)
        """
        if self.scaler is None or self.xgb_model is None:
            # Degraded but usable fallback: callers still apply lexical heuristics.
            return 0.5, 0.5, 0.5

        with self._predict_lock:
            scaled_vec = self.scaler.transform([feature_vector])
            prob = float(self.xgb_model.predict_proba(scaled_vec)[0][1])

        return prob, prob, prob

    def predict_batch(self, feature_vectors: List[list]) -> List[Tuple[float, float, float]]:
        """
        Batch inference for multiple feature vectors.
        """
        if self.scaler is None or self.xgb_model is None:
            return [(0.5, 0.5, 0.5) for _ in feature_vectors]

        with self._predict_lock:
            scaled_vecs = self.scaler.transform(feature_vectors)
            probs = self.xgb_model.predict_proba(scaled_vecs)[:, 1]

        return [
            (float(probs[i]), float(probs[i]), float(probs[i]))
            for i in range(len(feature_vectors))
        ]


# Single global ModelManager instance
model_manager = ModelManager()
