"""ML-based anomaly detection using Isolation Forest."""

import os
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional, Tuple

import numpy as np

logger = logging.getLogger(__name__)

_MODELS_DIR = Path(__file__).parent.parent.parent / "models"
_DEFAULT_MODEL_PATH = str(_MODELS_DIR / "anomaly_detector.joblib")

ANOMALY_THRESHOLD = -0.1
SEVERITY_THRESHOLDS = [
    (0.8, "critical"),
    (0.6, "high"),
    (0.4, "medium"),
    (0.2, "low"),
    (0.0, "info"),
]


class AnomalyDetector:
    """Detects anomalous security events using Isolation Forest."""

    def __init__(self, model_path: Optional[str] = None):
        self.model_path = model_path or _DEFAULT_MODEL_PATH
        self.model = None
        self._training_samples: Optional[int] = None
        self._score_min: float = -0.8
        self._score_max: float = -0.3

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _ensure_models_dir(self):
        Path(self.model_path).parent.mkdir(parents=True, exist_ok=True)

    @property
    def _meta_path(self) -> str:
        p = Path(self.model_path)
        return str(p.parent / (p.stem + "_meta.json"))

    def save(self):
        import joblib
        self._ensure_models_dir()
        joblib.dump(self.model, self.model_path)
        meta = {
            "training_samples": self._training_samples,
            "threshold": ANOMALY_THRESHOLD,
            "score_min": self._score_min,
            "score_max": self._score_max,
        }
        with open(self._meta_path, "w") as f:
            json.dump(meta, f)
        logger.info("Model saved to %s", self.model_path)

    def load_model(self):
        import joblib
        if not os.path.exists(self.model_path):
            raise FileNotFoundError(f"Model not found at {self.model_path}")
        self.model = joblib.load(self.model_path)
        if os.path.exists(self._meta_path):
            with open(self._meta_path) as f:
                meta = json.load(f)
            self._training_samples = meta.get("training_samples")
            self._score_min = float(meta.get("score_min", -0.8))
            self._score_max = float(meta.get("score_max", -0.3))
        logger.info("Model loaded from %s", self.model_path)

    @property
    def is_loaded(self) -> bool:
        return self.model is not None

    # ------------------------------------------------------------------
    # Training
    # ------------------------------------------------------------------

    def train(self, X: np.ndarray):
        from sklearn.ensemble import IsolationForest
        self.model = IsolationForest(
            n_estimators=100,
            contamination=0.12,
            random_state=42,
            n_jobs=-1,
        )
        self.model.fit(X)
        self._training_samples = len(X)
        # Record training score range for normalisation
        train_scores = self.model.score_samples(X)
        self._score_min = float(train_scores.min())
        self._score_max = float(train_scores.max())
        self.save()
        logger.info("Trained on %d samples", self._training_samples)

    def train_on_synthetic(self) -> int:
        from app.ml.dataset import build_training_data
        X, _ = build_training_data()
        self.train(X)
        return self._training_samples

    # ------------------------------------------------------------------
    # Inference
    # ------------------------------------------------------------------

    def _load_if_needed(self):
        if not self.is_loaded:
            self.load_model()

    def predict(self, features: np.ndarray) -> Tuple[float, bool]:
        """Return (anomaly_score 0-1, is_anomaly).

        anomaly_score is calibrated against training data range: 0=most normal, 1=most anomalous.
        is_anomaly is true when score > 0.5 (above training midpoint).
        """
        self._load_if_needed()
        vec = features.reshape(1, -1)
        raw_score = float(self.model.score_samples(vec)[0])
        # Normalise: raw_score range [score_min, score_max], lower = more anomalous
        score_range = self._score_max - self._score_min
        if score_range < 1e-6:
            normalised = 0.5
        else:
            normalised = float(np.clip(
                (self._score_max - raw_score) / score_range,
                0.0, 1.0,
            ))
        is_anomaly = normalised > 0.5
        return normalised, is_anomaly

    def analyze(
        self,
        source: str,
        event_type: str,
        severity: str,
        payload: Dict[str, Any],
        timestamp: datetime = None,
    ) -> Dict[str, Any]:
        """Full analysis of one event; returns structured result dict."""
        from app.ml.features import extract_features, FEATURE_NAMES

        self._load_if_needed()
        features = extract_features(source, event_type, severity, payload, timestamp)
        score, is_anomaly = self.predict(features)

        ml_severity = _score_to_severity(score)
        reason = _build_reason(score, is_anomaly, event_type, severity, payload, features)

        return {
            "anomaly_score": round(score, 4),
            "is_anomaly": is_anomaly,
            "confidence": round(score if is_anomaly else 1.0 - score, 4),
            "severity": ml_severity,
            "reason": reason,
            "features_used": list(FEATURE_NAMES),
            "detection_method": "isolation_forest",
        }

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------

    def status(self) -> Dict[str, Any]:
        from app.ml.features import FEATURE_NAMES
        return {
            "model_loaded": self.is_loaded,
            "model_path": self.model_path if os.path.exists(self.model_path) else None,
            "training_samples": self._training_samples,
            "features": list(FEATURE_NAMES),
            "threshold": ANOMALY_THRESHOLD,
            "detection_method": "isolation_forest",
        }


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _score_to_severity(score: float) -> str:
    for threshold, sev in SEVERITY_THRESHOLDS:
        if score >= threshold:
            return sev
    return "info"


def _build_reason(
    score: float,
    is_anomaly: bool,
    event_type: str,
    severity: str,
    payload: Dict[str, Any],
    features: np.ndarray,
) -> str:
    if not is_anomaly:
        return f"Event matches normal behaviour patterns (score={score:.2f})"

    parts = []
    failed = int(payload.get("failed_attempts", 0) or 0)
    if failed > 10:
        parts.append(f"high failed-attempt count ({failed})")

    hour = int(features[4])
    if hour < 6 or hour > 22:
        parts.append(f"unusual login hour ({hour:02d}:00)")

    bytes_log = float(features[3])
    if bytes_log > 10:
        mb = round(float(np.expm1(bytes_log)) / 1e6, 1)
        parts.append(f"abnormal data transfer ({mb} MB)")

    if severity in ("high", "critical"):
        parts.append(f"elevated event severity ({severity})")

    if event_type.lower() in ("data_exfiltration", "privilege_escalation", "malware"):
        parts.append(f"high-risk event type ({event_type})")

    if not parts:
        parts.append("statistical outlier vs. baseline")

    return "Anomaly detected: " + "; ".join(parts) + f" (score={score:.2f})"
