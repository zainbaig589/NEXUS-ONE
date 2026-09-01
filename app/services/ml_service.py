"""ML anomaly detection service layer."""

from datetime import datetime
from typing import Dict, Any

from app.ml import AnomalyDetector

_detector: AnomalyDetector = None


def _get_detector() -> AnomalyDetector:
    global _detector
    if _detector is None:
        _detector = AnomalyDetector()
    return _detector


class MLService:
    @staticmethod
    def train() -> Dict[str, Any]:
        detector = _get_detector()
        samples = detector.train_on_synthetic()
        return {
            "status": "success",
            "samples_trained": samples,
            "model_path": detector.model_path,
            "message": f"Model trained on {samples} synthetic samples",
        }

    @staticmethod
    def analyze(
        source: str,
        event_type: str,
        severity: str,
        payload: Dict[str, Any],
        timestamp: datetime = None,
    ) -> Dict[str, Any]:
        detector = _get_detector()
        return detector.analyze(source, event_type, severity, payload, timestamp)

    @staticmethod
    def status() -> Dict[str, Any]:
        return _get_detector().status()
