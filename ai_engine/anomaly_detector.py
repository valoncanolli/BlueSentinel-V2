"""
ai_engine/anomaly_detector.py
ML-based anomaly detection using IsolationForest.
Builds 7-day baseline, auto-retrains after 30 days.
"""
import json
import logging
import pickle
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

log = logging.getLogger(__name__)

CACHE_DIR = Path(__file__).parent.parent / "cache"
MODEL_PATH = CACHE_DIR / "baseline_model.pkl"
BASELINE_DATA_PATH = CACHE_DIR / "baseline_data.json"
RETRAIN_DAYS = 30
MIN_SAMPLES = 50

FEATURES = [
    "hour_of_day",
    "process_count",
    "new_processes",
    "outbound_connections",
    "failed_logins",
    "new_registry_keys",
    "new_scheduled_tasks",
]


class AnomalyDetector:
    """IsolationForest-based anomaly detector for system behavior."""

    def __init__(self) -> None:
        CACHE_DIR.mkdir(exist_ok=True)
        self.model = None
        self.trained_at: Optional[datetime] = None
        self._load_model()

    def _load_model(self) -> None:
        if MODEL_PATH.exists():
            try:
                with open(MODEL_PATH, "rb") as fh:
                    saved = pickle.load(fh)
                self.model = saved["model"]
                self.trained_at = saved["trained_at"]
                age = (datetime.now(timezone.utc) - self.trained_at).days
                if age > RETRAIN_DAYS:
                    log.info(f"Model is {age} days old (>{RETRAIN_DAYS}), will retrain.")
                    self.model = None
            except Exception as exc:
                log.warning(f"Failed to load anomaly model: {exc}")
                self.model = None

    def _save_model(self) -> None:
        try:
            with open(MODEL_PATH, "wb") as fh:
                pickle.dump({"model": self.model, "trained_at": datetime.now(timezone.utc)}, fh)
        except Exception as exc:
            log.error(f"Failed to save anomaly model: {exc}")

    def _load_baseline_data(self) -> List[Dict]:
        if BASELINE_DATA_PATH.exists():
            try:
                with open(BASELINE_DATA_PATH) as fh:
                    return json.load(fh)
            except Exception:
                return []
        return []

    def _save_baseline_data(self, data: List[Dict]) -> None:
        try:
            with open(BASELINE_DATA_PATH, "w") as fh:
                json.dump(data[-10000:], fh)  # keep last 10k samples
        except Exception as exc:
            log.error(f"Failed to save baseline data: {exc}")

    def add_sample(self, sample: Dict[str, Any]) -> None:
        """Record a new behavioral sample for future training."""
        data = self._load_baseline_data()
        sample["recorded_at"] = datetime.now(timezone.utc).isoformat()
        data.append(sample)
        self._save_baseline_data(data)
        # Auto-train if we have enough data and no model
        if len(data) >= MIN_SAMPLES and self.model is None:
            self.train(data)

    def train(self, samples: Optional[List[Dict]] = None) -> bool:
        """Train IsolationForest on historical samples."""
        try:
            from sklearn.ensemble import IsolationForest
        except ImportError:
            log.error("scikit-learn not installed. Cannot train anomaly model.")
            return False

        if samples is None:
            samples = self._load_baseline_data()

        if len(samples) < MIN_SAMPLES:
            log.warning(f"Insufficient samples for training: {len(samples)} < {MIN_SAMPLES}")
            return False

        X = self._extract_features(samples)
        self.model = IsolationForest(
            n_estimators=100,
            contamination=0.05,
            random_state=42,
            n_jobs=-1,
        )
        self.model.fit(X)
        self.trained_at = datetime.now(timezone.utc)
        self._save_model()
        log.info(f"Anomaly model trained on {len(samples)} samples.")
        return True

    def _extract_features(self, samples: List[Dict]) -> np.ndarray:
        rows = []
        for s in samples:
            row = [float(s.get(f, 0)) for f in FEATURES]
            rows.append(row)
        return np.array(rows, dtype=float)

    def detect(self, observation: Dict[str, Any]) -> Tuple[float, bool]:
        """
        Detect if an observation is anomalous.
        Returns (anomaly_score: float 0-1, is_anomaly: bool).
        """
        if self.model is None:
            log.debug("No anomaly model available — recording sample for future training.")
            self.add_sample(observation)
            return 0.0, False

        X = self._extract_features([observation])
        raw_score = self.model.decision_function(X)[0]
        # Normalize: decision_function returns negative for anomalies
        # Map to 0-1 where 1 = highly anomalous
        anomaly_score = float(max(0.0, min(1.0, (-raw_score + 0.5))))
        is_anomaly = bool(self.model.predict(X)[0] == -1)
        self.add_sample(observation)
        return anomaly_score, is_anomaly
