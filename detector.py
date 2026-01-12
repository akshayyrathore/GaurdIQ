import os
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.utils.validation import check_is_fitted
from backend.models.sql import AccessLog


class AnomalyDetector:
    def __init__(
        self,
        model_path: str = "anomaly_model.pkl",
        contamination: float = 0.01,
        random_state: int = 42,
    ):
        self.model_path = model_path
        self.model = None
        self.contamination = contamination
        self.random_state = random_state
        self._load_or_init_model()

    # ---------------------------------------------------------
    # Model lifecycle
    # ---------------------------------------------------------
    def _load_or_init_model(self):
        if os.path.exists(self.model_path):
            try:
                self.model = joblib.load(self.model_path)
                return
            except Exception:
                pass

        # Fresh model
        self.model = IsolationForest(
            n_estimators=200,
            contamination=self.contamination,
            random_state=self.random_state,
            n_jobs=-1,
        )

    def save(self):
        joblib.dump(self.model, self.model_path)

    # ---------------------------------------------------------
    # Training
    # ---------------------------------------------------------
    def train(self, logs: list[AccessLog]) -> None:
        if not logs:
            return

        df = self._logs_to_df(logs)
        X = self._extract_features(df)

        if len(X) < 10:
            # Too little data → IsolationForest becomes unstable
            return

        self.model.fit(X)
        self.save()

    # ---------------------------------------------------------
    # Prediction
    # ---------------------------------------------------------
    def predict(self, log: AccessLog) -> float:
        """
        Returns anomaly score in range [0, 1]
        0   → very normal
        1   → highly anomalous
        """
        if self.model is None:
            return 0.0

        try:
            check_is_fitted(self.model)
        except Exception:
            return 0.0

        df = self._logs_to_df([log])
        X = self._extract_features(df)

        # IsolationForest:
        # decision_function → higher = normal
        raw_score = self.model.decision_function(X)[0]

        # Convert to intuitive anomaly score
        # Typical range ~[-0.5, 0.5]
        anomaly_score = float(np.clip(-raw_score, 0, 1))
        return anomaly_score

    # ---------------------------------------------------------
    # Feature Engineering
    # ---------------------------------------------------------
    def _logs_to_df(self, logs: list[AccessLog]) -> pd.DataFrame:
        return pd.DataFrame([log.dict() for log in logs])

    def _extract_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Minimal but meaningful features for access-log anomaly detection
        """
        features = pd.DataFrame()

        # Numeric
        features["payload_size"] = df.get("payload_size", 0)

        # Request behavior
        features["endpoint_len"] = df.get("endpoint", "").astype(str).apply(len)
        features["method"] = df.get("method", "").astype(str)

        # Status behavior (404 storms, 500 spikes)
        features["status_code"] = df.get("status_code", 0)

        # Time-based (if exists)
        if "timestamp" in df.columns:
            ts = pd.to_datetime(df["timestamp"], errors="coerce")
            features["hour"] = ts.dt.hour.fillna(0)
            features["minute"] = ts.dt.minute.fillna(0)
        else:
            features["hour"] = 0
            features["minute"] = 0

        # Encode categorical safely
        features["method"] = features["method"].map({
            "GET": 0,
            "POST": 1,
            "PUT": 2,
            "DELETE": 3,
        }).fillna(4)

        return features.fillna(0)


# ---------------------------------------------------------
# Singleton / Dependency
# ---------------------------------------------------------
detector = AnomalyDetector()
