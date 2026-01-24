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

        self.model = IsolationForest(
            n_estimators=300,
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

        if len(X) < 20:
            # IsolationForest needs reasonable volume
            return

        self.model.fit(X)
        self.save()
