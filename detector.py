import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from backend.models.sql import AccessLog
import joblib
import os

class AnomalyDetector:
    def __init__(self, model_path="model.pkl"):
        self.model_path = model_path
        self.model = None
        self.encoder = None # For categorical features if needed
        self._load_model()

    def _load_model(self):
        if os.path.exists(self.model_path):
            try:
                self.model = joblib.load(self.model_path)
            except:
                self.model = None
        else:
            # Initialize a new model
            self.model = IsolationForest(n_estimators=100, contamination=0.01, random_state=42)

    def train(self, logs: list[AccessLog]):
        # feature extraction
        df = pd.DataFrame([l.dict() for l in logs])
        # Simple feature: payload_size, status_code (maybe not status code for anomaly detection unless 404 storm)
        # For demo, let's stick to numerical features or length of strings
        features = self._extract_features(df)
        self.model.fit(features)
        joblib.dump(self.model, self.model_path)

    def predict(self, log: AccessLog) -> float:
        if not self.model:
            return 0.0 # No model, no anomaly
        
        # Check if fitted
        from sklearn.utils.validation import check_is_fitted
        try:
            check_is_fitted(self.model)
        except:
            return 0.0

        features = self._extract_features(pd.DataFrame([log.dict()]))
        score = self.model.decision_function(features)[0] 
        # Score is negative for anomalies, positive for normal
        # We want "Anomaly Score" where higher is more anomalous?
        # Isolation forest: lower is more anomalous. 
        return score

    def _extract_features(self, df: pd.DataFrame):
        # Very simple feature engineering for demo
        data = pd.DataFrame()
        data['payload_size'] = df['payload_size']
        # data['url_len'] = df['endpoint'].apply(len)
        # data['status'] = df['status_code']
        return data.fillna(0)

# Singleton or dependency
detector = AnomalyDetector()
