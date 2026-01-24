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
        # ---------------------------------------------------------
    # Prediction
    # ---------------------------------------------------------
    def predict(self, log: AccessLog) -> float:
        """
        Returns anomaly score in range [0, 1]
        0 → normal
        1 → highly anomalous
        """
        if self.model is None:
            return 0.0

        try:
            check_is_fitted(self.model)
        except Exception:
            return 0.0

        df = self._logs_to_df([log])
        X = self._extract_features(df)

        raw_score = self.model.decision_function(X)[0]

        # Normalize → anomaly score
        anomaly_score = float(np.clip(-raw_score, 0, 1))
        return anomaly_score

    # ---------------------------------------------------------
    # Feature Engineering
    # ---------------------------------------------------------
    def _logs_to_df(self, logs: list[AccessLog]) -> pd.DataFrame:
        return pd.DataFrame([log.dict() for log in logs])

    def _extract_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Enhanced feature set for access-log anomaly detection
        """
        features = pd.DataFrame()

        # --------------------
        # Payload behavior
        # --------------------
        payload = df.get("payload_size", 0)
        features["payload_size"] = payload
        features["payload_log"] = np.log1p(payload)

        # --------------------
        # Endpoint behavior
        # --------------------
        endpoint = df.get("endpoint", "").astype(str)
        features["endpoint_len"] = endpoint.apply(len)
        features["endpoint_depth"] = endpoint.apply(lambda x: x.count("/"))
        features["has_query_params"] = endpoint.apply(lambda x: int("?" in x))

        # --------------------
        # HTTP method
        # --------------------
        method_map = {
            "GET": 0,
            "POST": 1,
            "PUT": 2,
            "DELETE": 3,
            "PATCH": 4,
        }
        features["method"] = (
            df.get("method", "")
            .astype(str)
            .map(method_map)
            .fillna(5)
        )

        # --------------------
        # Status behavior
        # --------------------
        status = df.get("status_code", 0)
        features["status_code"] = status
        features["status_class"] = (status // 100).clip(0, 5)

        # --------------------
        # IP behavior
        # --------------------
        ip = df.get("ip_address", "").astype(str)
        ip_split = ip.str.split(".", expand=True)

        features["ip_octet_1"] = (
            pd.to_numeric(ip_split[0], errors="coerce").fillna(0)
            if ip_split.shape[1] > 0 else 0
        )
        features["ip_octet_2"] = (
            pd.to_numeric(ip_split[1], errors="coerce").fillna(0)
            if ip_split.shape[1] > 1 else 0
        )

        # --------------------
        # User-Agent behavior
        # --------------------
        user_agent = df.get("user_agent", "").astype(str)
        features["user_agent_len"] = user_agent.apply(len)


