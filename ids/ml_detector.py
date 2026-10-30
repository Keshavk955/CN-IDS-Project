"""Unsupervised anomaly detector trained on a synthetic baseline prototype."""
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import make_pipeline
from .config import MODEL_PATH

FEATURES = ['packets_per_window', 'unique_dst_ports', 'icmp_ratio', 'syn_ratio', 'mean_packet_size', 'unique_destinations']


class MLAnomalyDetector:
    def __init__(self, model_path=MODEL_PATH):
        self.model_path = str(model_path)
        self.model = None
        self._load_existing_or_train()

    def _load_existing_or_train(self):
        try:
            from pathlib import Path
            import joblib
            path = Path(self.model_path)
            if path.exists():
                saved = joblib.load(path)
                if isinstance(saved, dict) and saved.get('features') == FEATURES and saved.get('model') is not None:
                    self.model = saved['model']
                    return
        except (OSError, ValueError, EOFError, AttributeError, ImportError):
            pass
        self.train_baseline()

    def train_baseline(self, random_state=42):
        rng = np.random.default_rng(random_state)
        n = 1800
        normal = np.column_stack([
            rng.poisson(8, n) + 1,
            np.clip(rng.poisson(2, n) + 1, 1, 8),
            rng.beta(1.2, 12, n),
            rng.beta(1.5, 10, n),
            np.clip(rng.normal(650, 250, n), 60, 1500),
            np.clip(rng.poisson(2, n) + 1, 1, 10),
        ])
        self.model = make_pipeline(StandardScaler(), IsolationForest(n_estimators=160, contamination=0.04, random_state=random_state))
        self.model.fit(normal)
        try:
            import joblib
            from pathlib import Path
            path = Path(self.model_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            joblib.dump({'model': self.model, 'features': FEATURES}, path)
        except (OSError, ValueError, ImportError):
            pass

    def score(self, features):
        if self.model is None:
            self.train_baseline()
        x = np.array([[float(features.get(k, 0)) for k in FEATURES]])
        decision = float(self.model.decision_function(x)[0])
        return round(float(np.clip(50 - decision * 85, 0, 100)), 2)
