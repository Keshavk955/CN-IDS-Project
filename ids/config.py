from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"
DB_PATH = DATA_DIR / "security_monitor.db"
MODEL_PATH = DATA_DIR / "anomaly_model.joblib"
DATA_DIR.mkdir(exist_ok=True)

# Thresholds are configurable starting points, not universal attack signatures.
PORT_SCAN_UNIQUE_PORTS = 10
PORT_SCAN_WINDOW_SECONDS = 10
PACKET_RATE_THRESHOLD = 40
PACKET_RATE_WINDOW_SECONDS = 5
ICMP_RATE_THRESHOLD = 10
ICMP_RATE_WINDOW_SECONDS = 5
SYN_RATE_THRESHOLD = 20
