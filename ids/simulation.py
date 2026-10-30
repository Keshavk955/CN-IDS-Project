"""Safe synthetic traffic generator. It does not send packets on any network."""
import random
from datetime import datetime, timezone
from .detection import utc_now

NORMAL_IPS = ['192.0.2.10', '192.0.2.11', '192.0.2.12']
TEST_ATTACK_IP = '198.51.100.23'  # TEST-NET-2 reserved for documentation/examples

def generate_demo_packets(seed=7):
    rng = random.Random(seed)
    packets = []
    # Benign baseline traffic
    for i in range(24):
        proto = rng.choice(['TCP','TCP','UDP','ICMP'])
        packets.append({'timestamp': utc_now(), 'source_ip': rng.choice(NORMAL_IPS), 'destination_ip': '192.0.2.100',
                        'protocol': proto, 'source_port': rng.randint(20000,60000) if proto in ('TCP','UDP') else None,
                        'destination_port': rng.choice([53,80,443,123,8080]) if proto in ('TCP','UDP') else None,
                        'packet_size': rng.randint(64,1400), 'flags': 'PA' if proto=='TCP' else ''})
    # A synthetic scan across distinct ports
    for port in range(20, 34):
        packets.append({'timestamp': utc_now(), 'source_ip': TEST_ATTACK_IP, 'destination_ip': '192.0.2.100', 'protocol': 'TCP',
                        'source_port': rng.randint(30000,50000), 'destination_port': port, 'packet_size': 60, 'flags': 'S'})
    # A synthetic ICMP burst from a separate documentation-only address
    for _ in range(14):
        packets.append({'timestamp': utc_now(), 'source_ip': '198.51.100.44', 'destination_ip': '192.0.2.100', 'protocol': 'ICMP',
                        'source_port': None, 'destination_port': None, 'packet_size': rng.randint(64,128), 'flags': ''})
    return packets


def generate_benign_burst(seed=19):
    """Generate benign high-volume HTTPS-like traffic that can trigger the simple rate rule.

    This is a labelled synthetic false-positive example. It does not send any
    packets to a real network.
    """
    rng = random.Random(seed)
    packets = []
    for _ in range(45):
        packets.append({
            'timestamp': utc_now(),
            'source_ip': '192.0.2.40',
            'destination_ip': '192.0.2.100',
            'protocol': 'TCP',
            'source_port': rng.randint(30000, 60000),
            'destination_port': 443,
            'packet_size': rng.randint(600, 1400),
            'flags': 'PA',
            'scenario_label': 'KNOWN BENIGN SYNTHETIC BURST',
        })
    return packets
