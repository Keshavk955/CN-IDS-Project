from detectors.port_scan import PortScanDetector


# Create detector object
detector = PortScanDetector()


# List of different ports for testing
test_ports = [
    21,
    22,
    23,
    25,
    53,
    80,
    110,
    143,
    443,
    3306
]


print("========================================")
print("PORT SCAN DETECTION TEST")
print("========================================\n")


# Simulated source IP
source_ip = "192.168.1.100"


# Send simulated packets to the detector
for port in test_ports:

    # Create simulated packet information
    packet_info = {

        "source_ip": source_ip,

        "destination_ip": "192.168.1.1",

        "protocol": "TCP",

        "source_port": 50000,

        "destination_port": port,

        "packet_size": 100
    }


    print("Testing connection to Port:", port)


    # Check packet using our IDS detector
    alert = detector.check_packet(packet_info)


    # Display alert if detected
    if alert is not None:

        print("\n!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
        print("SECURITY ALERT DETECTED")
        print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")

        print("Attack Type   :", alert["attack_type"])
        print("Source IP     :", alert["source_ip"])
        print("Ports Scanned :", alert["ports_detected"])
        print("Severity      :", alert["severity"])

        print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n")