from detectors.flood_detector import FloodDetector


# Create flood detector object
detector = FloodDetector()


print("========================================")
print("FLOOD ATTACK DETECTION TEST")
print("========================================\n")


# Simulated source IP
source_ip = "192.168.1.200"


# Simulate 25 packets from the same source IP
for i in range(25):

    packet_info = {

        "source_ip": source_ip,

        "destination_ip": "192.168.1.1",

        "protocol": "UDP",

        "source_port": 50000,

        "destination_port": 80,

        "packet_size": 100
    }


    print("Processing simulated packet:", i + 1)


    # Check the packet
    alert = detector.check_packet(packet_info)


    # Display alert if flooding is detected
    if alert is not None:

        print("\n!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
        print("SECURITY ALERT DETECTED")
        print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")

        print("Attack Type   :", alert["attack_type"])
        print("Source IP     :", alert["source_ip"])
        print("Packet Count  :", alert["packet_count"])
        print(
            "Time Window   :",
            alert["time_window"],
            "seconds"
        )
        print("Severity      :", alert["severity"])

        print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n")

        # Stop after detecting the attack
        break