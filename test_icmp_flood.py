from detectors.icmp_flood import ICMFloodDetector


detector = ICMFloodDetector()


print("========================================")
print("ICMP FLOOD DETECTION TEST")
print("========================================\n")


source_ip = "192.168.1.150"


# Simulate ICMP packets
for i in range(15):

    packet_info = {

        "source_ip": source_ip,

        "destination_ip": "192.168.1.1",

        "protocol": "ICMP",

        "source_port": None,

        "destination_port": None,

        "packet_size": 64
    }


    print(
        "Processing ICMP packet:",
        i + 1
    )


    alert = detector.check_packet(
        packet_info
    )


    if alert is not None:

        print("\n!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
        print("SECURITY ALERT DETECTED")
        print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")

        print(
            "Attack Type   :",
            alert["attack_type"]
        )

        print(
            "Source IP     :",
            alert["source_ip"]
        )

        print(
            "Packet Count  :",
            alert["packet_count"]
        )

        print(
            "Time Window   :",
            alert["time_window"],
            "seconds"
        )

        print(
            "Severity      :",
            alert["severity"]
        )

        print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n")

        break