from packet_parser import parse_packet
from statistics import NetworkStatistics
from detectors.port_scan import PortScanDetector
from detectors.flood_detector import FloodDetector
from database import Database
from datetime import datetime


# Create objects
statistics = NetworkStatistics()

port_scan_detector = PortScanDetector()

flood_detector = FloodDetector()

database = Database()


def process_packet(packet):

    # Parse packet
    packet_info = parse_packet(packet)

    # Ignore non-IP packets
    if packet_info is None:
        return

    # Update network statistics
    statistics.update_statistics(packet_info)

    # Current timestamp
    current_time = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    # ----------------------------------------
    # PORT SCAN DETECTION
    # ----------------------------------------

    port_scan_alert = port_scan_detector.check_packet(
        packet_info
    )

    if port_scan_alert is not None:

        print("\n")
        print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
        print("SECURITY ALERT")
        print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")

        print(
            "Attack Type   :",
            port_scan_alert["attack_type"]
        )

        print(
            "Source IP     :",
            port_scan_alert["source_ip"]
        )

        print(
            "Ports Scanned :",
            port_scan_alert["ports_detected"]
        )

        print(
            "Severity      :",
            port_scan_alert["severity"]
        )

        print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")

        # Save alert in database
        database.insert_alert(
            current_time,
            port_scan_alert["source_ip"],
            packet_info["destination_ip"],
            port_scan_alert["attack_type"],
            port_scan_alert["severity"],
            "Multiple destination ports detected"
        )

        print("Alert saved to database.")


    # ----------------------------------------
    # FLOOD DETECTION
    # ----------------------------------------

    flood_alert = flood_detector.check_packet(
        packet_info
    )

    if flood_alert is not None:

        print("\n")
        print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
        print("SECURITY ALERT")
        print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")

        print(
            "Attack Type   :",
            flood_alert["attack_type"]
        )

        print(
            "Source IP     :",
            flood_alert["source_ip"]
        )

        print(
            "Packet Count  :",
            flood_alert["packet_count"]
        )

        print(
            "Time Window   :",
            flood_alert["time_window"],
            "seconds"
        )

        print(
            "Severity      :",
            flood_alert["severity"]
        )

        print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")

        # Save alert in database
        database.insert_alert(
            current_time,
            flood_alert["source_ip"],
            packet_info["destination_ip"],
            flood_alert["attack_type"],
            flood_alert["severity"],
            "High packet rate detected"
        )

        print("Alert saved to database.")


    # ----------------------------------------
    # DISPLAY PACKET INFORMATION
    # ----------------------------------------

    print("\n========================================")

    print(
        "PACKET #",
        statistics.total_packets
    )

    print(
        "Time :",
        current_time
    )

    print("========================================")

    print(
        "Source IP       :",
        packet_info["source_ip"]
    )

    print(
        "Destination IP  :",
        packet_info["destination_ip"]
    )

    print(
        "Protocol        :",
        packet_info["protocol"]
    )

    # Display port information for TCP and UDP
    if packet_info["source_port"] is not None:

        print(
            "Source Port     :",
            packet_info["source_port"]
        )

        print(
            "Destination Port:",
            packet_info["destination_port"]
        )

    print(
        "Packet Size     :",
        packet_info["packet_size"],
        "bytes"
    )

    # Display statistics
    statistics.display_statistics()