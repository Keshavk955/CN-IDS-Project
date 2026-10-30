
from packet_parser import parse_packet
from statistics import NetworkStatistics
from detectors.port_scan import PortScanDetector
from detectors.flood_detector import FloodDetector
from detectors.icmp_flood import ICMFloodDetector
from database import Database
from risk_scoring import calculate_rule_only_score, get_risk_level
from datetime import datetime


statistics = NetworkStatistics()
port_scan_detector = PortScanDetector()
flood_detector = FloodDetector()
icmp_flood_detector = ICMFloodDetector()
database = Database()


def save_and_display_alert(alert, packet_info, details, rule_score):
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    preliminary_score = calculate_rule_only_score(rule_score)
    preliminary_level = get_risk_level(preliminary_score)

    print("\n")
    print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
    print("SECURITY ALERT")
    print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
    print("Attack Type   :", alert["attack_type"])
    print("Source IP     :", alert["source_ip"])
    print("Destination IP:", packet_info["destination_ip"])
    print("Severity      :", alert["severity"])
    print("Rule Score    :", rule_score)
    print("Preliminary Rule-Only Score:", preliminary_score)
    print("Preliminary Risk Level     :", preliminary_level)
    print("Combined Risk Score       : NOT AVAILABLE")
    print("Reason: ML, anomaly and historical scoring are not implemented yet.")
    print("Details       :", details)
    print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")

    database.insert_alert(
        current_time,
        alert["source_ip"],
        packet_info["destination_ip"],
        alert["attack_type"],
        alert["severity"],
        details,
        preliminary_score,
        preliminary_level
    )

    print("Alert saved to database.")


def process_packet(packet):
    packet_info = parse_packet(packet)

    if packet_info is None:
        return

    statistics.update_statistics(packet_info)

    port_scan_alert = port_scan_detector.check_packet(packet_info)

    if port_scan_alert is not None:
        save_and_display_alert(
            port_scan_alert,
            packet_info,
            "Multiple destination ports detected",
            75
        )

    flood_alert = flood_detector.check_packet(packet_info)

    if flood_alert is not None:
        save_and_display_alert(
            flood_alert,
            packet_info,
            "High packet rate detected",
            85
        )

    icmp_alert = icmp_flood_detector.check_packet(packet_info)

    if icmp_alert is not None:
        save_and_display_alert(
            icmp_alert,
            packet_info,
            "High ICMP packet rate detected",
            80
        )

    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")


    print("PACKET #", statistics.total_packets)
    print("Time :", current_time)

    print("Source IP      :", packet_info["source_ip"])
    print("Destination IP :", packet_info["destination_ip"])
    print("Protocol       :", packet_info["protocol"])

    if packet_info["source_port"] is not None:
        print("Source Port    :", packet_info["source_port"])
        print("Destination Port:", packet_info["destination_port"])

    print("Packet Size    :", packet_info["packet_size"], "bytes")
    statistics.display_statistics()
