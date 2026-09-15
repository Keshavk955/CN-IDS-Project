from scapy.all import sniff
from packet_sniffer import process_packet


def start_monitor():

    print("========================================")
    print("NETWORK SECURITY MONITORING SYSTEM")
    print("========================================")

    print("\nStarting packet capture...")
    print("Press Ctrl+C to stop.\n")

    sniff(prn=process_packet, count=20)


if __name__ == "__main__":

    start_monitor()