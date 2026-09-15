from scapy.all import IP, TCP, UDP, ICMP


def parse_packet(packet):

    packet_info = {}

    # Check if packet contains IP layer
    if IP not in packet:
        return None

    # Basic IP information
    packet_info["source_ip"] = packet[IP].src
    packet_info["destination_ip"] = packet[IP].dst
    packet_info["packet_size"] = len(packet)

    # Check protocol
    if TCP in packet:

        packet_info["protocol"] = "TCP"
        packet_info["source_port"] = packet[TCP].sport
        packet_info["destination_port"] = packet[TCP].dport

    elif UDP in packet:

        packet_info["protocol"] = "UDP"
        packet_info["source_port"] = packet[UDP].sport
        packet_info["destination_port"] = packet[UDP].dport

    elif ICMP in packet:

        packet_info["protocol"] = "ICMP"
        packet_info["source_port"] = None
        packet_info["destination_port"] = None

    else:

        packet_info["protocol"] = "Other"
        packet_info["source_port"] = None
        packet_info["destination_port"] = None

    return packet_info