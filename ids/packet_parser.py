def parse_packet(packet):
    try:
        from scapy.layers.inet import IP, TCP, UDP, ICMP
    except ImportError as exc:
        raise RuntimeError('Scapy is required for live packet parsing. Install requirements.txt.') from exc
    if IP not in packet: return None
    p = {'timestamp': __import__('datetime').datetime.now().astimezone().isoformat(timespec='seconds'),
         'source_ip': packet[IP].src, 'destination_ip': packet[IP].dst, 'packet_size': len(packet),
         'protocol': 'Other', 'source_port': None, 'destination_port': None, 'flags': ''}
    if TCP in packet:
        p.update(protocol='TCP', source_port=int(packet[TCP].sport), destination_port=int(packet[TCP].dport), flags=str(packet[TCP].flags))
    elif UDP in packet: p.update(protocol='UDP', source_port=int(packet[UDP].sport), destination_port=int(packet[UDP].dport))
    elif ICMP in packet: p['protocol'] = 'ICMP'
    return p
