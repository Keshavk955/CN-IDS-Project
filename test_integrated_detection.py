
from packet_sniffer import process_packet
from scapy.all import IP, TCP, Ether
from database import Database


print("========================================")
print("INTEGRATED DETECTION TEST")
print("========================================")

print("Sending simulated packets to the detector...")

for port in [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306]:
    packet = (
        Ether()
        / IP(src="192.168.1.100", dst="192.168.1.1")
        / TCP(sport=50000, dport=port)
    )
    process_packet(packet)

print("\n========================================")
print("CHECKING DATABASE")
print("========================================")

database = Database()
alerts = database.get_alerts()

matching_alerts = [
    alert for alert in alerts
    if alert[2] == "192.168.1.100"
    and alert[3] == "192.168.1.1"
    and alert[4] == "PORT SCAN"
]

if matching_alerts:
    print("SUCCESS: Integrated port-scan alert found in database.")
    print("Latest matching alert:")
    print(matching_alerts[0])
else:
    print("FAIL: No matching integrated port-scan alert found.")

print("========================================")
