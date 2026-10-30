
from scapy.all import Ether, IP, TCP
from packet_sniffer import process_packet
from database import Database

print("========================================")
print("INTEGRATED FLOOD DETECTION TEST")
print("========================================")

print("Sending 20 simulated TCP packets...")

for i in range(20):
    packet = (
        Ether()
        / IP(src="192.168.1.200", dst="192.168.1.1")
        / TCP(sport=50000, dport=8080)
    )
    process_packet(packet)

print("\n========================================")
print("CHECKING DATABASE")
print("========================================")

database = Database()
alerts = database.get_alerts()

matching_alerts = [
    alert for alert in alerts
    if alert[2] == "192.168.1.200"
    and alert[3] == "192.168.1.1"
    and alert[4] == "POSSIBLE FLOOD ATTACK"
]

if matching_alerts:
    print("SUCCESS: Integrated flood alert found in database.")
    print("Latest matching alert:")
    print(matching_alerts[0])
else:
    print("FAIL: No matching flood alert found in database.")

print("========================================")
