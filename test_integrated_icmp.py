
from scapy.all import Ether, IP, ICMP
from packet_sniffer import process_packet
from database import Database

print("========================================")
print("INTEGRATED ICMP FLOOD TEST")
print("========================================")

print("Sending 10 simulated ICMP packets...")

for i in range(10):
    packet = (
        Ether()
        / IP(src="192.168.1.150", dst="192.168.1.1")
        / ICMP()
    )
    process_packet(packet)

print("\n========================================")
print("CHECKING DATABASE")
print("========================================")

database = Database()
alerts = database.get_alerts()

matching_alerts = [
    alert for alert in alerts
    if alert[2] == "192.168.1.150"
    and alert[3] == "192.168.1.1"
    and alert[4] == "POSSIBLE ICMP FLOOD"
]

if matching_alerts:
    print("SUCCESS: Integrated ICMP alert found in database.")
    print("Latest matching alert:")
    print(matching_alerts[0])
else:
    print("FAIL: No matching ICMP alert found.")

print("========================================")