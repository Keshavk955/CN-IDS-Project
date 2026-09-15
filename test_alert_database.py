from database import Database


database = Database()


print("========================================")
print("DATABASE ALERT INTEGRATION TEST")
print("========================================")


# Simulated security alert
database.insert_alert(
    "2026-09-15 22:35:00",
    "192.168.1.100",
    "192.168.1.1",
    "PORT SCAN",
    "HIGH",
    "10 different destination ports detected"
)


print("\nSecurity alert inserted into database.")


# Retrieve alerts
alerts = database.get_alerts()


print("\n========================================")
print("ALERTS STORED IN DATABASE")
print("========================================")


for alert in alerts:

    print("\nID              :", alert[0])
    print("Timestamp       :", alert[1])
    print("Source IP       :", alert[2])
    print("Destination IP  :", alert[3])
    print("Attack Type     :", alert[4])
    print("Severity        :", alert[5])
    print("Details         :", alert[6])