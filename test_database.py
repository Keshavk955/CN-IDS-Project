from database import Database


database = Database()


database.insert_alert(

    "2026-09-15 22:20:00",

    "192.168.1.200",

    "192.168.1.1",

    "TEST PORT SCAN",

    "HIGH",

    "Test alert for database"

)


alerts = database.get_alerts()


print("========================================")
print("STORED SECURITY ALERTS")
print("========================================")


for alert in alerts:

    print("\nID              :", alert[0])
    print("Timestamp       :", alert[1])
    print("Source IP       :", alert[2])
    print("Destination IP  :", alert[3])
    print("Attack Type     :", alert[4])
    print("Severity        :", alert[5])
    print("Details         :", alert[6])