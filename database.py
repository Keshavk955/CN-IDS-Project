import sqlite3


class Database:

    def __init__(self, database_name="security_monitor.db"):

        self.database_name = database_name

        self.create_table()


    def connect(self):

        return sqlite3.connect(self.database_name)


    def create_table(self):

        connection = self.connect()

        cursor = connection.cursor()


        cursor.execute("""
            CREATE TABLE IF NOT EXISTS alerts (

                id INTEGER PRIMARY KEY AUTOINCREMENT,

                timestamp TEXT,

                source_ip TEXT,

                destination_ip TEXT,

                attack_type TEXT,

                severity TEXT,

                details TEXT

            )
        """)


        connection.commit()

        connection.close()


    def insert_alert(
        self,
        timestamp,
        source_ip,
        destination_ip,
        attack_type,
        severity,
        details
    ):

        connection = self.connect()

        cursor = connection.cursor()


        cursor.execute("""
            INSERT INTO alerts
            (
                timestamp,
                source_ip,
                destination_ip,
                attack_type,
                severity,
                details
            )

            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            timestamp,
            source_ip,
            destination_ip,
            attack_type,
            severity,
            details
        ))


        connection.commit()

        connection.close()


    def get_alerts(self):

        connection = self.connect()

        cursor = connection.cursor()


        cursor.execute("""
            SELECT
                id,
                timestamp,
                source_ip,
                destination_ip,
                attack_type,
                severity,
                details

            FROM alerts

            ORDER BY id DESC
        """)


        alerts = cursor.fetchall()

        connection.close()


        return alerts