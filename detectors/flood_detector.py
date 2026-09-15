import time


class FloodDetector:

    def __init__(self):

        # Store packet activity for each source IP
        self.packet_activity = {}

        # Number of packets required to trigger an alert
        self.packet_threshold = 20

        # Time window in seconds
        self.time_window = 5


    def check_packet(self, packet_info):

        source_ip = packet_info["source_ip"]

        current_time = time.time()


        # Create an empty activity list for a new source IP
        if source_ip not in self.packet_activity:

            self.packet_activity[source_ip] = []


        # Store the current packet time
        self.packet_activity[source_ip].append(current_time)


        # Keep only packets received within the time window
        self.packet_activity[source_ip] = [

            timestamp

            for timestamp in self.packet_activity[source_ip]

            if current_time - timestamp <= self.time_window
        ]


        # Count packets within the time window
        packet_count = len(self.packet_activity[source_ip])


        # Check for possible flooding
        if packet_count >= self.packet_threshold:

            return {

                "attack_type": "POSSIBLE FLOOD ATTACK",

                "source_ip": source_ip,

                "packet_count": packet_count,

                "time_window": self.time_window,

                "severity": "HIGH"
            }


        return None