import time


class ICMFloodDetector:

    def __init__(self):

        # Store ICMP activity for each source IP
        self.icmp_activity = {}

        # Number of ICMP packets required
        # to trigger an alert
        self.packet_threshold = 10

        # Time window in seconds
        self.time_window = 5


    def check_packet(self, packet_info):

        # Only check ICMP packets
        if packet_info["protocol"] != "ICMP":
            return None

        source_ip = packet_info["source_ip"]

        current_time = time.time()


        # Create activity list for new source IP
        if source_ip not in self.icmp_activity:

            self.icmp_activity[source_ip] = []


        # Store current packet time
        self.icmp_activity[source_ip].append(
            current_time
        )


        # Keep only recent packets
        self.icmp_activity[source_ip] = [
            timestamp
            for timestamp in self.icmp_activity[source_ip]
            if current_time - timestamp <= self.time_window
        ]


        # Count recent ICMP packets
        packet_count = len(
            self.icmp_activity[source_ip]
        )


        # Check for possible ICMP flood
        if packet_count >= self.packet_threshold:

            return {
                "attack_type": "POSSIBLE ICMP FLOOD",
                "source_ip": source_ip,
                "packet_count": packet_count,
                "time_window": self.time_window,
                "severity": "HIGH"
            }


        return None