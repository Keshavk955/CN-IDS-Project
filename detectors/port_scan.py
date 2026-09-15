import time


class PortScanDetector:

    def __init__(self):

        # Store port activity for each source IP
        self.port_activity = {}

        # Number of different ports required to trigger an alert
        self.port_threshold = 10

        # Time window in seconds
        self.time_window = 10


    def check_packet(self, packet_info):

        # Only TCP and UDP packets have destination ports
        if packet_info["protocol"] not in ["TCP", "UDP"]:
            return None


        source_ip = packet_info["source_ip"]
        destination_port = packet_info["destination_port"]

        # Get the current time
        current_time = time.time()


        # Create an empty list for a new source IP
        if source_ip not in self.port_activity:

            self.port_activity[source_ip] = []


        # Store the destination port and current time
        self.port_activity[source_ip].append(
            (destination_port, current_time)
        )


        # Keep only activities within the specified time window
        self.port_activity[source_ip] = [

            activity

            for activity in self.port_activity[source_ip]

            if current_time - activity[1] <= self.time_window
        ]


        # Find all unique destination ports
        unique_ports = set()

        for port, timestamp in self.port_activity[source_ip]:

            unique_ports.add(port)


        # Check whether the number of different ports
        # has reached the port scan threshold
        if len(unique_ports) >= self.port_threshold:

            return {

                "attack_type": "PORT SCAN",

                "source_ip": source_ip,

                "ports_detected": len(unique_ports),

                "severity": "HIGH"

            }


        # No suspicious activity detected
        return None