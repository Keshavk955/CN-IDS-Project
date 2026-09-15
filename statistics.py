class NetworkStatistics:

    def __init__(self):

        self.total_packets = 0

        self.tcp_packets = 0
        self.udp_packets = 0
        self.icmp_packets = 0
        self.other_packets = 0

        self.total_data = 0


    def update_statistics(self, packet_info):

        self.total_packets += 1

        self.total_data += packet_info["packet_size"]

        protocol = packet_info["protocol"]

        if protocol == "TCP":

            self.tcp_packets += 1

        elif protocol == "UDP":

            self.udp_packets += 1

        elif protocol == "ICMP":

            self.icmp_packets += 1

        else:

            self.other_packets += 1


    def display_statistics(self):

        print("\n----------------------------------------")
        print("NETWORK STATISTICS")
        print("----------------------------------------")

        print("Total Packets :", self.total_packets)
        print("TCP Packets   :", self.tcp_packets)
        print("UDP Packets   :", self.udp_packets)
        print("ICMP Packets  :", self.icmp_packets)
        print("Other Packets :", self.other_packets)
        print("Total Data    :", self.total_data, "bytes")

        print("----------------------------------------")