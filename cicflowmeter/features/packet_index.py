class PacketIndex:
    """This class extracts features related to the Packet Index."""

    def __init__(self, feature):
        self.feature = feature

    def get_indexes(self, sep="_") -> str:
        """Packet indexes in a PCAP file.

        Returns:
            a str separating packet indexes by a sep:

        """

        return sep.join(map(str, self.feature.packets_indexes))