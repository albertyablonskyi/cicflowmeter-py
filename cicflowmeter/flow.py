from enum import Enum
from typing import Any

from scapy.all import TCP

from cicflowmeter import constants
from cicflowmeter.features.context import packet_flow_key
from cicflowmeter.features.context.packet_direction import PacketDirection
from cicflowmeter.features.flag_count import FlagCount
from cicflowmeter.features.flow_bytes import FlowBytes
from cicflowmeter.features.packet_count import PacketCount
from cicflowmeter.features.packet_length import PacketLength
from cicflowmeter.features.packet_time import PacketTime
from cicflowmeter.features.packet_index import PacketIndex
from cicflowmeter.utils import get_statistics


class Flow:
    """This class summarizes the values of the features of the network flows"""

    def __init__(self, packet: Any, direction: Enum, fid=0):
        """This method initializes an object from the Flow class.

        Args:
            packet (Any): A packet from the network.
            direction (Enum): The direction the packet is going over the wire.
        """

        (
            self.dest_ip,
            self.src_ip,
            self.src_port,
            self.dest_port
        ) = packet_flow_key.get_packet_flow_key(packet, direction)

        self.fwd_fin_flags = 0
        self.bwd_fin_flags = 0
        self.name = "Flow {}".format(fid)
        self.id = fid
        self.packets_indexes = []
        self.packets = []
        self.flow_interarrival_time = []
        self.latest_timestamp = 0
        self.start_timestamp = 0
        self.init_window_size = {
            PacketDirection.FORWARD: 0,
            PacketDirection.REVERSE: 0,
        }

        self.start_active = 0
        self.last_active = 0
        self.active = []
        self.idle = []

        # self.forward_bulk_last_timestamp = 0
        # self.forward_bulk_start_tmp = 0
        self.forward_bulk_count = 0
        # self.forward_bulk_count_tmp = 0
        # self.forward_bulk_duration = 0
        # self.forward_bulk_packet_count = 0
        # self.forward_bulk_size = 0
        # self.forward_bulk_size_tmp = 0
        # self.backward_bulk_last_timestamp = 0
        # self.backward_bulk_start_tmp = 0
        self.backward_bulk_count = 0
        # self.backward_bulk_count_tmp = 0
        # self.backward_bulk_duration = 0
        # self.backward_bulk_packet_count = 0
        # self.backward_bulk_size = 0
        # self.backward_bulk_size_tmp = 0

    def get_data(self, flow_id="") -> dict:
        """This method obtains the values of the features extracted from each flow.

        Note:
            Only some of the network data plays well together in this list.
            Time-to-live values, window values, and flags cause the data to
            separate out too much.

        Returns:
           list: returns a List of values to be outputted into a csv file.

        """

        flow_bytes = FlowBytes(self)
        flag_count = FlagCount(self)
        packet_count = PacketCount(self)
        packet_length = PacketLength(self)
        packet_time = PacketTime(self)
        packet_index = PacketIndex(self)
        flow_iat = get_statistics(self.flow_interarrival_time)
        forward_iat = get_statistics(
            packet_time.get_packet_iat(PacketDirection.FORWARD)
        )
        backward_iat = get_statistics(
            packet_time.get_packet_iat(PacketDirection.REVERSE)
        )
        active_stat = get_statistics(self.active)
        idle_stat = get_statistics(self.idle)

        data = {
            "Destination Port": self.dest_port,
            "Flow Duration": 1e3 * packet_time.get_duration(),

            "Total Fwd Packets": packet_count.get_total(PacketDirection.FORWARD),
            "Total Backward Packets": packet_count.get_total(PacketDirection.REVERSE),

            "Total Length of Fwd Packets": packet_length.get_total(PacketDirection.FORWARD),
            "Total Length of Bwd Packets": packet_length.get_total(PacketDirection.REVERSE),

            "Fwd Packet Length Max": float(packet_length.get_max(PacketDirection.FORWARD)),
            "Fwd Packet Length Min": float(packet_length.get_min(PacketDirection.FORWARD)),
            "Fwd Packet Length Mean": float(packet_length.get_mean(PacketDirection.FORWARD)),
            "Fwd Packet Length Std": float(packet_length.get_std(PacketDirection.FORWARD)),

            "Bwd Packet Length Max": float(packet_length.get_max(PacketDirection.REVERSE)),
            "Bwd Packet Length Min": float(packet_length.get_min(PacketDirection.REVERSE)),
            "Bwd Packet Length Mean": float(packet_length.get_mean(PacketDirection.REVERSE)),
            "Bwd Packet Length Std": float(packet_length.get_std(PacketDirection.REVERSE)),

            "Flow Bytes/s": flow_bytes.get_rate(),
            "Flow Packets/s": packet_count.get_rate(),
            "Flow IAT Mean": float(flow_iat["mean"]),
            "Flow IAT Std": float(flow_iat["std"]),
            "Flow IAT Max": float(flow_iat["max"]),
            "Flow IAT Min": float(flow_iat["min"]),

            "Fwd IAT Total": forward_iat["total"],
            "Fwd IAT Mean": float(forward_iat["mean"]),
            "Fwd IAT Std": float(forward_iat["std"]),
            "Fwd IAT Max": float(forward_iat["max"]),
            "Fwd IAT Min": float(forward_iat["min"]),

            "Bwd IAT Total": float(backward_iat["total"]),
            "Bwd IAT Mean": float(backward_iat["mean"]),
            "Bwd IAT Std": float(backward_iat["std"]),
            "Bwd IAT Max": float(backward_iat["max"]),
            "Bwd IAT Min": float(backward_iat["min"]),

            "Fwd PSH Flags": flag_count.has_flag("PSH", PacketDirection.FORWARD),
            "Bwd PSH Flags": flag_count.has_flag("PSH", PacketDirection.REVERSE),
            "Fwd URG Flags": flag_count.has_flag("URG", PacketDirection.FORWARD),
            "Bwd URG Flags": flag_count.has_flag("URG", PacketDirection.REVERSE),

            "Fwd Header Length": flow_bytes.get_forward_header_bytes(),
            "Bwd Header Length": flow_bytes.get_reverse_header_bytes(),

            "Fwd Packets/s": packet_count.get_rate(PacketDirection.FORWARD),
            "Bwd Packets/s": packet_count.get_rate(PacketDirection.REVERSE),

            "Min Packet Length": packet_length.get_min(),
            "Max Packet Length": packet_length.get_max(),
            
            "Packet Length Mean": float(packet_length.get_mean()),
            "Packet Length Std": float(packet_length.get_std()),
            "Packet Length Variance": float(packet_length.get_var()),

            "FIN Flag Count": flag_count.has_flag("FIN"),
            "SYN Flag Count": flag_count.has_flag("SYN"),
            "RST Flag Count": flag_count.has_flag("RST"),
            "PSH Flag Count": flag_count.has_flag("PSH"),
            "ACK Flag Count": flag_count.has_flag("ACK"),
            "URG Flag Count": flag_count.has_flag("URG"),
            "CWE Flag Count": flag_count.has_flag("ECE"),
            "ECE Flag Count": flag_count.has_flag("ECE"),

            "Down/Up Ratio": packet_count.get_down_up_ratio(),
            
            "Average Packet Size": packet_length.get_avg(),
            "Avg Fwd Segment Size": float(packet_length.get_mean(PacketDirection.FORWARD)),
            "Avg Bwd Segment Size": float(packet_length.get_mean(PacketDirection.REVERSE)),

            "Fwd Header Length.1": flow_bytes.get_forward_header_bytes(),

            "Fwd Avg Bytes/Bulk": float(
                flow_bytes.get_bytes_per_bulk(PacketDirection.FORWARD)
            ),
            "Fwd Avg Packets/Bulk": float(
                flow_bytes.get_packets_per_bulk(PacketDirection.FORWARD)
            ),
            "Fwd Avg Bulk Rate": float(
                flow_bytes.get_bulk_rate(PacketDirection.FORWARD)
            ),
            
            "Bwd Avg Bytes/Bulk": float(
                flow_bytes.get_bytes_per_bulk(PacketDirection.REVERSE)
            ),
            "Bwd Avg Packets/Bulk": float(
                flow_bytes.get_packets_per_bulk(PacketDirection.REVERSE)
            ),
            "Bwd Avg Bulk Rate": float(
                flow_bytes.get_bulk_rate(PacketDirection.REVERSE)
            ),

            "Subflow Fwd Packets": packet_count.get_total(PacketDirection.FORWARD),
            "Subflow Fwd Bytes": packet_length.get_total(PacketDirection.FORWARD),
            "Subflow Bwd Packets": packet_count.get_total(PacketDirection.REVERSE),
            "Subflow Bwd Bytes": packet_length.get_total(PacketDirection.REVERSE),

            "Init_Win_bytes_forward": self.init_window_size[PacketDirection.FORWARD],
            "Init_Win_bytes_backward": self.init_window_size[PacketDirection.REVERSE],

            "act_data_pkt_fwd": packet_count.has_payload(PacketDirection.FORWARD),
            "min_seg_size_forward": flow_bytes.get_min_forward_header_bytes(),

            "Active Mean": float(active_stat["mean"]),
            "Active Std": float(active_stat["std"]),
            "Active Max": float(active_stat["max"]),
            "Active Min": float(active_stat["min"]),

            "Idle Mean": float(idle_stat["mean"]),
            "Idle Std": float(idle_stat["std"]),
            "Idle Max": float(idle_stat["max"]),
            "Idle Min": float(idle_stat["min"]),
        }

        # Duplicated features
        # data["fwd_seg_size_avg"] = data["fwd_pkt_len_mean"]
        # data["bwd_seg_size_avg"] = data["bwd_pkt_len_mean"]
        # data["cwe_flag_count"] = data["fwd_urg_flags"]
        # data["subflow_fwd_pkts"] = data["tot_fwd_pkts"]
        # data["subflow_bwd_pkts"] = data["tot_bwd_pkts"]
        # data["subflow_fwd_byts"] = data["totlen_fwd_pkts"]
        # data["subflow_bwd_byts"] = data["totlen_bwd_pkts"]

        return data

    def add_packet(self, packet: Any, direction: Enum, pindex=None) -> None:
        """Adds a packet to the current list of packets.

        Args:
            packet: Packet to be added to a flow
            direction: The direction the packet is going in that flow
            pindex: packet index in the PCAP file
        """
        self.packets.append((packet, direction))

        if pindex:
            self.packets_indexes.append(pindex)

        # self.update_flow_bulk(packet, direction)
        self.update_subflow(packet)

        if self.start_timestamp != 0:
            self.flow_interarrival_time.append(
                1e3 * (packet.time - self.latest_timestamp)
            )

        self.latest_timestamp = max([packet.time, self.latest_timestamp])

        if "TCP" in packet:
            if (
                direction == PacketDirection.FORWARD
                and self.init_window_size[direction] == 0
            ):
                self.init_window_size[direction] = packet["TCP"].window
            elif direction == PacketDirection.REVERSE:
                self.init_window_size[direction] = packet["TCP"].window

        # First packet of the flow
        if self.start_timestamp == 0:
            self.start_timestamp = packet.time
            self.protocol = packet.proto

        if packet.haslayer(TCP) and "F" in str(packet[TCP].flags):
            if direction == PacketDirection.FORWARD:
                self.fwd_fin_flags += 1
            else:
                self.bwd_fin_flags += 1

    def update_subflow(self, packet):
        """Update subflow

        Args:
            packet: Packet to be parsed as subflow

        """
        last_timestamp = (
            self.latest_timestamp if self.latest_timestamp != 0 else packet.time
        )
        if (packet.time - last_timestamp) > constants.CLUMP_TIMEOUT:
            self.update_active_idle(packet.time - last_timestamp)

    def update_active_idle(self, current_time):
        """Adds a packet to the current list of packets.

        Args:
            packet: Packet to be update active time

        """
        if (current_time - self.last_active) > constants.ACTIVE_TIMEOUT:
            duration = abs(float(self.last_active - self.start_active))
            if duration > 0:
                self.active.append(1e3 * duration)
            self.idle.append(1e3 * (current_time - self.last_active))
            self.start_active = current_time
            self.last_active = current_time
        else:
            self.last_active = current_time

    def update_flow_bulk(self, packet, direction):
        """Update bulk flow

        Args:
            packet: Packet to be parse as bulk

        """
        payload_size = len(PacketCount.get_payload(packet))
        if payload_size == 0:
            return
        if direction == PacketDirection.FORWARD:
            if self.backward_bulk_last_timestamp > self.forward_bulk_start_tmp:
                self.forward_bulk_start_tmp = 0
            if self.forward_bulk_start_tmp == 0:
                self.forward_bulk_start_tmp = packet.time
                self.forward_bulk_last_timestamp = packet.time
                self.forward_bulk_count_tmp = 1
                self.forward_bulk_size_tmp = payload_size
            else:
                if (
                    packet.time - self.forward_bulk_last_timestamp
                ) > constants.CLUMP_TIMEOUT:
                    self.forward_bulk_start_tmp = packet.time
                    self.forward_bulk_last_timestamp = packet.time
                    self.forward_bulk_count_tmp = 1
                    self.forward_bulk_size_tmp = payload_size
                else:  # Add to bulk
                    self.forward_bulk_count_tmp += 1
                    self.forward_bulk_size_tmp += payload_size
                    if self.forward_bulk_count_tmp == constants.BULK_BOUND:
                        self.forward_bulk_count += 1
                        self.forward_bulk_packet_count += self.forward_bulk_count_tmp
                        self.forward_bulk_size += self.forward_bulk_size_tmp
                        self.forward_bulk_duration += (
                            packet.time - self.forward_bulk_start_tmp
                        )
                    elif self.forward_bulk_count_tmp > constants.BULK_BOUND:
                        self.forward_bulk_packet_count += 1
                        self.forward_bulk_size += payload_size
                        self.forward_bulk_duration += (
                            packet.time - self.forward_bulk_last_timestamp
                        )
                    self.forward_bulk_last_timestamp = packet.time
        else:
            if self.forward_bulk_last_timestamp > self.backward_bulk_start_tmp:
                self.backward_bulk_start_tmp = 0
            if self.backward_bulk_start_tmp == 0:
                self.backward_bulk_start_tmp = packet.time
                self.backward_bulk_last_timestamp = packet.time
                self.backward_bulk_count_tmp = 1
                self.backward_bulk_size_tmp = payload_size
            else:
                if (
                    packet.time - self.backward_bulk_last_timestamp
                ) > constants.CLUMP_TIMEOUT:
                    self.backward_bulk_start_tmp = packet.time
                    self.backward_bulk_last_timestamp = packet.time
                    self.backward_bulk_count_tmp = 1
                    self.backward_bulk_size_tmp = payload_size
                else:  # Add to bulk
                    self.backward_bulk_count_tmp += 1
                    self.backward_bulk_size_tmp += payload_size
                    if self.backward_bulk_count_tmp == constants.BULK_BOUND:
                        self.backward_bulk_count += 1
                        self.backward_bulk_packet_count += self.backward_bulk_count_tmp
                        self.backward_bulk_size += self.backward_bulk_size_tmp
                        self.backward_bulk_duration += (
                            packet.time - self.backward_bulk_start_tmp
                        )
                    elif self.backward_bulk_count_tmp > constants.BULK_BOUND:
                        self.backward_bulk_packet_count += 1
                        self.backward_bulk_size += payload_size
                        self.backward_bulk_duration += (
                            packet.time - self.backward_bulk_last_timestamp
                        )
                    self.backward_bulk_last_timestamp = packet.time

    @property
    def duration(self):
        return self.latest_timestamp - self.start_timestamp

    def __str__(self):
        return self.name
