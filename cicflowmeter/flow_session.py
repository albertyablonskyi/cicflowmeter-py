from collections import defaultdict
from scapy.all import TCP
from scapy.sessions import DefaultSession

from cicflowmeter.features.context.packet_direction import PacketDirection
from cicflowmeter.features.context.packet_flow_key import get_packet_flow_key
from cicflowmeter.flow import Flow

EXPIRED_UPDATE = 120
GARBAGE_COLLECT_PACKETS = 100000


class FlowSession(DefaultSession):
    """Creates a list of network flows."""

    def __init__(self, *args, **kwargs):
        self.flows = {}
        self.flows_completed_by_FIN = set()
        self.csv_line = 0

        # Check if a custom Flow class is provided
        if not hasattr(self, "flow_class"):
            if kwargs.get("flow_class", None):
                self.flow_class = kwargs["flow_class"]
            else:
                # Falling back to the default Flow class
                self.flow_class = Flow

        # if self.output_mode == "flow":
        #     output = open(self.output_file, "w")
        #     self.csv_writer = csv.writer(output)

        self.packets_count = 0

        self.clumped_flows_per_label = defaultdict(list)

        super(FlowSession, self).__init__(*args, **kwargs)

    def toPacketList(self):
        # Sniffer finished all the packets it needed to sniff.
        # It is not a good place for this, we need to somehow define a finish signal for AsyncSniffer
        # self.garbage_collect(None)
        return super(FlowSession, self).toPacketList()

    def on_packet_received(self, packet):
        count = 0
        direction = PacketDirection.FORWARD

        if self.output_mode != "flow":
            if "TCP" not in packet:
                return
            elif "UDP" not in packet:
                return

        try:
            # Creates a key variable to check
            packet_flow_key = get_packet_flow_key(packet, direction)
            flow = self.flows.get((packet_flow_key, count))
        except Exception:
            return

        self.packets_count += 1

        # If there is no forward flow with a count of 0
        if flow is None:
            # There might be one of it in reverse
            direction = PacketDirection.REVERSE
            packet_flow_key = get_packet_flow_key(packet, direction)
            flow = self.flows.get((packet_flow_key, count))

        if flow is None:
            # If no flow exists create a new flow
            direction = PacketDirection.FORWARD
            flow = self.flow_class(packet, direction, len(self.flows))
            packet_flow_key = get_packet_flow_key(packet, direction)
            self.flows[(packet_flow_key, count)] = flow

        elif (packet.time - flow.latest_timestamp) > EXPIRED_UPDATE:
            # If the packet exists in the flow but the packet is sent
            # after too much of a delay than it is a part of a new flow.
            expired = EXPIRED_UPDATE
            while (packet.time - flow.latest_timestamp) > expired:
                count += 1
                expired += EXPIRED_UPDATE
                flow = self.flows.get((packet_flow_key, count))

                if flow is None:
                    flow = self.flow_class(packet, direction, len(self.flows))
                    self.flows[(packet_flow_key, count)] = flow
                    break
        elif (packet_flow_key, count) in self.flows_completed_by_FIN:
            # If the packets exists in the flow but the flow
            # has been completed by a FIN flag previously
            while True:
                count += 1
                flow = self.flows.get((packet_flow_key, count))

                if flow is None:
                    flow = self.flow_class(packet, direction, len(self.flows))
                    self.flows[(packet_flow_key, count)] = flow
                    break

        if packet.haslayer(TCP) and "F" in str(packet[TCP].flags):
            # print("Hello f", packet[TCP].flags)
            # If it has FIN flag then early collect flow and continue
            # print("####### Received FIN")
            self.flows_completed_by_FIN.add((packet_flow_key, count))
            # self.garbage_collect(packet.time)

        flow.add_packet(packet, direction)
        # print("Hello out", len(flow.packets))
        # if not self.url_model:
        #     GARBAGE_COLLECT_PACKETS = 10000

        # if self.packets_count % GARBAGE_COLLECT_PACKETS == 0 or (
        #     flow.duration > 120 and self.output_mode == "flow"
        # ):
        #     self.garbage_collect(packet.time)

        return flow, (packet_flow_key, count)

    def get_flows(self) -> list:
        return self.flows.values()

    def garbage_collect(self, latest_time) -> None:
        # TODO: Garbage Collection / Feature Extraction should have a separate thread
        if not self.url_model:
            print("Garbage Collection Began. Flows = {} ... ".format(len(self.flows)), end="")
        keys = list(self.flows.keys())
        for k in keys:
            flow = self.flows.get(k)

            if (
                latest_time is None
                or latest_time - flow.latest_timestamp > EXPIRED_UPDATE
                or flow.duration > 90
            ):
                data = flow.get_data()

                if self.csv_line == 0:
                    self.csv_writer.writerow(data.keys())

                self.csv_writer.writerow(data.values())
                self.csv_line += 1

                del self.flows[k]
        if not self.url_model:
            print("Garbage Collection Finished. Flows = {}".format(len(self.flows)))


def generate_session_class(output_mode, output_file, url_model):
    return type(
        "NewFlowSession",
        (FlowSession,),
        {
            "output_mode": output_mode,
            "output_file": output_file,
            "url_model": url_model,
        },
    )
