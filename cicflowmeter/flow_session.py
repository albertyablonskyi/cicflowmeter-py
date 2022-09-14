import csv
import sys
import gc
from pathlib import Path
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor
from scapy.all import TCP
from scapy.sessions import DefaultSession

from cicflowmeter.features.context.packet_direction import PacketDirection
from cicflowmeter.features.context.packet_flow_key import get_packet_flow_key
from cicflowmeter.flow import Flow

EXPIRED_UPDATE = 120
GARBAGE_COLLECT_PACKETS = 1000


def calculate_flow_data(key, flow):
    # print(f"Got {key} ... ")
    dest_ip, src_ip, src_port, dest_port = key
    data = flow.get_data(flow_id="-".join(map(str, (src_ip, dest_ip, src_port, dest_port, flow.id))))
    del flow
    # _ = gc.collect()
    return key, data


class FlowSession(DefaultSession):
    """Creates a list of network flows."""

    def __init__(self, *args, **kwargs):
        self.flows = {}
        self.nb_flows_completed = 0
        self.flows_ready_for_dumping = {}
        self.csv_file = None

        # Check if a custom Flow class has not been set by the generator
        if not hasattr(self, "flow_class"):
            if kwargs.get("flow_class", None):
                self.flow_class = kwargs["flow_class"]
            else:
                # Falling back to the default Flow class
                self.flow_class = Flow

        if not hasattr(self, "show_packet_count"):
            self.show_packet_count = False

        if not hasattr(self, "dump_incomplete_flows"):
            self.dump_incomplete_flows = False

        if self.output_mode == "csv":
            self.executor = ProcessPoolExecutor(max_workers=self.nb_workers)

            output_directory = Path(self.output_directory).resolve()

            if not output_directory.is_dir():
                output_directory = Path.cwd()
                print(f"Invalid output_directory provided using the {str(output_directory)}")

            if Path(self.source_name).is_file():
                self.csv_file = output_directory / f"{Path(self.source_name).stem}.csv"
            else:
                self.csv_file = output_directory / f"{self.source_name}.csv"

            print(f"Dump flows to {self.csv_file}")

        self.packets_count = 0

        self.clumped_flows_per_label = defaultdict(list)

        super(FlowSession, self).__init__(*args, **kwargs)

    def toPacketList(self):
        # Sniffer finished all the packets it needed to sniff.
        # It is not a good place for this, we need to somehow define a finish signal for AsyncSniffer

        if self.output_mode == "csv":
            if self.dump_incomplete_flows:
                self.mark_incomplete_flows_as_completed()

            self.executor.shutdown(wait=True)
            print("")
            print("Dumped all the processed flows!")
        return super(FlowSession, self).toPacketList()

    def on_packet_received(self, packet):
        direction = PacketDirection.FORWARD

        self.packets_count += 1

        if self.show_packet_count:
            print(f"No. of packets: {self.packets_count} and flows processed: {self.nb_flows_completed}", end="\r")

        # Creates a key variable to check a flow in the forward direction
        packet_flow_key = get_packet_flow_key(packet, direction)

        # check_cond = ((src_ip == '192.168.10.14' and dest_ip == '72.21.91.29' and
        #                src_port == 59150 and dest_port == 80) or
        #               (dest_ip == '192.168.10.14' and src_ip == '72.21.91.29' and
        #                dest_port == 59150 and src_port == 80)) and False

        # check_cond = self.packets_count >= 1070384 and False

        # if check_cond:
        #     print("==========", self.packets_count)
        #     print(packet.show())

        # Creates a key variable to check a flow in the forward direction
        flow = self.flows.get(packet_flow_key)

        # if check_cond:
        #     print("1.", self.packets_count)
        #     print(packet_flow_key, flow)

        # If there is no forward flow with a count of 0
        if flow is None:
            # There might be one of it in reverse
            direction = PacketDirection.REVERSE
            packet_flow_key = get_packet_flow_key(packet, direction)
            flow = self.flows.get(packet_flow_key)

        # if check_cond:
        #     print("2.", self.packets_count)
        #     print(packet_flow_key, flow)

        if flow is None:
            # If no flow exists create a new flow
            direction = PacketDirection.FORWARD
            packet_flow_key = get_packet_flow_key(packet, direction)
            flow = self.flow_class(packet, direction, len(self.flows))
            self.flows[packet_flow_key] = flow
            # if check_cond:
            #     print("Create a new 1")
        elif (packet.time - flow.latest_timestamp) > EXPIRED_UPDATE:
            # If the packet exists in the flow but the packet is sent
            # after too much of a delay than it is a part of a new flow.

            # We mark the current flow as completed
            self.mark_flow_completed(packet_flow_key, flow)
            # if check_cond:
            #     print("Marking done on Expiration")

            flow = self.flows.get(packet_flow_key)

            if flow is None:
                # If a flow with that key doesn't exist
                direction = PacketDirection.FORWARD
                packet_flow_key = get_packet_flow_key(packet, direction)
                flow = self.flow_class(packet, direction, len(self.flows))
                # if check_cond:
                #     print("Create a new 2")
                self.flows[packet_flow_key] = flow
            else:
                # we have already marked expired flow as completed
                print("######## ERROR", packet_flow_key, flow)
                sys.exit()
        elif packet.haslayer(TCP) and "R" in str(packet[TCP].flags):
            # If it has RST flag then we collect the flow and continue
            # if check_cond:
            #     print("Marking done on RST")
            self.mark_flow_completed(packet_flow_key, flow)
        elif packet.haslayer(TCP) and "A" in str(packet[TCP].flags):
            if flow.fwd_fin_flags >= 1 and flow.bwd_fin_flags >= 1:
                # if check_cond:
                #     print("Marking done on F", flow.fwd_fin_flags, flow.bwd_fin_flags)
                self.mark_flow_completed(packet_flow_key, flow)

        # if check_cond:
        #     print("adding packet")

        flow.add_packet(packet, direction, self.packets_count)

        # if check_cond:
        #     print("4.", self.packets_count)
        #     print(packet_flow_key, flow)
        #     print(len(flow.packets))

        # if self.packets_count % GARBAGE_COLLECT_PACKETS == 0 or (
        #     flow.duration > 120 and self.output_mode == "flow"
        # ):
        if self.output_mode == "csv":
            self.write_flows()

        # if check_cond:
        #     print("done dumping")

        return flow, packet_flow_key

    def mark_flow_completed(self, flow_key, flow):
        self.flows_ready_for_dumping[flow_key] = flow
        del self.flows[flow_key]

    def get_flows(self) -> list:
        return self.flows.values()

    def cb_write_csv_line(self, future):
        with open(self.csv_file, "a+") as output:
            csv_writer = csv.writer(output)
            key, data = future.result()
            if output.tell() == 0:
                # the file is just created, write headers
                csv_writer.writerow(data.keys())
            csv_writer.writerow(data.values())
        self.nb_flows_completed += 1

    def mark_incomplete_flows_as_completed(self):
        print("No. of incomplete flows:", len(self.flows))
        for k, f in self.flows.items():
            self.mark_flow_completed(k, f)
        self.write_flows()

    def write_flows(self) -> None:
        if len(self.flows_ready_for_dumping) == 0:
            return

        while True:
            try:
                k, flow = self.flows_ready_for_dumping.popitem()
            except KeyError:
                # the set is empty, we have dumped all the flows for now
                break

            future = self.executor.submit(calculate_flow_data, k, flow)
            future.add_done_callback(self.cb_write_csv_line)

        if self.packets_count % GARBAGE_COLLECT_PACKETS == 0:
            _ = gc.collect()


def generate_session_class(
        source_name, output_mode, output_directory, dump_incomplete_flows, nb_workers, show_packet_count
):
    return type(
        "NewFlowSession",
        (FlowSession,),
        {
            "source_name": source_name,
            "output_mode": output_mode,
            "output_directory": output_directory,
            "dump_incomplete_flows": dump_incomplete_flows,
            "nb_workers": nb_workers,
            "show_packet_count": show_packet_count,
        },
    )
