import argparse
import sys
from pathlib import Path

from scapy.sendrecv import AsyncSniffer

from cicflowmeter.flow_session import generate_session_class
# from cicflowmeter.aysncreader import AsyncReader


def create_sniffer_for_pcap(
    input_file, output_mode, output_directory, dump_incomplete_flows
):
    NewFlowSession = generate_session_class(
        input_file, output_mode, output_directory, dump_incomplete_flows, show_packet_count=True
    )


    # return AsyncReader(
    #     offline=input_file,
    #     filter="ip and (tcp or udp)",
    #     prn=None,
    #     session=NewFlowSession,
    #     # timeout=200,
    #     store=False,
    # )

    return AsyncSniffer(
        offline=input_file,
        filter="ip and (tcp or udp)",
        prn=None,
        session=NewFlowSession,
        store=False,
    )


def create_sniffer_for_interface(
    input_interface, output_mode, output_directory
):
    NewFlowSession = generate_session_class(input_interface, output_mode, output_directory)

    return AsyncSniffer(
        iface=input_interface,
        filter="ip and (tcp or udp)",
        prn=None,
        session=NewFlowSession,
        store=False,
    )


def main():
    parser = argparse.ArgumentParser()

    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument(
        "-i",
        "--interface",
        action="store",
        dest="input_interface",
        help="capture online data from INPUT_INTERFACE",
    )

    input_group.add_argument(
        "-f",
        "--file",
        action="store",
        dest="input_file",
        help="capture offline data from a PCAP file or a folder containing PCAP files",
    )

    parser.add_argument(
        "-c",
        "--csv",
        action="store_const",
        const="csv",
        dest="output_mode",
        help="output flows as csv",
    )

    parser.add_argument(
        "--in",
        action="store_true",
        dest="dump_incomplete_flows",
        help="Dump incomplete flows to the csv file before existing the program",
        default=False
    )

    parser.add_argument(
        "--dir",
        dest="output_directory",
        help="output directory (in csv mode)",
        default=str(Path.cwd())
    )

    args = parser.parse_args()

    input_file = args.input_file
    input_interface = args.input_interface

    assert (input_file is None) ^ (input_interface is None)

    if input_file is not None:
        if Path(input_file).is_dir():
            input_files = map(str, Path(input_file).glob('*.pcap'))
        elif Path(input_file).is_file():
            input_files = [input_file, ]
        else:
            print("Invalid input file")
            sys.exit()

        for nb, ifile in enumerate(input_files):
            print(f"==> {nb+1}. Processing file: {ifile}")
            sniffer = create_sniffer_for_pcap(
                ifile,
                args.output_mode,
                args.output_directory,
                args.dump_incomplete_flows,
            )

            sniffer.start()
            stopped = False

            try:
                sniffer.join()
                stopped = True
                input("\nPress enter to exit.")
            except KeyboardInterrupt:
                print("\nExiting...")
                if not stopped:
                    sniffer.stop()
            print("")
    else:
        sniffer = create_sniffer_for_interface(
            input_interface,
            args.output_mode,
            args.output_directory,
        )
        sniffer.start()

        try:
            sniffer.join()
        except KeyboardInterrupt:
            sniffer.stop()
        finally:
            sniffer.join()


if __name__ == "__main__":
    main()
