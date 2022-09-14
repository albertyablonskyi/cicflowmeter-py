import sys
from pathlib import Path
from functools import partial

import cloup
from scapy.sendrecv import AsyncSniffer
from cicflowmeter import __version__
from cicflowmeter.flow_session import generate_session_class


def create_sniffer(
    input_interface, input_file, output_mode, output_directory, dump_incomplete_flows, nb_workers
):
    if input_file:
        partial_sniffer = partial(AsyncSniffer, offline=input_file)
        input_source = input_file
    else:
        partial_sniffer = partial(AsyncSniffer, iface=input_interface)
        input_source = input_interface

    NewFlowSession = generate_session_class(
        input_source, output_mode, output_directory, dump_incomplete_flows, nb_workers, show_packet_count=True
    )

    return partial_sniffer(
        filter="ip and (tcp or udp)",
        prn=None,
        session=NewFlowSession,
        store=False,
    )


@cloup.command(show_constraints=True)
@cloup.constraints.require_one(
    cloup.option("-i", "--interface", "input_interface", default=None, type=str,
                 help="Capture live data from the network interface.", multiple=False),
    cloup.option("-f", "--pfile", "input_file", default=None,
                 help="capture offline data from a PCAP file or a folder containing PCAP files.",
                 type=cloup.Path(exists=True, readable=True), multiple=False)
)
@cloup.option("-c", "--csv", is_flag=True, help="output flows as csv")
@cloup.option("-w", "--workers", type=int, default=2, multiple=False, show_default=True,
              help="No. of workers to write flows to a CSV file.")
@cloup.option("--in", "dump_incomplete_flows", is_flag=True,
              help="Dump incomplete flows to the csv file before existing the program.")
@cloup.option("--dir", "output_directory", help="output directory (in csv mode). [default: current directory]", default=str(Path.cwd()),
              type=cloup.Path(file_okay=False, exists=True, writable=True), multiple=False)
@cloup.version_option(version=__version__)
def main(input_interface, input_file, csv, workers, dump_incomplete_flows, output_directory):
    if csv:
        output_mode = "csv"
    else:
        output_mode = ""

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
            sniffer = create_sniffer(
                input_interface,
                ifile,
                output_mode,
                output_directory,
                dump_incomplete_flows,
                workers
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
        sniffer = create_sniffer(
            input_interface,
            input_file,
            output_mode,
            output_directory,
            dump_incomplete_flows,
            workers
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
