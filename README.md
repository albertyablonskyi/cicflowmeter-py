# NobilisIDS CICFlowMeter

This project is a fork of the Python CICFlowMeter, customized to suit the needs of the NobilisIDS project. It includes changes to the output format of the .csv file and a workaround for dropping packets other than IP TCP/UDP.

The NobilisIDS project can be found [here](https://github.com/albertyablonskyi/NobilisIDS.git), which is the repository customized for your specific use case.

## Installation

To install and use the Python CICFlowMeter, follow these steps:

1. Clone the repository:
git clone https://github.com/albertyablonskyi/cicflowmeter-py.git
cd cicflowmeter-py

2. Install the package:

## Usage

The Python CICFlowMeter provides command-line options to capture and analyze network traffic. Here are the available options:

Usage: cicflowmeter [OPTIONS]

Options:
-i, --interface TEXT Capture live data from the network interface.
-f, --pfile PATH Capture offline data from a PCAP file or a folder containing PCAP files.
-c, --csv Output flows as CSV.
-w, --workers INTEGER Number of workers to write flows to a CSV file. [default: 2]
--in Dump incomplete flows to the CSV file before exiting the program.
--dir DIRECTORY Output directory (in CSV mode). [default: current directory]
--version Show the version and exit.
--help Show this message and exit.

**Constraints:**
- You must use either `--interface` or `--pfile`, but not both.

### Convert PCAP file to CSV

To convert a PCAP file to a CSV file containing flows in the `output_flows` folder, use the following command:

cicflowmeter -f example.pcap -c --dir .

### Sniff packets in real-time from an interface

To capture and analyze packets in real-time from the `eth0` interface (requires root permission), use the following command:

### Sniff packets in real-time from an interface

To capture and analyze packets in real-time from the `eth0` interface (requires root permission), use the following command:

cicflowmeter -i eth0 -c --dir .

## Reference

For more information about the CICFlowMeter and its applications, please refer to the [CICFlowMeter website](https://www.unb.ca/cic/research/applications.html#CICFlowMeter).

