# NobilisIDS CICFlowMeter

The NobilisIDS CICFlowMeter is a customized version of the Python CICFlowMeter, designed specifically for the NobilisIDS project. It includes modifications to the output format of the .csv file and a workaround for dropping packets other than IP TCP/UDP.

## Installation

To install and use the NobilisIDS CICFlowMeter, follow these steps:

```bash
git clone https://github.com/albertyablonskyi/cicflowmeter-py.git
cd cicflowmeter
python3 setup.py install
```

## Usage

The NobilisIDS CICFlowMeter provides command-line options to capture and analyze network traffic. Here are the available options:

```
Usage: cicflowmeter [OPTIONS]

Options:
  -i, --interface TEXT   Capture live data from the network interface.
  -f, --pfile PATH       Capture offline data from a PCAP file or a folder containing PCAP files.
  -c, --csv              Output flows as CSV.
  -w, --workers INTEGER  Number of workers to write flows to a CSV file. [default: 2]
  --in                   Dump incomplete flows to the CSV file before exiting the program.
  --dir DIRECTORY        Output directory (in CSV mode). [default: current directory]
  --version              Show the version and exit.
  --help                 Show this message and exit.

Constraints:
  {--interface, --pfile}  Exactly 1 required
```

### Convert PCAP file to CSV

To convert a PCAP file to a CSV file containing flows, use the following command:

```bash
cicflowmeter -f example.pcap -c
```

Replace `example.pcap` with the path to your PCAP file.

### Sniff packets in real-time from an interface

To capture and analyze packets in real-time from a network interface (requires root permission), use the following command:

```bash
cicflowmeter -i interface_name -c
```

Replace `interface_name` with the name of the network interface you want to monitor.

## Reference

For more information about the CICFlowMeter and its applications, please refer to the [CICFlowMeter website](https://www.unb.ca/cic/research/applications.html#CICFlowMeter).