# Python CICFlowMeter

> This project is cloned from [Python Wrapper CICflowmeter](https://github.com/datthinh1801/cicflowmeter) and customized to fit my need.  


### Installation
```sh
git clone https://gitlab.abo.fi/tahmad/cicflowmeter-py
cd cicflowmeter
python3 setup.py install
```


### Usage
```sh
Usage: cicflowmeter [OPTIONS]

Options:
  -i, --interface TEXT   Capture live data from the network interface.
  -f, --pfile PATH       capture offline data from a PCAP file or a folder containing PCAP files.
  -c, --csv              output flows as csv
  -w, --workers INTEGER  No. of workers to write flows to a CSV file.  [default: 2]
  --in                   Dump incomplete flows to the csv file before existing the program.
  --dir DIRECTORY        output directory (in csv mode). [default: current directory]
  --version              Show the version and exit.
  --help                 Show this message and exit.

Constraints:
  {--interface, --pfile}  exactly 1 required
```

Convert the `example.pcap` PCAP file to a csv file containing flows in the `output_flows` folder:

```
cicflowmeter -f example.pcap -c --dir output_flows/
```

Sniff packets real-time from interface: (**need root permission**)

```
cicflowmeter -i eth0 -c --dir output_flows/
```

- Reference: https://www.unb.ca/cic/research/applications.html#CICFlowMeter
