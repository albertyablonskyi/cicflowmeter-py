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
sage: cicflowmeter [-h] (-i INPUT_INTERFACE | -f INPUT_FILE) [-c] [--in] [--dir OUTPUT_DIRECTORY]

optional arguments:
  -h, --help            show this help message and exit
  -i INPUT_INTERFACE, --interface INPUT_INTERFACE
                        capture online data from INPUT_INTERFACE
  -f INPUT_FILE, --file INPUT_FILE
                        capture offline data from a PCAP file or a folder containing PCAP files
  -c, --csv             output flows as csv
  --in                  Dump incomplete flows to the csv file before existing the program
  --dir OUTPUT_DIRECTORY
                        output directory (in csv mode)
```

Convert pcap file to flow csv:

```
cicflowmeter -f example.pcap -c flows.csv
```

Sniff packets real-time from interface to flow csv: (**need root permission**)

```
cicflowmeter -i eth0 -c flows.csv
```

- Reference: https://www.unb.ca/cic/research/applications.html#CICFlowMeter
