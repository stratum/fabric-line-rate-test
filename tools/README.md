# Tools for analizing pcap files

## Requirement

- Docker
- make

## pcap-info

`pcap-info` tool can read a pcap file and show the following information:

- The file size
- The link layer type(Ethernet, Raw IP, ...)
- Total number of packets
- Number of IPv4 packets
- Number of IPv6 packets
- Number of IPv5 5-tuples
- Number of IPv5 5-tuples hashes (CRC32)

### Build pcap-info

```bash
make pcap-info
```

### Usage

```bash
./pcap-info -i [pcap file] [-o output.txt]
```

## int-info

`int-info` tool can read a pcap file that includes INT reports and show the following information:

- Total INT reports
- Total invalid packets (e.g., No INT report or invalid inner packet)
- Total IPv4 flows from all reports
- Number of flows with single reports and multiples
- Number of total intervals
- All interval data

### Build int-info

```bash
make int-info
```

### Usage

```bash
./int-info -i [pcap file] [-o output.txt]
```

## int_plot.py

`int_plot.py` reads the output from `int-info` and generate a figure which shows the histogram and CDF of all intervals.

This script requires `numpy`, `matplotlib`, and `scipy`, you can use the following command to install it:

```bash
pip3 install scipy==1.5.4 numpy==1.19.4 matplotlib==3.3.3
```

### Usage

```bash
./int_plot.py -i [output.txt] -o [output.png]
```
