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
