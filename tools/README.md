# Tools for analizing pcap files

## Requirement

- Docker
- make

## pcap_info

`pcap_info` tool can read a pcap file and show the following information:

- The file size
- The link layer type(Ethernet, Raw IP, ...)
- Total number of packets
- Number of IPv4 packets
- Number of IPv6 packets
- Number of IPv5 5-tuples
- Number of IPv5 5-tuples hashes (CRC32)

### Build pcap_info

```bash
make pcap_info
```

### Usage

```bash
./pcap_info -i [pcap file] [-o output.txt]
```

