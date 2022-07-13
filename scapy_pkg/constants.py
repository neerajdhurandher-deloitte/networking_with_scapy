ether_dst = "00:00:01:01:01:01"
ether_src = "02:02:02:03:03:03"
ether_type = 0x0800

udp_src_port = 0x2710
udp_dst_port = 0x2368
udp_checksum = 1207
udp_sequence = bytearray([0x01]*4)

ip_src = "127.0.0.1"
ip_dst = "127.0.0.3"

packet_length = 263
msg_str = "Networking Assignment with Scapy"
sign_msg = "Submitted by Neeraj Dhurandher, SDET"
