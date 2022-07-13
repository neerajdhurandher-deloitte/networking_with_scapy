from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import *
from scapy.packet import Raw
import constants
from scapy_pkg import packet, util

log = util.get_logger_obj()

data_packet = bytearray([0xEE,
                         0xFF, 0x01, 0x02, 0x03, 0x04,
                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                         0xFE, 0xEF, 0x77, 0x65, 0x20, 0x61, 0x72, 0x65, 0x20, 0x77,
                         0x6f, 0x72, 0x6b, 0x69, 0x6e, 0x67, 0x20, 0x6f, 0x6e, 0x20, 0x6e,
                         0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x69, 0x6e, 0x67, 0x20, 0x70, 0x72, 0x6f, 0x6a, 0x65,
                         0x63, 0x74])


# scapy layer
scapy_variable = Ether() / IP() / UDP() / Raw()
log.info(scapy_variable.show())
print(scapy_variable.show())

# set scapy layer port values
scapy_variable[Ether].dst = constants.ether_dst
scapy_variable[Ether].src = constants.ether_src
scapy_variable[Ether].type = constants.ether_type

scapy_variable[IP].dst = constants.ip_dst

#set udp
scapy_variable[UDP].sport = constants.udp_src_port
scapy_variable[UDP].dport = constants.udp_dst_port
scapy_variable[UDP].chksum = constants.udp_checksum

log.info("scapy show :- " + str(scapy_variable.show()))
log.info("ether type :- " + str(scapy_variable[Ether].type))
log.info("ip dst constant  " + constants.ip_dst)

udp_sequence = 0x01
sequence_num = struct.pack("!I", udp_sequence)
load_value = data_packet + sequence_num
print("val " + str(load_value))


# load data packet in Raw
scapy_variable[Raw].load = load_value
log.info(scapy_variable)
print("scapy_variable load len ", str(scapy_variable.__len__()))
print("after ", scapy_variable.show())

# sending packets for infinite time in the interval of 1 sec
while True:
    sendp(scapy_variable)
    time.sleep(1.0)
