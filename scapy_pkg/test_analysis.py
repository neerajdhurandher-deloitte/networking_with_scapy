from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy_pkg.packet import PacketClass as packet_class
import constants
from scapy.utils import rdpcap

from scapy_pkg import util

log = util.get_logger_obj()

data = "/Users/ndhurandher/Documents/networking_scapy_test.pcap"
packets = rdpcap(data)

interested_packets = []

for i in packets:
    if len(i) == constants.packet_length:
        interested_packets.append(i)

print(interested_packets[0][Raw])

a = interested_packets[0][Raw].load
print(a)
index = 0
temp = ""
slash = '\\'

print(slash)

# for i in str(a):
#     if i == slash:
#         print(temp, " ", index)
#         index += 1
#         temp = ""
#     else:
#         temp += i
require = interested_packets[0][Raw].load[185:].decode(util.get_encoding())
# require = require
actual = constants.sign_msg
print("require ", require)
print("actual ", actual)
if require == actual:
    print("equal")
else:
    print("not equal")

try:
    assert len(interested_packets[0]) == constants.packet_length, "Packet length is not as per preset."
    log.info("Packet length is same as preset " + str(len(interested_packets[0])))

    assert interested_packets[0][Ether].dst == constants.ether_dst, "Ether destination is not as per preset"
    log.info("Ether destination  is same as preset " + str(interested_packets[0][Ether].dst))

    assert interested_packets[0][Ether].src == constants.ether_src, "Ether source is not as per preset"
    log.info("Ether source is same as preset " + str(interested_packets[0][Ether].src))

    assert interested_packets[0][Ether].type == constants.ether_type, "Ether type is not as per preset"
    log.info("Ether type is same as preset " + str(interested_packets[0][Ether].type))

    assert interested_packets[0][UDP].sport == constants.udp_src_port, "UDP source port is not as per preset"
    log.info("UDP source port is same as preset " + str(interested_packets[0][UDP].sport))

    assert interested_packets[0][UDP].dport == constants.udp_dst_port, "UDP destination port is not as per preset"
    log.info("UDP source destination is same as preset " + str(interested_packets[0][UDP].dport))

    assert interested_packets[0][UDP].chksum == constants.udp_checksum, "UDP check sum is not as per preset"
    log.info("UDP source check sum is same as preset " + str(interested_packets[0][UDP].chksum))

    assert interested_packets[0][IP].dst == constants.ip_dst, "IP destination not as per preset"
    log.info("IP destination is same as preset " + str(interested_packets[0][IP].dst))

    assert interested_packets[0][IP].src == constants.ip_src, "IP source not as per preset"
    log.info("IP source is same as preset " + str(interested_packets[0][IP].src))

    assert bytearray(interested_packets[0][Raw].load[26:33]) == packet_class.byte26_32, "byte26_32 is not as per preset"
    log.info("byte26_32 is same as preset " + str(bytearray(interested_packets[0][Raw].load[26:33])))

    assert interested_packets[0][Raw].load[60:92].decode(util.get_encoding()) == constants.msg_str, \
        "Input Message data is not as per preset"
    log.info("Input Message data is same as preset " +
             str(interested_packets[0][Raw].load[60:92].decode(util.get_encoding())))

    assert interested_packets[0][Raw].load[185:].decode(util.get_encoding()) == constants.sign_msg, \
        "Signature data is not as per preset"
    log.info("Signature data is same as preset " +
             str(interested_packets[0][Raw].load[185:].decode(util.get_encoding())))


except AssertionError as error_msg:
    log.error(error_msg)
