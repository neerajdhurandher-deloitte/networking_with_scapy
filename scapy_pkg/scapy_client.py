from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import *
from scapy.packet import Raw
import constants
from scapy_pkg.packet import PacketClass
from scapy_pkg import util

log = util.get_logger_obj()

# scapy layer
scapy_variable = Ether() / IP() / UDP() / Raw()
# log.info("Default value in Scapy layer " + str(scapy_variable.show()))
print(scapy_variable.show())
# set scapy layer port values
scapy_variable[Ether].dst = constants.ether_dst
scapy_variable[Ether].src = constants.ether_src
scapy_variable[Ether].type = constants.ether_type

scapy_variable[IP].src = constants.ip_src
scapy_variable[IP].dst = constants.ip_dst

# set udp
scapy_variable[UDP].sport = constants.udp_src_port
scapy_variable[UDP].dport = constants.udp_dst_port
scapy_variable[UDP].chksum = constants.udp_checksum

log.info("scapy show :- " + str(scapy_variable.show()))
log.info("ether type :- " + str(scapy_variable[Ether].type))
log.info("ip dst constant  " + constants.ip_dst)

# get packet structure
package_structure = PacketClass.get_package_structure()
print("package structure len ", str(len(package_structure)))
log.info("package structure ", str(package_structure))
log.info("package structure len ", str(len(package_structure)))

# load data packet in Raw
scapy_variable[Raw].load = package_structure
# log.info(scapy_variable.show())
print("after load ", scapy_variable.show())
print("scapy_variable load len ", str(scapy_variable.__len__()))

# sending packets for infinite time in the interval of 1 sec
while True:
    sendp(scapy_variable)
    time.sleep(1.0)
