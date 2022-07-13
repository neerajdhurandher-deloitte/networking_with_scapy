import encodings

from scapy_pkg import constants, util


class PacketClass:
    # 2 bytes
    st_pack = bytearray([0xEE, 0xFF])
    # 4 bytes
    model = bytearray([0x01, 0x02, 0x03, 0x04])
    # 20 bytes
    reserved1 = bytearray([0x00] * 20)
    # 7 bytes
    byte26_32 = bytearray([0xAA, 0xBB, 0xCC, 0xDD, 0xFF, 0xAB, 0xAC])
    # 25 bytes
    reserved2 = bytearray([0x00] * 25)
    # 2 bytes
    begin_data1 = bytearray([0xFE, 0xEF])
    # 36 bytes
    msg_data = bytearray(constants.msg_str, util.get_encoding())
    assert len(msg_data) <= 36
    msg_data += bytearray([0x00] * (36 - len(msg_data)))
    # 4 bytes
    crc1 = bytearray([0x1, 0x0, 0x0, 0x1])
    # 2 bytes
    begin_data2 = bytearray([0xAF, 0xFA])
    # 48 bytes
    data2 = bytearray([0x00] * 48)
    # 4 bytes
    crc2 = bytearray([0x1, 0x0, 0x0, 0x1])
    # 6 bytes
    present_date_data = bytearray(util.getCurrentDate())
    # 4 bytes
    time_stamp = util.get_time_stamp()
    # 4 bytes
    upd_seq = constants.udp_sequence
    # 32 bytes
    sig_data = bytearray(constants.sign_msg, util.get_encoding())

    # total 221 bytes

    def get_package_structure(self):
        res = self.st_pack + self.model + self.reserved1 + self.byte26_32 + self.reserved2 + self.begin_data1 + self.msg_data + self.crc1
        res += self.begin_data2 + self.data2 + self.crc2 + self.present_date_data + self.time_stamp + self.upd_seq + self.sig_data
        # print("packet length ", len(res))

        return res
