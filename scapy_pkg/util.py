import array
import encodings
import time
from datetime import date
import logging


def get_logger_obj():
    logging.basicConfig(filename="networking_scapy.log",
                        format='%(asctime)s %(message)s',
                        filemode='w')
    log = logging.getLogger()
    log.setLevel(logging.INFO)
    return log

def getCurrentDate():
    present_day = date.today().timetuple()
    present_day_array = [present_day.tm_year - 1900, present_day.tm_mon,
                         present_day.tm_mday, present_day.tm_hour,
                         present_day.tm_min, present_day.tm_sec
                         ]

    return present_day_array


def get_time_stamp():
    time_stamp = bytearray(time.time().hex(), get_encoding())
    return time_stamp


def get_encoding():
    return encodings.normalize_encoding("utf-8")
