#!/usr/bin/env python3
from collections import namedtuple
import subprocess as sp
from ipaddress import IPv4Address
import csv
from datetime import datetime
from io import StringIO
from enum import Enum, IntEnum
from dateutil.parser import isoparse
from binascii import unhexlify
import sys

class MACAddress(bytes):
    def __repr__(self):
        return ':'.join('%02x'%b for b in self)

def BitField(name, bits):
    if not hasattr(bits, 'keys'):
        bits = [(n,1<<ii) for ii,n in enumerate(bits)]
    class bf(int):
        _enum = IntEnum(name, bits)
        @classmethod
        def from_bits(cls, *values):
            return cls(sum(cls._enum[v] for v in values))
        def __repr__(self):
            if self == 0:
                return '0'
            else:
                extra = self - sum(v.value for v in self._enum if self & v.value)
                return '|'.join(v.name for v in self._enum if self & v.value) + ('|%d'%extra if extra else '')
    return bf

wlan_type = Enum('wlan_type', 'ASOCRQ ASOCRP REASRQ REASRP PROBRQ PROBRP TIMING BEACON ATIM DISASC AUTH DEAUTH ACTION ACTNOA CTWRAP BACKRQ BACK PSPOLL RTS CTS ACK CFEND CFENDK DATA DCFACK DCFPLL DCFKPL NULL CFACK CFPOLL CFCKPL QDATA QDCFCK QDCFPL QDCFKP QDNULL QCFPLL QCFKPL BADFCS VHTNDP')
packet_type = BitField('packet_type', 'CTRL MGMT DATA BADFCS BEACON PROBE ASSOC AUTH RTSCTS ACK NULL QDATA ARP IP ICMP UDP TCP OLSR BATMAN MESHZ'.split())
op_mode = BitField('op_mode', 'AP ADH STA PRB WDS UNKNOWN'.split())

_pf = ['TIME', 'WLAN TYPE', 'MAC SRC', 'MAC DST', 'BSSID', 'PACKET TYPES', 'SIGNAL', 'LENGTH', 'PHY RATE', 'FREQUENCY', 'TSF', 'ESSID', 'MODE', 'CHANNEL', 'WEP', 'WPA1', 'RSN (WPA2)', 'IP SRC', 'IP DST']
Packet = namedtuple('Packet', (s.translate({0x28:None,0x29:None,0x20:'_'}) for s in _pf))


class HorstReader:
    def __init__(self, stream):
        self.rd = csv.reader(stream, skipinitialspace=True)
        self.header = next(self.rd)
        assert self.header == _pf

    def __iter__(self):
        return self

    def __next__(self):
        r = next(self.rd)
        r[0] = isoparse(r[0].replace(' ','T',1).replace(' ',''))      # Timestamp
        r[1] = wlan_type[r[1]]                                        # WLAN type
        r[2:5] = map(lambda x: MACAddress(unhexlify(x.replace(':','')))
                     if x not in ('00:00:00:00:00:00','ff:ff:ff:ff:ff:ff')
                     else None, r[2:5])                               # MAC addresses
        r[5:10] = map(int, r[5:10])                                   # Signal, length, phy rate, frequency
        r[10] = int(r[10], 16)                                        # TSF (64-bit µs counter)
        r[11] = r[11] or None                                         # ESSID
        r[12:14] = map(int, r[12:14])                                 # Mode, channel
        r[14:17] = map(bool, r[14:17])                                # WEP, WPA1, WPA2
        r[17:19] = (None, None if r[17:19] == ['0.0.0.0','0.0.0.0']   # IP addresses
                    else map(IPv4Address, r[17:19]))

        # Convert packet type and op mode bitfields to sets of enums
        r[5] = packet_type(r[5]) # set(v for k,v in packet_type.__members__.items() if (1<<v.value) & r[5])
        r[12] = op_mode(r[12]) # set(v for k,v in op_mode.__members__.items() if (1<<v.value) & r[12])
        return Packet(*r)

hr = HorstReader(sys.stdin)
for rec in hr:
    print(rec)
