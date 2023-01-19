#!/bin/python
from src.vtivrt import *
import timeit

class StrSocket(object):
    def __init__(self, buf):
        self.buf = buf

    def recv(self, n):
        try:
            return self.buf[:n]
        finally:
            self.buf = self.buf[n:]

v = VtiVrtPacket(42, 0, VrtPacketType.IF_DATA_WITH_ID, VrtTimestampInteger.GPS, VrtTimestampFractional.REAL, False, trailer=0xa55aa5a5)
print(v)
print(VrtTrailer.decode(v.trailer))

s = StrSocket(struct.pack('!IIIHHffffI', 0x1C010009, 47, VTI_OUI, 9, 13, 1.2, -2.3, 3.4, -4.5, 0x00500481))
v = VtiVrtPacket.from_socket(s)
print(v)

s = StrSocket(struct.pack('!IIIHHiiii', 0x18010008, 47, VTI_OUI, 1, 1, int(1.2*(1<<24)), int(-2.3*(1<<24)), int(3.4*(1<<24)), int(-4.5*(1<<24))))
v = VtiVrtPacket.from_socket(s, 24)
print(v)
