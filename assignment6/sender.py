#!/usr/bin/env python3
#SENDER

import argparse
import sys
import socket
import random
import struct
import re

from scapy.all import sendp, send, srp1
from scapy.all import Packet, hexdump
from scapy.all import Ether, StrFixedLenField, XByteField, IntField
from scapy.all import bind_layers
import readline

class tictac(Packet):
    name = "tictac"
    fields_desc = [ IntField("user_input", 0),
                    IntField("new_game", 0),
                    IntField("is_valid", 0),
                    IntField("field0", 0),
                    IntField("field1", 0),
                    IntField("field2", 0),
                    IntField("field3", 0),
                    IntField("field4", 0),
                    IntField("field5", 0),
                    IntField("field6", 0),
                    IntField("field7", 0),
                    IntField("field8", 0)]

bind_layers(Ether, tictac, type=0x1234)



def main():

    s = ''
    iface = 'eth0'

    while True:
        s = input('> ')
        if s == "quit":
            break
        print(s)

        try:
            if s == "new" or s == "reset":
                pkt = Ether(dst='00:04:00:00:00:00', type=0x1234) / tictac(new_game=1)
                pkt = pkt/' '
                pkt.show()
                resp = srp1(pkt, iface=iface, timeout=1, verbose=False)
            else:
                s = int(s)
                if isinstance(s, int) and s>=0 and s<=8:            
                    pkt = Ether(dst='00:04:00:00:00:00', type=0x1234) / tictac(user_input=s, new_game=0)
                    pkt = pkt/' '
                    pkt.show()
                    resp = srp1(pkt, iface=iface, timeout=1, verbose=False)
                else:
                    print("Invalid input. Enter a number between 0 and 9")
        except Exception as error:
            print(error)


if __name__ == '__main__':
    main()
