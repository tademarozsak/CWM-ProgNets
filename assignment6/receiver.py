#!/usr/bin/env python3
#RECEIVER

import argparse
import sys
import socket
import random
import struct
import re
from scapy.all import *
from scapy.all import sendp, send, srp1
from scapy.all import Packet, hexdump
from scapy.all import Ether, StrFixedLenField, XByteField, IntField
from scapy.all import bind_layers
import readline
import time

class tictac(Packet):
    name = "tictac"
    fields_desc = [ IntField("user_input", 0),
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
        time.sleep(0.5)
        try:
            resp = sniff(filter = "ether dst 00:04:00:00:00:00", iface=iface,count = 2, timeout=10)
            print(resp)
        except Exception as error:
            print(error)


if __name__ == '__main__':
    main()
