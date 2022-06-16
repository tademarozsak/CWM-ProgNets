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
                    IntField("field8", 0),
                    IntField("is_valid", 0)]

bind_layers(Ether, tictac, type=0x1234)



def main():

    s = ''
    iface = 'eth0'

    while True:
        time.sleep(0.5)
        try:
            resp2 = sniff(filter = "ether dst 00:04:00:00:00:00", iface=iface,count = 2, timeout=10)
            resp = resp2[1]
            if resp:
                var1=resp[tictac]
                if var1:
                    #resp.show()
                    table = [[var1.field0,var1.field1,var1.field2],[var1.field3,var1.field4,var1.field5],[var1.field6,var1.field7,var1.field8]]
                    matrix =[var1.field0,var1.field1,var1.field2,var1.field3,var1.field4,var1.field5,var1.field6,var1.field7,var1.field8]
                    matrix = ['•' if item == 0 else 'o' if item == 2 else 'x' if item == 1 else item for item in matrix]
                    matrix = [matrix[0:3],matrix[3:6],matrix[6:9]]
                    for v in matrix:
                    	v1, v2, v3 = v
                    	print ("{:<1} {:<1} {:<1}".format(v1,v2,v3))
                    	
                    print ('\n\n')
                    # print(var1.is_valid)
                    
                else:
                    print("cannot find P4calc header in the packet")
            else:
                print("Didn't receive response")

        except Exception as error:
            #print(error)
            pass


if __name__ == '__main__':
    main()
