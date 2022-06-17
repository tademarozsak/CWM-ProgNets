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
        #print(s)
        
        #HELP command:
        if s.lower() == 'help':
            print("You have to enter a number between 1 and 9 corresponding to the following fields:\n")	
            for v in [[1,2,3],[4,5,6],[7,8,9]]:
                v1, v2, v3 = v
                print ("{:<1} {:<1} {:<1}".format(v1,v2,v3))
            print("\nIf the fields is aleady occupied or the input is invalid, you will be asked to enter another one.\nFor results and outputs please use the display on the receiving end.")
        try:
            #Check if new game should start:
            if s.lower() == "new" or s.lower() == "reset" or s.lower() == "restart" or s.lower() == "start":
                pkt = Ether(dst='00:04:00:00:00:00', type=0x1234) / tictac(new_game=1)
                pkt = pkt/' '
                #pkt.show()
                resp = srp1(pkt, iface=iface, timeout=1, verbose=False)
            #Otherwise check if input is within range, and if so, forward it
            else:
                s = int(s)
                s -= 1
                if isinstance(s, int) and s>=0 and s<=8:            
                    pkt = Ether(dst='00:04:00:00:00:00', type=0x1234) / tictac(user_input=s, new_game=0)
                    pkt = pkt/' '
                    #pkt.show()
                    resp = srp1(pkt, iface=iface, timeout=1, verbose=False)
                #If use input is outside allowed range, give warning:
                else:
                    print("Invalid input. Enter a number between 1 and 9")
        except Exception as error:
            #print(error)
            pass


if __name__ == '__main__':
    main()
