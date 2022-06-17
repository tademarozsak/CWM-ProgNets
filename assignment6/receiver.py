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



def get_response(iface):
    resp2 = sniff(filter = "ether dst 00:04:00:00:00:00", iface=iface,count = 2, timeout=10)
    return resp2[1]



def output_table(hdr):
    #Create table from the header file containing all the fields, arranged in a list:
    matrix =[hdr.field0,hdr.field1,hdr.field2,hdr.field3,hdr.field4,hdr.field5,hdr.field6,hdr.field7,hdr.field8]
    
    #Set winner to no one. If someone did win, we'll update this
    winner = 0
    	
    #If there is no field left, the game is over:
    if (0 in matrix):
    	gameover = 0
    else:
    	gameover = 1
    	
    
    #Check if someone has won:
    symbols = [1,2]
    for symbol in symbols:
	    if matrix[0:3].count(symbol) == 3 or matrix[3:6].count(symbol) == 3 or matrix[6:9].count(symbol) == 3 or matrix[0:9:3].count(symbol) == 3 or matrix[1:9:3].count(symbol) == 3 or matrix[2:9:3].count(symbol) == 3 or matrix[0:9:4].count(symbol) == 3 or matrix[2:7:2].count(symbol) == 3:
	    	gameover = 1
	    	winner = symbol
    
    
    """
    matrix[0:3].count(symbol) == 3
    matrix[3:6].count(symbol) == 3
    matrix[6:9].count(symbol) == 3
    
    matrix[0:9:3].count(symbol) == 3
    matrix[1:9:3].count(symbol) == 3
    matrix[2:9:3].count(symbol) == 3
    
    matrix[0:9:4].count(symbol) == 3
    matrix[2:7:2].count(symbol) == 3
    """
    
    #Replace the numbers with symbols for display and change matrix to a more easily displayable format	
    matrix = ['•' if item == 0 else 'o' if item == 2 else 'x' if item == 1 else item for item in matrix]
    matrix = [matrix[0:3],matrix[3:6],matrix[6:9]]
    
    #If a new game has started, print that out:
    if hdr.new_game == 1:
    	print("New game started.\nRemember, you are X.\n\nField numbering:")
    	for v in [[1,2,3],[4,5,6],[7,8,9]]:
            v1, v2, v3 = v
            print ("{:<1} {:<1} {:<1}".format(v1,v2,v3))
    	print ('\n')
    	
    #Display the current table:
    for v in matrix:
        v1, v2, v3 = v
        print ("{:<1} {:<1} {:<1}".format(v1,v2,v3))
    print ('\n')
    
    #If game is finished, let the user know:
    if gameover:
        if winner == 0:
            print("No winner\n")
        if winner == 1:
            print("You won!\n")
        if winner == 2:
            print("You lost!\n")
        print("The game has finished. Enter either 'new' / 'reset' / 'start' / 'restart' to start another one!\n\n")
    	



def main():

    s = ''
    iface = 'eth0'

    while True:
        time.sleep(0.5)
        try:
            resp = get_response(iface)
            if resp:
                hdr = resp[tictac]
                if hdr:
                    if hdr.is_valid == 1:
                        #resp.show()
                        output_table(hdr)
                    else:
                        print("Invalid input (field already occupied); enter a different number")
                else:
                    print("Cannot find tictac header in the packet")
            else:
                print("Didn't receive response")

        except Exception as error:
            #print(error)
            pass


if __name__ == '__main__':
    main()
