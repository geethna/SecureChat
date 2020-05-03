import socket
import os
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
import hashlib
from features import *

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(('0.0.0.0', 8001))


while True:
    
    print("Sending to client...")
    data = input()
    print("Securing data...")
    iv,data,hash_pt,h = encryption(data)
    client.send(hash_pt.encode() + h.encode() + iv + data )
    
client.close()