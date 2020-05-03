import socket
import os
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
import hashlib
from features import *

serv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
serv.bind(('0.0.0.0', 8001))
serv.listen(5)


while True:
    conn, addr = serv.accept()
    while True:
        print("Waiting for client")
        data = conn.recv(4096)
        if not data: 
            print("No messages from client, exiting...")
            break
        hash_pt = data[0:128]
        h = data[128:192]
        iv = data[192:208]
        data = data[208:]
        decryption(iv,data,hash_pt,h) 

    conn.close()
    print('client disconnected')