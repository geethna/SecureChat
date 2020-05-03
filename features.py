import socket
import os
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
import hashlib

def encryption(data):
    iv,ct = AES_encrypt(data)            #AES encryption for confidentiality 
    hash_pt = hash(data)                 #SHA-512 has for integrity
    h = auth(data)                       #HMAC for message authentication
    return iv,ct,hash_pt,h


def decryption(iv,data,hash,h):
    pt = AES_decrypt(iv,data)           #AES encryption for confidentiality 
    check_hash(pt,hash)                 #SHA-512 has for integrity
    check_auth(h,pt)                       #HMAC for message authentication
    return pt

def padding(s):
    b = 16
    s += chr( b - (len(s)%b)) * (b-(len(s)%b))
    return s

def AES_encrypt(data):
    key = b'\xea\xf1\xb4\x03\x951\x03~b\x93\xf9/\xcd\x92\\\x86'
    iv  = os.urandom(16)
    data = padding(data)
    aes = AES.new(key, AES.MODE_CBC, iv)
    ct = aes.encrypt(data.encode())
    return iv,ct

def AES_decrypt(iv,data):
    key = b'\xea\xf1\xb4\x03\x951\x03~b\x93\xf9/\xcd\x92\\\x86'
    aes = AES.new(key, AES.MODE_CBC, iv)
    pt = aes.decrypt(data)
    pt = pt[:-pt[-1]]
    return pt

def hash(ct):
    hash = hashlib.sha512(ct.encode())
    hash = hash.hexdigest()
    return hash

def check_hash(pt,hash):
    hash_txt = hashlib.sha512(pt)
    hash_txt = hash_txt.hexdigest().encode()
    if(hash == hash_txt):
        print("The plaintext is same! Integrity is ensured")
    else:
        print("No")

def auth(pt):
    secret = b'Swordfish'
    h = HMAC.new(secret, digestmod=SHA256)
    h.update(pt.encode())
    return h.hexdigest()

def check_auth(mac,msg):
    secret = b'Swordfish'
    h = HMAC.new(secret, digestmod=SHA256)
    h.update(msg)
    try:
      h.hexverify(mac)
      print("The message '%s' is authentic" % msg)
    except ValueError:
      print("The message or the key is wrong")

