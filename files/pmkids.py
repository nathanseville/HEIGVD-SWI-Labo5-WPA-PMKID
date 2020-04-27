#!/usr/bin/env python
# -*- coding: utf-8 -*-

from scapy.all import *
from binascii import a2b_hex, b2a_hex
# from pbkdf2_math import pbkdf2_hex
#from pbkdf2 import *
from numpy import array_split
from numpy import array
import hmac, hashlib

def customPRF512(key,A,B):
    """
    This function calculates the key expansion from the 256 bit PMK to the 512 bit PTK
    """
    blen = 64
    i    = 0
    R    = b''
    while i<=((blen*8+159)/160):
        hmacsha1 = hmac.new(key,A+str.encode(chr(0x00))+B+str.encode(chr(i)),hashlib.sha1)
        i+=1
        R = R+hmacsha1.digest()
    return R[:blen]

# Read capture file -- it contains beacon, authentication, associacion, handshake and data
wpa=rdpcap('PMKID_handshake.pcap') 

# Transform mac from string with semicolon to binary string
def normalizeMac(mac):
    return a2b_hex(mac.replace(":", ""))


# Return an array of SSIDs found in packets. 
def findSSIDs(packets):
    SSIDs = []

    for packet in packets: 
        # The SSID is advertized in Beacons
        if Dot11Beacon in packet and Dot11Elt in packet[Dot11Beacon]:
            packet = packet[Dot11Beacon]
            packet = packet[Dot11Elt]
            if packet.ID == 0: # SSID
                SSIDs.append(packet.info.decode())

    return SSIDs

def findPMKIDs(packets):
    PMKIDs = {}

    for packet in packets:
        if packet.haslayer(EAPOL):
            # Tuple with PMKID, Client MAC, AP MAC
            PMKIDs[packet[Raw].load[-16:]] = (normalizeMac(packet.addr1), normalizeMac(packet.addr2))

    return PMKIDs

print(findPMKIDs(wpa))
