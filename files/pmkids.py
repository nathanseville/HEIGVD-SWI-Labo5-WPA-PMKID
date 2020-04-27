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

# Transform mac from string with semicolon to binary string
def normalizeMac(mac):
    return a2b_hex(mac.replace(":", ""))

# Return an array of SSIDs found in packets. 
def findSSID(packets, apmac):
    for packet in packets: 
        # The SSID is advertized in Beacons
        if Dot11Beacon in packet and Dot11Elt in packet[Dot11Beacon] and packet.addr2 == apmac:
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
            ssid = findSSID(packets, packet.addr2)
            if ssid != None
                PMKIDs[ssid] = (packet[Raw].load[-16:], normalizeMac(packet.addr1), normalizeMac(packet.addr2))

    return PMKIDs

def wordCombinations(words, n):
    return list(itertools.combinations(words, n))

def PMKID(key, ssid, staMAC, apMAC):
    key = pbkdf2(hashlib.sha1, key, ssid, 4096, 32)
    return hmac.new(key,str.encode('PMK Name'+str(apMAC)+str(staMAC)),hashlib.sha1).digest()[:16]

# Read dictionnary words
words = [line.rstrip() for line in open('wordlist.txt', 'r')]

# Max combinations of words
maxc = int(input("Enter maximum words combinations [Int]: "))

APs = findPMKIDs(wpa)

for ssid in APs:
    for i in range(1, maxc+1):
        for key in wordCombinations(words, i):
            pmkid, stamac, apmac = APs[ssid]
            
            #print(key)
            #print(str.encode(''.join(key)))
            #print(str.encode(ssid))
            if 'admin123' in ''.join(key):
                print(ssid)
                print(''.join(key))
                print(PMKID(str.encode(''.join(key)), str.encode(ssid), stamac, apmac))
                print(pmkid)

            if pmkid == PMKID(str.encode(''.join(key)), str.encode(ssid), stamac, apmac):
                print("Found passphrase ", word, " for AP ", ssid)
                break
            
