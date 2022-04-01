#!/usr/bin/env python
# coding: utf-8
'''
Project 10 03/2022
@Witch_Sec
https://github.com/miss-anthrope
-
Class: https://www.udemy.com/course/python-for-pentesters (Credit to Cristi Zot https://www.udemy.com/user/cristivlad2/)
'''
#Hidden WiFi Network hunting for signals obfuscating the SSID
print("Be vewwy vewwy quiet. I'm hunting WiFi!")

from scapy.all import *
import os

iface="wlan0"

def h_packet(packet):
	if packet.haslayer(Dot11ProbeReq) or packet.haslayer(Dot11ProbeResp) or packet.haslayer(Dot11AssoReq):
		print("SSID identified! "+packet.info)

os.system("iwconfig",+iface+"mode monitor")

print("Sniffing traffic on interface "+iface)
sniff(iface=iface,prn=h_packet)

print("\nNow go clean your ports. Disgusting.")

