#!/usr/bin/python
# Author: ablil
# Description: Detect if you are under ARP Spoofing attack
# On every ARP replay received, if the sender MAC Address equals to our, we are under ATTACK

from scapy import all as scapy
import sys

class ARPSpooferDetecter:
    def __init__(self, interface=None):
        scapy.conf.verb = 0
        if interface:
            scapy.conf.iface = interface
        print("Using interface {}".format(scapy.conf.iface))

    def __get_mac(self, ip):
        pkt = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')/scapy.ARP(pdst=ip)
        ans, uns = scapy.srp(pkt, timeout=2)
        sent, received = ans[0]
        return received[scapy.Ether].src
    
    def run(self):
        print("Running and processing received ARP replies (CTRL + C to stop)  ...")
        scapy.sniff(store=False, prn=self.__process_packet)

    def __process_packet(self, pkt):
        """Query packet (ARP Replay) sender real MAC.
        if MAC is different than the MAC in the pkt, we are under ATTACK
        """

        if pkt.haslayer(scapy.ARP) and pkt[scapy.ARP].op == 2:
            try:
                real_mac = self.__get_mac(pkt[scapy.ARP].psrc)
                if real_mac != pkt[scapy.ARP].hwsrc:
                    print("You are UNDER ARP Spoofing attack")
                    print("REAL MAC: {}, FAKE MAC: {}".format(real_mac, pkt[scapy.ARP].hwsrc))
            except IndexError:
                pass

def usage():
    print("ARP Spoofer detecter")
    print("Usage: python3 {} interface".format(sys.argv[0]))
    print("")
    print("Example: ./detecter.py wlo1")
    sys.exit(1)

def main():
    try:
        if len(sys.argv[1:]) == 1:
            detecter = ARPSpooferDetecter(sys.argv[1])
            detecter.run()
        else:
            usage()
    except KeyboardInterrupt:
        pass

if __name__=='__main__':
    main()
