#!/usr/bin/python
# Author: ablil
# Description: ARP scanner

from scapy import all as scapy
import sys
import ipaddress
import argparse
import netifaces
import netaddr
import collections
import threading

class ARPScanner:

    def __init__(self, interface, isPassive=False):
        scapy.conf.verb = 0
        scapy.conf.iface = interface
        self.mode = isPassive
        self.scanned_mac = set()
        self.scanned_ip = set()
        self.THREAD_MAX = 50
        self.gateway = self.__get_gateway()

        print("Using interface {} in {} mode".format(
            scapy.conf.iface, 'ACTIVE' if self.mode else 'PASSIVE'))

        print("Default gateway: {}".format(self.gateway))

    def run(self):
        if self.mode:
            iprange = self.__get_current_ip_range()

            for i in range(self.THREAD_MAX):
                th = threading.Thread(target=self.__process_ip, args=(iprange, ))
                th.start()
        else:
            scapy.sniff(store=False, prn=self.__process_packet)

    def __process_ip(self, queue):
        """request all hosts on the network by sending ARP requests"""
        while queue:
            ip = queue.pop()
            mac = self.__get_mac(ip)
            if mac not in self.scanned_mac:
                print("MAC: {}, IP: {}".format(mac, ip))
                self.scanned_mac.add(mac)

    def __process_packet(self, pkt):
        """Extract info from sniffer ARP packet
        If packet is request, capture the requested ip and ask it yourself
        If packet is response, extract info only
        """

        if pkt.haslayer(scapy.ARP) and pkt[scapy.ARP].op == 2:
            mac = pkt[scapy.ARP].hwsrc
            ip = pkt[scapy.ARP].psrc

            if mac not in self.scanned_mac:
                print("MAC: {}, IP: {}".format(mac, ip))
                self.scanned_mac.add(mac)

        if pkt.haslayer(scapy.ARP) and pkt[scapy.ARP].op == 1:
            requested_ip = pkt[scapy.ARP].pdst
            if requested_ip not in self.scanned_ip and requested_ip != self.gateway:
                self.scanned_ip.add(requested_ip)
                mac = self.__get_mac(requested_ip)
                if mac not in self.scanned_mac:
                    print("MAC: {}, IP: {}".format(mac, requested_ip))
                    self.scanned_mac.add(mac)


    def __get_mac(self, ip):
        try:
            pkt = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')/scapy.ARP(pdst=ip)
            ans, uns = scapy.srp(pkt, timeout=2)
            sent, received = ans[0]
            return received[scapy.Ether].src
        except IndexError:
            return None
    
    def __get_gateway(self):
        info = netifaces.gateways()
        for k in info.keys():
            if k != 'default':
                for item in info[k]:
                    if item[1] == scapy.conf.iface:
                        return item[0]

        return None


    def __get_current_ip_range(self):
        """get all current address in the current network range"""
        ipaddr = netifaces.ifaddresses('wlo1')[2][0]['addr']
        mask = netifaces.ifaddresses('wlo1')[2][0]['netmask']
        network_addr = netaddr.IPNetwork(ipaddr + "/" + mask).cidr
        ip_queue = collections.deque(ipaddress.ip_network(network_addr).hosts())
        return ip_queue

def usage():
    parser = argparse.ArgumentParser(description=sys.argv[0])
    parser.add_argument("iface", help="network interface")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('-a', '--active', action='store_true', help='active scan mode')
    mode.add_argument('-p', '--passive', action='store_true', help='passive scan mode')
    args = parser.parse_args()

    interface = args.iface
    mode = True if args.active else False

    return (interface, mode)

def main():
    interface, mode = usage()
    scanner = ARPScanner(interface, mode)
    scanner.run()

if __name__=='__main__':
    main()
