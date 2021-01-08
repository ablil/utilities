#!/usr/bin/python
# Author: ablil
# Date: 2021-01-08
# Description: sniff and process http packet (not https)

from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy import all as scapy
import argparse

class HTTPDecoder:
    def __init__(self, pkt, req=False):
        self.req = req
        self.pkt = pkt 

    def run(self):
        if self.req:
            self.__process_request()
        else:
            self.__process_response()

    def __process_request(self):
        pkt = self.pkt[HTTPRequest]

        url =  f"{pkt.Host.decode()}/{pkt.Path.decode()}"
        method = pkt.Method.decode()
        print(f"\t\33[41mRequest\33[0m: {method} -> {url}")

        if pkt.Authorization:
            print(f"\tAuthorization: {pkt.Authorization.decode()}")
        
        if content_type := pkt.Content_Type:
            print(f"\tContent-Type: {pkt.Content_Type.decode()}")
            if content_type.decode() in ('application/json', 'multipart/form-data'):
                print(f"\tPayload: {self.pkt[scapy.Raw].load}")


    
    def __process_response(self):
        pkt = self.pkt[HTTPResponse]

        print(f"\t\33[42mResponse\33[0m: {pkt.Status_Code.decode()}")
        if content_type := pkt.Content_Type:
            print(f"\tContent-Type: {pkt.Content_Type.decode()}")
            if content_type.decode() in ('application/json'):
                print(f"\tPayload: {self.pkt[scapy.Raw].load}")


class HTTPSniffer:
    def __init__(self, iface):
        scapy.conf.verb = 0
        if iface:
            scapy.conf.iface = iface

        self.domainname_cache = dict() # Client with domain name
        self.client_cache = dict()  # Client without domain name

    def run(self):
       """Run the sniffing"""
       print("Using interface {}".format(scapy.conf.iface))
       print("Sniffing http packets ...")
       scapy.sniff(prn=self.__process_packet, filter="port 80 or port 8080", store=0)

    def __process_packet(self, pkt):
        if pkt.haslayer(HTTPRequest) or pkt.haslayer(HTTPResponse):
            src = pkt[scapy.IP].src
            srcport = pkt[scapy.IP].sport
            dst = pkt[scapy.IP].dst
            dstport = pkt[scapy.IP].dport
            proto = 'TCP' if pkt[scapy.IP].proto == 6 else 'UDP'
            print(f"{src}:{srcport} --({proto})---> {dst}:{dstport}")

        if pkt.haslayer(HTTPRequest):
            http_decoder = HTTPDecoder(pkt, True)
            http_decoder.run()
        
        if pkt.haslayer(HTTPResponse):
            http_decoder = HTTPDecoder(pkt, False)
            http_decoder.run()

def usage():
    parser = argparse.ArgumentParser(description='Http packet sniffer')
    parser.add_argument('iface', help='Interface')
    args = parser.parse_args()
    return args.iface

def main():
    iface = usage()
    sniffer = HTTPSniffer(iface)
    sniffer.run()

if __name__=='__main__':
    main()

