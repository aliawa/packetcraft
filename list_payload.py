#!/usr/bin/python

import argparse
#import time
#import threading
#import queue
#import textwrap
import logging
#import ipaddress
#import inspect

from scapy.all import *
from sip_parser.sip_message import SipMessage

import pdb
import argparse


# --------------------------------------------------------------
# Filter out given callid from the pcap
# --------------------------------------------------------------

cmdln_parsr = argparse.ArgumentParser()
cmdln_parsr.add_argument('pcap')
cmdln_parsr.add_argument('-s', '--src')
cmdln_parsr.add_argument('-d', '--dst')
cmdln_parsr.add_argument('-sp', '--sport', type=int)
cmdln_parsr.add_argument('-dp', '--dport', type=int)
cmdln_parsr.add_argument('-p', '--proto')
cmdln_parsr.add_argument('--sip')

args = cmdln_parsr.parse_args()

def pcapfilter(args, p):
    if args.src and p[IP].src != args.src:
        return False
    if args.dst and p[IP].dst != args.dst:
        return False

    if TCP in p:
        if args.proto and args.proto.lower() != "tcp":
            return False;
        if args.sport and p[TCP].sport != args.sport:
            return False
        if args.dport and p[TCP].dport != args.dport:
            return False
    elif UDP in p:
        if args.proto and args.proto.lower() != "udp":
            return False;
        if args.sport and p[UDP].sport != args.sport:
            return False
        if args.dport and p[UDP].dport != args.dport:
            return False
    else:
        return False     # only works for UDP or TCP

    if args.sip:
        ls = args.sip.split('=')
        sip_msg = SipMessage.from_string(p[Raw].load.decode('utf-8'))
        key = ls[0].split('.')
        dkey="sip_msg.headers"
        for k in key:
            dkey += ".get('" + k + "')"
        if str(eval(dkey)).lower() != ls[1]:
            return False

    return True;


pcap = rdpcap(args.pcap).filter(lambda p: pcapfilter(args, p))

for pkt in pcap:
    if Raw in pkt:
        try: 
            print (pkt[Raw].load.decode('utf-8'))
        except UnicodeDecodeError:
            print ("-- Error --")




