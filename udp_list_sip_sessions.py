#!/usr/bin/python

import argparse
import time
import threading
import queue
import textwrap
import logging
import ipaddress
import inspect

from scapy.all import *

import pdb
import argparse


# --------------------------------------------------------------
# Filter out given callid from the pcap
# --------------------------------------------------------------

cmdln_parsr = argparse.ArgumentParser()
cmdln_parsr.add_argument('rx')
cmdln_parsr.add_argument('-c', required=True)

args = cmdln_parsr.parse_args()


rx = rdpcap(args.rx)
pattrn = re.compile("Call-ID:\s+{}".format(args.c))
for pkt in rx:
    if UDP in pkt and Raw in pkt:
        try: 
            pl = pkt[UDP].load.decode('utf-8')
            if pattrn.search(pl):
                print (f"{pkt[IP].id}  {pkt[IP].src}({pkt[UDP].sport}) --> {pkt[IP].dst}({pkt[UDP].dport})") 
                print (f"\n{pl}")
                print ("------------")
        except UnicodeDecodeError:
            pass




