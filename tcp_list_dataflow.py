#!/Users/aawais/workspace/packetcraft/scapy_venv/bin/python

import argparse
import time
import threading
import queue
import textwrap
import logging
import ipaddress
import inspect
from dataclasses import dataclass, field, InitVar
import textwrap

logging.getLogger("scapy").setLevel(logging.CRITICAL)
from scapy.all import *

import pdb
import argparse
import sys

from ruamel.yaml.representer import RoundTripRepresenter
from ruamel.yaml import YAML

# --------------------------------------------------------------
# Filter out stream from the provided rx and tx pcaps based
# the source port provided
# Dumps the client to server data
# --------------------------------------------------------------

# client   firewall  server
#   |  c2f   ||  f2s   |
#   | -----> || -----> |
#   |        ||        |
#   |  f2c   ||  s2f   |
#   | <----- || <----- |
#   |        ||        |


cmdln_parsr = argparse.ArgumentParser()
cmdln_parsr.add_argument('rx')
cmdln_parsr.add_argument('tx')
cmdln_parsr.add_argument('-pc','--clntport', type=int, required=True)
cmdln_parsr.add_argument('-ps','--srvrport', type=int, required=True)
cmdln_parsr.add_argument('-ipc','--clntip')
cmdln_parsr.add_argument('-ips','--srvrip')
cmdln_parsr.add_argument('-pcn','--clntport_n', type=int)
cmdln_parsr.add_argument('-psn','--srvrport_n', type=int)
cmdln_parsr.add_argument('-ipcn','--clntip_n')
cmdln_parsr.add_argument('-ipsn','--srvrip_n')
cmdln_parsr.add_argument('-r', '--rel-seq',  action='store_true')
cmdln_parsr.add_argument('-hdr', '--no-headers',  action='store_true')
cmdln_parsr.add_argument('-o', '--output',  choices=['flow_c2s', 'flow_s2c', 'detail_c2s', 'detail_s2c', 'scenario'], required=True)

args = cmdln_parsr.parse_args()

if not args.clntport_n:
    args.clntport_n = args.clntport
if not args.srvrip_n:
    args.srvrip_n = args.srvrip
if not args.clntip_n:
    args.clntip_n = args.clntip
if not args.srvrport_n:
    args.srvrport_n = args.srvrport

def rxfilter(args, p):
    if  TCP in p:
        if ((p[TCP].sport == args.clntport and p[TCP].dport == args.srvrport) or 
            (p[TCP].sport == args.srvrport_n and p[TCP].dport == args.clntport_n)):
            if args.clntip:
                if p[TCP].sport == args.clntport and p[IP].src != args.clntip:
                    return False
            if args.srvrip:
                if p[TCP].dport == args.srvrport and p[IP].dst != args.srvrip:
                    return False

            return True
    else:
        return False


def txfilter(args, p):
    if  TCP in p:
        if ((p[TCP].sport == args.clntport_n and p[TCP].dport == args.srvrport_n) or
            (p[TCP].sport == args.srvrport and p[TCP].dport == args.clntport)): 
            if args.clntip_n:
                if p[TCP].sport == args.clntport_n and p[IP].src != args.clntip_n:
                    return False
            if args.srvrip_n:
                if p[TCP].dport == args.srvrport_n and p[IP].dst != args.srvrip_n:
                    return False
            return True
    else:
        return False

@dataclass
class FlowState:
    complmnt: str = ""
    strt_seq: int = 0
    last_seq: int = 0
    last_len: int = 0
    expected: int = 0

    def update(self, seq, plen, ack, nxt):
        seq_flg= " "
        ack_flg= " "

        if self.strt_seq:
            if self.expected != seq:
                if self.last_seq == seq and self.last_len == plen:
                    seq_flg="+"
                else:
                    seq_flg="*"

            if Flows[self.complmnt].expected != ack:
                ack_flg= "*"
            elif self.last_seq == seq and self.last_len == plen:
                ack_flg = "+"

            self.expected = nxt
            self.last_seq = seq
            self.last_len = plen
        else:
            self.strt_seq = seq

        return (seq_flg, ack_flg)


@dataclass
class MyPackt:
    spkt: Any
    args: InitVar
    pcap: InitVar[str]
    flow: str = field(init=False)
    seq_flg: str = " "
    ack_flg: str = " "

    def __post_init__(self, args, pcap):
        if pcap == 'rx':
            if self.spkt[TCP].sport == args.clntport:
                self.flow = 'c2f'
            elif self.spkt[TCP].sport == args.srvrport_n:
                self.flow = 's2f'
        else:
            if self.spkt[TCP].dport == args.clntport:
                self.flow = 'f2c'
            elif self.spkt[TCP].dport == args.srvrport_n:
                self.flow = 'f2s'

        plen = len(self.spkt[TCP].payload) if Raw in self.spkt else 0
        self.seq_flg, self.ack_flg = Flows[self.flow].update(self.spkt[TCP].seq, 
                                                             plen,
                                                             self.spkt[TCP].ack,
                                                             self.next())

    @property
    def time(self):
        return self.spkt.time

    @property
    def len(self):
        return len(self.spkt[TCP].payload) if Raw in self.spkt else 0

    def next(self):
        if (self.spkt[TCP].flags.S or self.spkt[TCP].flags.F):
            return 1 + self.spkt[TCP].seq 
        else:
            return self.len + self.spkt[TCP].seq 

    @property
    def seq(self):
        return self.spkt[TCP].seq

    @property
    def ack(self):
        return self.spkt[TCP].ack



class pcapsItr:
    def __init__(self, args):
        rx = rdpcap(args.rx).filter(lambda p: rxfilter(args,p))
        tx = rdpcap(args.tx).filter(lambda p: txfilter(args,p))
        self.rx        = iter(rx)
        self.tx        = iter(tx)
        self.p1        = None
        self.p2        = None
        self.args      = args

    def get_next_pkt(self, pcap, side):
        try:
            return MyPackt(next(pcap), self.args, side)
        except StopIteration:
            return None


    def __iter__(self):
        return self


    def __next__(self):
        if self.p1 == None:
            self.p1 = self.get_next_pkt(self.rx, 'rx')
        if self.p2 == None:
            self.p2 = self.get_next_pkt(self.tx, 'tx')

        if self.p1 and self.p2:
            if self.p1.time <= self.p2.time:
                pkt = self.p1
                self.p1 = None
            else:
                pkt = self.p2
                self.p2 = None
        elif self.p1:
            pkt = self.p1
            self.p1 = None
        elif self.p2:
            pkt = self.p2
            self.p2 = None
        else:
            raise StopIteration

        return pkt

# return absolute or relative
# sequence-nr, next-sequence-nr and ack-nr 
# from the packet (type MyPackt)
# depending on the command-line option '-r'
def get_pkt_seqs(pkt, args):
    if args.rel_seq:
        fl = Flows[pkt.flow]
        seq = pkt.seq - fl.strt_seq  #+ 1
        nxt = pkt.next() - fl.strt_seq #+ 1
        ack = pkt.ack - Flows[fl.complmnt].strt_seq 
        return seq, nxt, ack
    else:
        return pkt.seq, pkt.next(), pkt.ack



def print_scenario(pcap, args):
    output_map = {
        'c2f': ('c2s', 'send'), 
        'f2s': ('s2c', 'recv'), 
        'f2c': ('c2s', 'recv'), 
        's2f': ('s2c', 'send') }
    output = { 'flows': {}, 'scenario' : [] }
    for p in pcap:
        pkt = p.spkt
        flow = p.flow
        plen  = p.len
        seq_s, nxt, ack = get_pkt_seqs(p, args)
        flg   = pkt.sprintf("%TCP.flags%")
        seq_e = seq_s+plen-1 if plen > 0 else seq_s

        act = { 'flow': output_map[flow][0] }

        if Raw in pkt:
            payload = pkt[Raw].load.decode('utf8')
            for r in (("\r","\\r"),("\n","\\n\n")):
                payload = payload.replace(*r)
            act['data'] = payload
        else:
            act['flags'] = flg


        output['scenario'].append( {output_map[flow][1] : act})

        if flow == 'c2f' and 'c2s' not in output['flows']:
            output['flows']['c2s'] = {}
            if TCP in pkt:
                output['flows']['c2s']['proto'] = 'tcp'
            else:
                output['flows']['c2s']['proto'] = 'udp'
            output['flows']['c2s']['src'] = pkt[IP].src
            output['flows']['c2s']['dst'] = pkt[IP].dst
            output['flows']['c2s']['sport'] = pkt[TCP].sport
            output['flows']['c2s']['dport'] = pkt[TCP].dport
        elif flow == 's2f' and 's2c' not in output['flows']:
            output['flows']['s2c'] = {}
            if TCP in pkt:
                output['flows']['s2c']['proto'] = 'tcp'
            else:
                output['flows']['s2c']['proto'] = 'udp'
            output['flows']['s2c']['src'] = pkt[IP].src
            output['flows']['s2c']['sport'] = pkt[TCP].sport

    yaml = YAML()
    yaml.representer.add_representer(str, repr_str)
    yaml.dump(output, sys.stdout)





def print_detail(pcap, args):
    with open('client.txt', 'w') as fclnt, open("server.txt", 'w') as fsrvr:
        output_map = {
                'c2f': ('-->', fclnt), 
                'f2s': ('-->', fsrvr), 
                'f2c': ('<--', fclnt), 
                's2f': ('<--', fsrvr)
        }

        for p in pcap:
            pkt = p.spkt
            flow = p.flow
            plen  = p.len
            seq_s, nxt, ack = get_pkt_seqs(p, args)
            flg   = pkt.sprintf("%TCP.flags%")
            seq_e = seq_s+plen-1 if plen > 0 else seq_s
            
            if args.output == 'detail_c2s':
                if flow == 'c2f' or flow == 'f2s':
                    if not args.no_headers:
                        print (f"{output_map[flow][0]}[{pkt[IP].id:7}, {flg:2}] seq {seq_s}-{seq_e}, len {plen}", file=output_map[flow][1])
                    if Raw in pkt:
                        payload = pkt[Raw].load.decode('utf8').split("\n")
                        for l in payload:
                            print (f"    {l}", file=output_map[flow][1])
                        print (file=output_map[flow][1])
                elif flow == 'f2c' or flow == 's2f':
                    if not args.no_headers:
                        print (f"{output_map[flow][0]}[{pkt[IP].id:7}, {flg:2}] ack {ack}", file=output_map[flow][1])
            elif args.output == 'detail_s2c':
                if flow == 'f2c' or flow == 's2f':
                    if not args.no_headers:
                        print (f"{output_map[flow][0]}[{pkt[IP].id:7}, {flg:2}] seq {seq_s}-{seq_e}, len {plen}", file=output_map[flow][1])
                    if Raw in pkt:
                        payload = pkt[Raw].load.decode('utf8').split("\n")
                        for l in payload:
                            print (f"    {l}", file=output_map[flow][1])
                        print (file=output_map[flow][1])
                elif flow == 'c2f' or flow == 'f2s':
                    if not args.no_headers:
                        print (f"{output_map[flow][0]}[{pkt[IP].id:7}, {flg:2}] ack {ack}", file=output_map[flow][1])



def print_flow(pcap, args):
    output_map = {
            'c2f': ("",              " -->|"), 
            'f2s': (41*" "+"|-->",   ""     ), 
            'f2c': ("",              "<--|"), 
            's2f': (41*" "+"|<--",   ""     ) 
    }

    for ed in ['','\n']:
        print (f" {'id':>7} {'seq':>10} {'len':>5} {'next':>10} {' '*7}", end=ed)
    for ed in ['','\n']:
        print (f" {'----':>7} {'----':>10} {'----':>5} {'----':>10} {' '*7}", end=ed)

    for p in pcap:
        pkt = p.spkt
        flow = p.flow
        plen = p.len

        seq, nxt, ack = get_pkt_seqs(p, args)
        pre = output_map[flow][0]
        post = output_map[flow][1]

        if args.output == 'flow_c2s':
            if flow == 'c2f' or flow == 'f2s':
                print (f"{pre}{pkt[IP].id:7} {seq:10}{p.seq_flg} {plen:5} {nxt:10} {post}")
            elif flow == 'f2c' or flow == 's2f':
                gap = " "
                print (f"{pre}{pkt[IP].id:7} {gap:10} {gap:6} {ack:10}{p.ack_flg} {post}")
        elif args.output == 'flow_s2c':
            if flow == 'f2c' or flow == 's2f':
                print (f"{pre}{p.seq_flg}{pkt[IP].id:7} {seq:10}{p.seq_flg} {plen:5} {nxt:10} {post}")
            elif flow == 'c2f' or flow == 'f2s':
                gap = " "
                print (f"{pre}{pkt[IP].id:7} {gap:10} {gap:6} {ack:10}{p.ack_flg} {post}")
        else:
            print ("Unknown output type")



def repr_str(dumper: RoundTripRepresenter, data: str):
    if '\n' in data:
        return dumper.represent_scalar('tag:yaml.org,2002:str', data, style='|')
    return dumper.represent_scalar('tag:yaml.org,2002:str', data)

# ----------------------------------------------------------------------
#                                 MAIN
# ----------------------------------------------------------------------

# Global Flow state database
Flows = {'c2f': FlowState('f2c'),
         'f2c': FlowState('c2f'),
         'f2s': FlowState('s2f'),
         's2f': FlowState('f2s')}

# Global pcap iterator
pcapIter = pcapsItr(args)


if args.output == 'flow_c2s' or args.output == 'flow_s2c':
    print_flow(iter(pcapIter), args )
elif args.output == 'detail_c2s' or args.output == 'detail_s2c':
    print_detail(iter(pcapIter), args)
elif args.output == 'scenario':
    print_scenario(iter(pcapIter), args)

