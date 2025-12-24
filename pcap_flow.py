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
from pathlib import Path

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


def rxfilter_tcp(args, p):
    if  TCP in p:
        if (p[IP].src == args.clntip and p[TCP].sport == args.clntport) or (p[IP].dst == args.clntip_n and p[TCP].dport == args.clntport_n) :
            return True
    return False

def txfilter_tcp(args, p):
    if  TCP in p:
        if (p[IP].src == args.clntip_n and p[TCP].sport == args.clntport_n) or (p[IP].dst == args.clntip and p[TCP].dport == args.clntport) :
            return True
    return False

def rxfilter_udp(args, p):
    if  UDP in p:
        if (p[IP].src == args.clntip and p[UDP].sport == args.clntport) or (p[IP].dst == args.clntip_n and p[UDP].dport == args.clntport_n) :
            return True
    return False

def txfilter_udp(args, p):
    if  UDP in p:
        if (p[IP].src == args.clntip_n and p[UDP].sport == args.clntport_n) or (p[IP].dst == args.clntip and p[UDP].dport == args.clntport) :
            return True
    return False


@dataclass
class FlowState:
    name: str = ""
    complmnt: str = ""
    strt_seq: int = 0
    last_seq: int = 0
    last_len: int = 0
    expected: int = 0
    flg_init: int = 0

    # def update(self, seq, plen, ack, nxt):
    def update(self, pkt, nxt):
        seq_flg= " "
        ack_flg= " "
        if TCP in pkt:
            cur_plen = len(pkt[TCP].payload) if Raw in pkt else 0
            cur_seq  = pkt[TCP].seq
            cur_ack  = pkt[TCP].ack
        else:
            cur_plen = len(pkt[UDP].payload) if Raw in pkt else 0
            cur_seq  = 0
            cur_ack  = 0

        if self.flg_init:
            if self.expected != cur_seq:
                if self.last_seq == cur_seq and self.last_len == cur_plen and self.last_ack == cur_ack:
                    seq_flg="+" # retransmission
                else:
                    seq_flg="*" # out of sequence
            else:
                self.expected = nxt
                self.last_len = cur_plen
                self.last_seq = cur_seq
                self.last_ack = cur_ack


            if Flows[self.complmnt].expected != cur_ack:
                ack_flg= "*"    # wrong ack number
                

        else:
            self.strt_seq = cur_seq
            self.flg_init = 1
            self.expected = nxt
            self.last_len = cur_plen
            self.last_seq = cur_seq
            self.last_ack = cur_ack

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
        sport = None
        dport = None
        if TCP in self.spkt:
            sport = self.spkt[TCP].sport 
            dport = self.spkt[TCP].dport 
        elif UDP in self.spkt:
            sport = self.spkt[UDP].sport 
            dport = self.spkt[UDP].dport 

        if pcap == 'rx':
            if sport == args.clntport and self.spkt[IP].src == args.clntip:
                self.flow = 'c2f'
            elif dport == args.clntport_n and self.spkt[IP].dst == args.clntip_n:
                self.flow = 's2f'
        else:
            if sport == args.clntport_n and self.spkt[IP].src == args.clntip_n:
                self.flow = 'f2s'
            elif dport == args.clntport and self.spkt[IP].dst == args.clntip:
                self.flow = 'f2c'


    @property
    def time(self):
        return self.spkt.time

    @property
    def len(self):
        if TCP in self.spkt:
            return self.spkt[IP].len - (self.spkt[IP].ihl*4) - (self.spkt[TCP].dataofs*4)
            # return len(self.spkt[TCP].payload) if Raw in self.spkt else 0
        else:
            return len(self.spkt[UDP].payload) if Raw in self.spkt else 0

    def next(self):
        if TCP in self.spkt:
            if (self.spkt[TCP].flags.S or self.spkt[TCP].flags.F):
                return 1 + self.spkt[TCP].seq 
            else:
                return self.len + self.spkt[TCP].seq 
        else:
            return 0

    @property
    def seq(self):
        if TCP in self.spkt:
            return self.spkt[TCP].seq
        else:
            return 0

    @property
    def ack(self):
        if TCP in self.spkt:
            return self.spkt[TCP].ack
        else:
            return 0



class pcapsItr:
    def __init__(self, args):
        if args.proto == "udp":
            rx = rdpcap(args.rx).filter(lambda p: rxfilter_udp(args,p))
            tx = rdpcap(args.tx).filter(lambda p: txfilter_udp(args,p))
        else:
            rx = rdpcap(args.rx).filter(lambda p: rxfilter_tcp(args,p))
            tx = rdpcap(args.tx).filter(lambda p: txfilter_tcp(args,p))
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


        pkt.seq_flg, pkt.ack_flg = Flows[pkt.flow].update(pkt.spkt, pkt.next())
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
        # flg   = pkt.sprintf("%TCP.flags%")
        seq_e = seq_s+plen-1 if plen > 0 else seq_s

        act = { 'flow': output_map[flow][0] }

        if Raw in pkt:
            payload = pkt[Raw].load.decode('utf8')
            for r in (("\r","\\r"),("\n","\\n\n")):
                payload = payload.replace(*r)
            act['data'] = payload
        elif TCP in pkt:
            act['flags'] = pkt.sprintf("%TCP.flags%")


        output['scenario'].append( {output_map[flow][1] : act})

        if flow == 'c2f' and 'c2s' not in output['flows']:
            output['flows']['c2s'] = {}
            output['flows']['c2s']['src'] = pkt[IP].src
            output['flows']['c2s']['dst'] = pkt[IP].dst
            if TCP in pkt:
                output['flows']['c2s']['proto'] = 'tcp'
                output['flows']['c2s']['sport'] = pkt[TCP].sport
                output['flows']['c2s']['dport'] = pkt[TCP].dport
            else:
                output['flows']['c2s']['proto'] = 'udp'
                output['flows']['c2s']['sport'] = pkt[UDP].sport
                output['flows']['c2s']['dport'] = pkt[UDP].dport

        elif flow == 's2f' and 's2c' not in output['flows']:
            output['flows']['s2c'] = {}
            if TCP in pkt:
                output['flows']['s2c']['proto'] = 'tcp'
                output['flows']['s2c']['src'] = pkt[IP].src
                output['flows']['s2c']['sport'] = pkt[TCP].sport
            else:
                output['flows']['s2c']['proto'] = 'udp'
                output['flows']['s2c']['src'] = pkt[IP].src
                output['flows']['s2c']['sport'] = pkt[UDP].sport

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
            'c2f': ( 2*" ",           "-->|"), 
            'f2s': (42*" "+"|-->",    ""    ), 
            'f2c': ( 2*" ",           "<--|"), 
            's2f': (42*" "+"|<--",    ""    ) 
    }

    for ed in ['','\n']:
        print (f"{'id':>8}{'seq':>11}{'len':>7}{'next':>11}{' '*7}", end=ed)
    for ed in ['','\n']:
        print (f"{'----':>8}{'----':>11}{'----':>7}{'----':>11}{' '*7}", end=ed)

    for p in pcap:
        pkt = p.spkt
        flow = p.flow
        plen = p.len

        seq, nxt, ack = get_pkt_seqs(p, args)
        pre = output_map[flow][0]
        post = output_map[flow][1]

        if args.output == 'flow_c2s':
            if flow == 'c2f' or flow == 'f2s':
                print (f"{pre}{pkt[IP].id:6} {seq:10}{p.seq_flg} {plen:5} {nxt:10}  {post}")
            elif flow == 'f2c' or flow == 's2f':
                gap = 19*" "
                print (f"{pre}{pkt[IP].id:6}{gap}{ack:10}{p.ack_flg} {post}")
        elif args.output == 'flow_s2c':
            if flow == 'f2c' or flow == 's2f':
                print (f"{pre}{pkt[IP].id:6} {seq:10}{p.seq_flg} {plen:5} {nxt:10}  {post}")
            elif flow == 'c2f' or flow == 'f2s':
                gap = 19*" "
                print (f"{pre}{pkt[IP].id:6}{gap}{ack:10}{p.ack_flg} {post}")
        else:
            print ("Unknown output type")



def repr_str(dumper: RoundTripRepresenter, data: str):
    if '\n' in data:
        return dumper.represent_scalar('tag:yaml.org,2002:str', data, style='|')
    return dumper.represent_scalar('tag:yaml.org,2002:str', data)

# ----------------------------------------------------------------------
#                                 MAIN
# ----------------------------------------------------------------------

cmdln_parsr = argparse.ArgumentParser()
cmdln_parsr.add_argument('rx')
cmdln_parsr.add_argument('tx')
cmdln_parsr.add_argument('-p','--proto', choices=['udp','tcp'])
cmdln_parsr.add_argument('-pc','--clntport', type=int, required=True)
cmdln_parsr.add_argument('-ps','--srvrport', type=int)
cmdln_parsr.add_argument('-ipc','--clntip', required=True)
cmdln_parsr.add_argument('-ips','--srvrip')
cmdln_parsr.add_argument('-pcn','--clntport_n', type=int)
cmdln_parsr.add_argument('-psn','--srvrport_n', type=int)
cmdln_parsr.add_argument('-ipcn','--clntip_n')
cmdln_parsr.add_argument('-ipsn','--srvrip_n')
cmdln_parsr.add_argument('-r', '--rel-seq',  action='store_true')
cmdln_parsr.add_argument('-hdr', '--no-headers',  action='store_true')
cmdln_parsr.add_argument('-o', '--output',  choices=['flow_c2s', 'flow_s2c', 'detail_c2s', 'detail_s2c', 'scenario'], required=True)

args = cmdln_parsr.parse_args()



if not Path(args.rx).is_file():
    print(f"Error: {args.rx} not found")
    exit()
if not Path(args.tx).is_file():
    print(f"Error: {args.tx} not found")
    exit()

if not args.clntport_n:
    args.clntport_n = args.clntport
if not args.srvrip_n:
    args.srvrip_n = args.srvrip
if not args.clntip_n:
    args.clntip_n = args.clntip
if not args.srvrport_n:
    args.srvrport_n = args.srvrport


# Global Flow state database
Flows = {'c2f': FlowState('c2f', 'f2c'),
         'f2c': FlowState('f2c', 'c2f'),
         'f2s': FlowState('f2s', 's2f'),
         's2f': FlowState('s2f', 'f2s')}

# Global pcap iterator
pcapIter = pcapsItr(args)


if args.output == 'flow_c2s' or args.output == 'flow_s2c':
    print_flow(iter(pcapIter), args )
elif args.output == 'detail_c2s' or args.output == 'detail_s2c':
    print_detail(iter(pcapIter), args)
elif args.output == 'scenario':
    print_scenario(iter(pcapIter), args)

