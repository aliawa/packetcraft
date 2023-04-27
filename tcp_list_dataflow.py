#!/Users/aawais/workspace/scapy/py_venv/bin/python

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
cmdln_parsr.add_argument('-pcn','--clntport_n')
cmdln_parsr.add_argument('-psn','--srvrport_n')
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

# keep track of star sequences here
start_seq = {}


def rxfilter(args, p):
    if  TCP in p:
        if ((p[TCP].sport == args.clntport and p[TCP].dport == args.srvrport_n) or 
                (p[TCP].sport == args.srvrport_n and p[TCP].dport == args.clntport)): 
            # ports match
            if args.clntip:
                if p[IP].src != args.clntip and p[IP].dst != args.clntip:
                    return False
            if args.srvrip:
                if p[IP].src != args.srvrip_n and p[IP].dst != args.srvrip_n:
                    return False
            return True
    else:
        return False


def txfilter(args, p):
    if  TCP in p:
        if ((p[TCP].sport == args.clntport_n and p[TCP].dport == args.srvrport) or
            (p[TCP].sport == args.srvrport and p[TCP].dport == args.clntport_n)): 
                # ports match
                if args.clntip_n:
                    if p[IP].src != args.clntip_n and p[IP].dst != args.clntip_n:
                        return False
                if args.srvrip:
                    if p[IP].src != args.srvrip and p[IP].dst != args.srvrip:
                        return False
                return True
    else:
        return False

@dataclass
class MyPackt:
    spkt: Any
    expected: InitVar
    pcap: InitVar
    args: InitVar
    flow: str = field(init=False)
    inseq: bool = field(init=False)

    def __post_init__(self, expected, pcap, args):
        if pcap == 'rx':
            if self.spkt[TCP].sport == args.clntport:
                self.flow = 'c2f'
                if 'c2f' not in start_seq:
                    start_seq['c2f'] = self.spkt[TCP].seq
            elif self.spkt[TCP].sport == args.srvrport:
                self.flow = 's2f'
                if 's2f' not in start_seq:
                    start_seq['s2f'] = self.spkt[TCP].seq
        else:
            if self.spkt[TCP].dport == args.clntport_n:
                self.flow = 'f2c'
                if 'f2c' not in start_seq:
                    start_seq['f2c'] = self.spkt[TCP].seq
            elif self.spkt[TCP].dport == args.srvrport_n:
                self.flow = 'f2s'
                if 'f2s' not in start_seq:
                    start_seq['f2s'] = self.spkt[TCP].seq

        self.inseq = True
        if expected and self.flow in expected and self.spkt[TCP].seq != expected[self.flow]:
            self.inseq = False

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
        # print(len(tx))
        self.rx        = iter(rx)
        self.tx        = iter(tx)
        self.p1        = None
        self.p2        = None
        self.args      = args
        self.npkt      = None
        #self.start_seq = 0
        self.expects   = {}

    def update(self):
        if self.npkt:
            if self.npkt == self.p1:
                try:
                    self.p1 = MyPackt(next(self.rx), self.expects, 'rx', self.args)
                except StopIteration:
                    self.p1 = None
                    self.rx = None
            elif self.npkt == self.p2:
                try:
                    self.p2 = MyPackt(next(self.tx), self.expects, 'tx', self.args)
                except StopIteration:
                    self.tx = None
                    self.p2 = None
        else:
            if not self.rx and not self.tx:
                raise StopIteration
            if self.rx:
                self.p1 = MyPackt(next(self.rx), None, 'rx', self.args)
            if self.tx:
                self.p2 = MyPackt(next(self.tx), None, 'tx', self.args)

        if self.p1 and self.p2:
            if self.p1.time <= self.p2.time:
                self.npkt = self.p1
            else:
                self.npkt = self.p2
        elif self.p1:
            self.npkt = self.p1
        elif self.p2:
            self.npkt = self.p2
        else:
            raise StopIteration

        self.expects[self.npkt.flow] = self.npkt.next()



    def __iter__(self):
        return self

    def __next__(self):
        self.update()
        return self.npkt


# return absolute or relative
# sequence-nr, next-sequence-nr and ack-nr 
# from the packet (type MyPackt)
# depending on the command-line option '-r'
def get_pkt_seqs(pkt, args):
    if args.rel_seq:
        seq = pkt.seq - start_seq[pkt.flow]
        nxt = pkt.next() - start_seq[pkt.flow]
        # zero ack means it is a syn packet
        ack = 0
        if pkt.ack > 0:
            if pkt.flow == 'c2f':
                ack = pkt.ack - start_seq.get('f2c',0)
            elif pkt.flow == 'f2c':
                ack = pkt.ack - start_seq.get('c2f',0)
            elif pkt.flow == 'f2s':
                ack = pkt.ack - start_seq.get('s2f',0)
            elif pkt.flow == 's2f':
                ack = pkt.ack - start_seq.get('f2s',0)
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
        # seq_s = pkt[TCP].seq - pcap.start_seq
        # ack   = pkt[TCP].ack - pcap.start_seq
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
            'f2c': ("",              " <--|"), 
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
        insq = " " if p.inseq else "*"

        if args.output == 'flow_c2s':
            if flow == 'c2f' or flow == 'f2s':
                print (f"{pre}{insq}{pkt[IP].id:7} {seq:10} {plen:5} {nxt:10} {post}")
            elif flow == 'f2c' or flow == 's2f':
                gap = " "
                print (f"{pre}{insq}{pkt[IP].id:7} {gap:10} {gap:5} {ack:10} {post}")
        elif args.output == 'flow_s2c':
            if flow == 'f2c' or flow == 's2f':
                print (f"{pre}{insq}{pkt[IP].id:7} {seq:10} {plen:5} {nxt:10} {post}")
            elif flow == 'c2f' or flow == 'f2s':
                gap = " "
                print (f"{pre}{insq}{pkt[IP].id:7} {gap:10} {gap:5} {ack:10} {post}")
        else:
            print ("Unknown output type")



def repr_str(dumper: RoundTripRepresenter, data: str):
    if '\n' in data:
        return dumper.represent_scalar('tag:yaml.org,2002:str', data, style='|')
    return dumper.represent_scalar('tag:yaml.org,2002:str', data)


pcapIter = pcapsItr(args)

if args.output == 'flow_c2s' or args.output == 'flow_s2c':
    print_flow(iter(pcapIter), args )
elif args.output == 'detail_c2s' or args.output == 'detail_s2c':
    print_detail(iter(pcapIter), args)
elif args.output == 'scenario':
    print_scenario(iter(pcapIter), args)

