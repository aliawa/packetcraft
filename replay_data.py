#!/usr/bin/python

import argparse
import time
import yaml
import threading
import queue
import textwrap
import logging
import ipaddress
import inspect

from scapy.all import *

import pdb

# -----------------------------------------------------------
#                            Globals
# -----------------------------------------------------------
rcvqueue = queue.Queue()                        # receive queue
l7data={}                                       # global Layer 7 data 
routing={}                                      # global routing table
mylog = logging.getLogger('replay_data')        # Logger
mylog.setLevel(logging.DEBUG)
pktlog = open('pktlog', 'w')

# -----------------------------------------------------------
#                          Configuration 
# -----------------------------------------------------------
RCV_TIMEOUT=30                                  # timeout in seconds


# -----------------------------------------------------------
#                            Defines
# -----------------------------------------------------------

class Flow:
    def __init__(self, src, sport, dst, dport, proto):
        self.intf = ip2dev(src)
        self.src = src
        self.sport = sport
        self.dst = dst
        self.dport = dport
        self.seq = 0
        self.ack = 0
        self.src_mac = ip2mac(src)
        self.ipid = random.randint(1,100)
        self.proto = proto


class Error(Exception):
    def __init__(self, message):
        self.message=message


class NoRoute(Error):
    def __init__(self, message):
        super().__init__(message)


def setup_flows(cfg_flows):
    intfs = set()
    hosts = set()
    flows = {}
    for fl in cfg_flows:
        newFl = flows[fl['name']] = Flow(fl['src'], fl['sport'], fl.get('dst',None), fl.get('dport',None), fl['proto']);
        intfs.add(newFl.intf)
        hosts.add(fl['src'])
    
    return flows, list(intfs), list(hosts)




# --------------------------------------------------------------------------
#                                 ACTIONS
# --------------------------------------------------------------------------

def log_action(act, pkt):
    if act['action'] == 'delay':
        # data is timeout
        mylog.info("{:<6} pause {}ms".format(".....", act['timeout']))
        return

    if act['action'] == 'send':
        prefix = "---->"
    elif act['action'] == 'recv':
        prefix = "<----"

    fl_name = act['flow']
    if (Raw in pkt):
        if act.get('type') == "binary":
            mylog.info(f"{prefix:<6}{fl_name:<10} binary")
        else:
            mylog.info("{:<6}{:<10} {}".format(prefix, fl_name, pkt[Raw].load.decode('utf8').splitlines()[0][:26]))
    elif 'flags' in act:
        mylog.info("{:<6}{:<10} {}".format(prefix, fl_name, act['flags']))


def do_delay(act, flows):
    log_action(act, None)
    time.sleep(act['timeout']/1000)


def do_recv(act, flows):
    mylog.debug("{} on intf {}".format(inspect.stack()[0][3], act['flow']))
    fl = flows[act['flow']]
    to = act['timeout'] if 'timeout' in act else RCV_TIMEOUT

    try:
        while True:
            pkt = rcvqueue.get(block=True, timeout=to)
            if (fl.intf != pkt.sniffed_on):
                mylog.debug("intf no match expecting {} != pkt {}".format(fl.intf, pkt.sniffed_on))
                continue 
            else:
                mylog.debug("intf match expecting {} = pkt {}".format(fl.intf, pkt.sniffed_on))

            if (fl.src and fl.src != pkt[IP].dst):
                mylog.debug("dst no match {} != pkt {}".format(fl.src, pkt[IP].dst))
                continue

            if (fl.proto == 'tcp'):
                if (not pkt.haslayer(TCP)):
                    mylog.debug("proto no match, expecting TCP")
                    continue
                if (fl.sport and int(fl.sport) != int(pkt[TCP].dport)):
                    mylog.debug("port no match expecting {} != pkt {}".format(fl.sport, pkt[TCP].dport))
                    continue

            if (fl.proto == 'udp'):
                if (not pkt.haslayer(UDP)):
                    mylog.debug("proto no match, expecting UDP")
                    continue
                if (fl.sport and int(fl.sport) != int (pkt[UDP].dport)):
                    mylog.debug("port no match expecting {} != pkt {}".format(fl.sport, pkt[UDP].dport))
                    continue

            if ("flags" in act  and act['flags'] != pkt[TCP].flags):
                mylog.debug("flags no match, expecting {}".format(pkt[TCP].flags))
                continue

            if ("match" in act):
                if (not Raw in pkt):
                    continue
                if (not re.match(act['match'], pkt[Raw].load.decode('utf8'))):
                    mylog.debug("rcv match failed")
                    continue

            if ("search" in act):
                if (Raw in pkt):
                    mylog.debug("search {}".format(act['search']))
                    for itm in act['search']:
                        mylog.debug("itm {}".format(itm))
                        m = re.search(itm, pkt[Raw].load.decode('utf8'))

                        if m:
                            mylog.debug("groupdict:{}".format(m.groupdict()))
                            for key,val in m.groupdict().items():
                                mylog.debug("search got {}={}".format(key, val))
                            l7data.update(m.groupdict())
                        else:
                            mylog.warning("[!] Warning: search failed")


            # All matches succecceeded.

            if "exec" in act:
                fields = {}
                if IP in pkt:
                    fields['IP.src'] = pkt[IP].src
                    fields['IP.dst'] = pkt[IP].src
                if TCP in pkt:
                    fields['TCP.sport'] = pkt[TCP].sport
                    fields['TCP.dport'] = pkt[TCP].dport
                if UDP in pkt:
                    fields['UDP.sport'] = pkt[UDP].sport
                    fields['UDP.dport'] = pkt[UDP].dport
                fields.update(l7data)

                for itm in act['exec']:
                    cmd = itm.partition('=')
                    lhs = cmd[0].partition('.')
                    fld = cmd[2].strip()
                    if fld[0]=='{':
                        fld = fld.strip('{}')
                        var = fld.partition(':')
                        fld = var[0] if var[0] in fields else var[2]
                    
                    if fld[0]=="'":
                        setattr(flows[lhs[0]], lhs[2], fld.strip("'"))
                    else:
                        if fld in fields:
                            setattr(flows[lhs[0]], lhs[2], fields[fld])
                        else:
                            mylog.warning(f"[!] Warning: key not found {fld}")

                    mylog.debug("set attribute: {},{},{}".format(lhs[0], lhs[2], fld))


            if TCP in pkt: 
                if Raw in pkt:
                    fl.ack += len (pkt[Raw].load)
                elif 'S' in pkt[TCP].flags:
                    fl.ack += 1


            log_action(act, pkt)
            return

    except Empty:
        mylog.critical ("receive failed")
        raise Error("receive timeout")



def ip2mac(ip):
    ipadr = ipaddress.ip_address(ip)
    for i in routing:
        if ipadr in ipaddress.ip_network(i):
            return routing[i]['mac']
    raise Error (f"[x] No mac for {ip}")


def ip2dev(ip):
    ipadr = ipaddress.ip_address(ip)
    for i in routing:
        if ipadr in ipaddress.ip_network(i):
            return routing[i]['dev']
    raise Error (f"[x] No device for {ip}")


def ip2dst_dev(ip):
    ipadr = ipaddress.ip_address(ip)
    for i in routing:
        if ipadr in ipaddress.ip_network(i):
            return routing[i]['dst-dev']
    raise Error (f"No route to {ip}")


class field_val:
    def __init__(self, flows, l7data):
        self.flows = flows
        self.l7data = l7data

    def __call__(self, m):
        if '.' in m.group(1):
            a = m.group(1).split('.')
            return getattr(self.flows[a[0]], a[1])
        else:
            return self.l7data[m.group(1)]


         
def do_send(act, flows):
    mylog.debug("{} called from {}".format(inspect.stack()[0][3],inspect.stack()[1][3]))

    fl = flows[act['flow']]
    if (fl.dst == None):
        mylog.error("[x] Error: No destination ip for {}".format(act['flow']))
        raise Error ("No destination ip for {}".format(act['flow']))
    if (fl.dport == None):
        mylog.error ("[x] Error: No destination port for {}".format(act['flow']))
        raise Error ("No destination port for {}".format(act['flow']))

    # Ether/IP
    ip_layr = Ether(src=fl.src_mac, dst=(ip2mac(fl.dst))) / IP(src=fl.src,dst=fl.dst) 
    ip_layr[IP].id = fl.ipid
    fl.ipid += fl.ipid

    # udp/tcp
    if (fl.proto == "tcp"):
        pkt = ip_layr/TCP(sport=int(fl.sport), dport=int(fl.dport))
    else:
        pkt = ip_layr/UDP(sport=int(fl.sport), dport=int(fl.dport))

    if act.get('flags',None):
        pkt[TCP].flags= act['flags']
        fl.seq=1
        if 'A' in act['flags']:
            fl.ack=1
            pkt[TCP].ack= fl.ack

    # Raw
    elif act['type'] == "text":

        fields = field_val(flows, l7data)
        patrn = re.compile(r'\{([^}]+)\}')
        a1 = patrn.sub(fields, act['data'])
        a2 = a1.split('\n')
        data = "\r\n".join([ x.strip() for x in a2 ])
        data += "\r\n";
        pkt = pkt/data

        if pkt.haslayer(TCP):
            pkt[TCP].flags='PA'
            pkt[TCP].seq = fl.seq
            fl.seq+=len(data)
            pkt[TCP].ack = fl.ack

    elif act['type'] == "binary":
        pkt = pkt/act['data']

        if (pkt.haslayer(TCP)):
            pkt[TCP].flags='PA'
            fl.seq+=len(act['data'])

    else:
        raise Error(f"Unknown send type {act['type']}")
        return

    intf = ip2dst_dev(fl.dst)

    if TCP in pkt:
        mylog.debug("send to {}:{} intf {}".format(pkt[IP].dst, pkt[TCP].dport, intf))
    elif UDP in pkt:
        mylog.debug("send to {}:{} intf {}".format(pkt[IP].dst, pkt[UDP].dport, intf))

    sendp(pkt, iface=intf, verbose=False)
    log_action(act, pkt)


def default_action(act, flows):
    raise Error(f"Unknown action {act['action']}")


# --------------------------------------------------------------------------
#                                  DRIVER
# --------------------------------------------------------------------------

actions = {
        "delay": do_delay,
        "send" : do_send,
        "recv" : do_recv
        }

def run_scenario(scenario, flows):
    for s in scenario:
        cb = actions.get(s['action'], default_action)
        cb(s, flows)
    

        



# ---------------------------------------------------------------
#           Add support for include in yaml files
# ---------------------------------------------------------------


class Loader(yaml.SafeLoader):

    def __init__(self, stream):

        self._root = os.path.split(stream.name)[0]

        super(Loader, self).__init__(stream)

    def include(self, node):

        filename = os.path.join(self._root, self.construct_scalar(node))

        with open(filename, 'r') as f:
            return yaml.load(f, Loader)

Loader.add_constructor('!include', Loader.include)


# ---------------------------------------------------------------
#                            Receiver
# ---------------------------------------------------------------



def printpkt(pkt):

    rcvqueue.put(pkt)
    original_stdout = sys.stdout
    sys.stdout = pktlog

    if (pkt.haslayer(TCP)):
        print("{}: {}:{} -> {}:{} {}".format(
            pkt.sniffed_on,
            pkt[IP].src, 
            pkt[TCP].sport, 
            pkt[IP].dst, 
            pkt[TCP].dport, 
            pkt.sprintf('%TCP.flags%')))
    elif (pkt.haslayer(UDP)):
        print("{}: {}:{} -> {}:{}".format(
            pkt.sniffed_on,
            pkt[IP].src,
            pkt[UDP].sport,
            pkt[IP].dst,
            pkt[UDP].dport))

    if (pkt.haslayer(Raw)):
        try:
            print(textwrap.indent(pkt.load.decode('utf8'), '    '))

        except UnicodeDecodeError: 
            pass

    sys.stdout = original_stdout 


# ---------------------------------------------------------------
#                              Main
# ---------------------------------------------------------------

if __name__ == '__main__':

    parser = argparse.ArgumentParser(description="execute tests")
    parser.add_argument('-t', '--testfile', help='testfile name')
    parser.add_argument('-s', '--savepcap', action='store_true', help='save pcap file')
    parser.add_argument('-l', '--log', choices=['DEBUG','INFO','WARNING','ERROR','CRITICAL'], help='Set logging level', default='CRITICAL')
    parser.add_argument('-r', '--routes', help='routing file')

    args=parser.parse_args()

    logging.getLogger("scapy").setLevel(args.log)
    conf.verb=0

    loghdlr = logging.StreamHandler()
    loghdlr.setLevel(args.log)
    mylog.addHandler(loghdlr)

    with open(args.testfile, 'r') as f:
        dictionary = yaml.load(f, Loader)

    with open(args.routes, 'r') as f:
        routing = yaml.load(f, Loader)
    
    try:
        flows, intfs, hosts = setup_flows(dictionary['flows'])

        sendpcap = None
        if args.savepcap:
            fname = os.path.splitext(args.testfile)[0] + "_send.pcap"
            sendpcap = PcapWriter(fname)

        # This is needed otherwise packet will appear twice in pcap
        conf.sniff_promisc=0
        conf.promisc=0

        fltr=' or '.join(map(lambda x: "host "+x, hosts))
        a = AsyncSniffer(prn=printpkt, filter=fltr, iface=intfs, store=args.savepcap)
        a.start()
        time.sleep(3)

        run_scenario(dictionary['scenario'], flows)

    except KeyError as inst:
        mylog.critical ("KeyError: {}".format(inst))
        raise
    except Error as err:
        mylog.critical ("Error: {}".format(err))
        raise
    finally:
        pktlst = a.stop()
        if (args.savepcap):
            wrpcap(fname, pktlst)




