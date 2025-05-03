#!/usr/bin/python


import argparse
import yaml
import queue
import logging
import ipaddress
import inspect
import string
from scapy.layers.all import * 
from scapy.sendrecv import *
from enum import Enum
from textwrap3 import indent


# -----------------------------------------------------------
#                          Configuration 
# -----------------------------------------------------------
RCV_TIMEOUT=10 # timeout in seconds

class Routing(Enum):
    source = 1
    dest = 2


# -----------------------------------------------------------
#                        Global Helpers
# -----------------------------------------------------------
def random_num(start, end):
    return random.randint(int(start), int(end))

def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return False
    return True

def is_valid_port(port):
    return int(port) >=1000 and int(port) < 65536





# -----------------------------------------------------------
#                           Classes
# -----------------------------------------------------------

class Flow:
    def __init__(self, fl, arg_proto):
        self.proto   = fl['proto'] if 'proto' in fl else arg_proto
        self.src     = fl['src']
        self.intf    = ip2dev(self.src)
        self.src_mac = ip2mac(self.src)
        self.ipid    = random.randint(1,100)
        self.seq     = 0
        self.ack     = 0
        self.ooq     = {}   # out of order queue
        self.l7      = {}   # Layer 7 data

        self.sport   = flds_eval(fl['sport']) #evalport(fl,'sport')

        if 'dst' in fl:
            self.dst = fl['dst']
        if 'dport' in fl:
            self.dport = flds_eval(fl['dport'])
        if 'tos' in fl:
            self.tos = fl['tos']
        if 'mss' in fl:
            self.mss = fl['mss']
        if 'mtu' in fl:
            self.mtu = fl['mtu']

    def __repr__(self):
        d = {x:getattr(self,x) for x in dir(self) if not x.startswith('__')}
        return d.__str__()


class Error(Exception):
    def __init__(self, message):
        self.message=message


class NoRoute(Error):
    def __init__(self, message):
        super().__init__(message)

class MyValueError(Exception):
    pass


# --------------------------------------------------------------------------
#                                 LOADER
# --------------------------------------------------------------------------


def rtp_constructor(loader, node):
    rtp_dict = loader.construct_mapping(node)
    pkt=RTP()
    if 'payload' in rtp_dict:
        pkt=pkt/rtp_dict['payload']
    return pkt

yaml.add_constructor(u'!rtp', rtp_constructor)



# --------------------------------------------------------------------------
#                                    Log
# --------------------------------------------------------------------------

def log_action(act, fl, pkt):
    if act == 'delay':
        # data is timeout
        actlog.info("{:<6} pause {} ms".format(".....", fl))
        return

    if act == 'send':
        prefix = "---->"
    elif act == 'recv':
        prefix = "<----"
    elif act == 'create':
        prefix = "-----"

    s = "{} [{}]".format(act, fl)
    if (RTP in pkt):
        actlog.info(f"{prefix:<6}{s:<15} RTP {pkt[UDP].sport}->{pkt[UDP].dport} {scapy.layers.rtp._rtp_payload_types[pkt[RTP].payload_type]} ssrc:{pkt[RTP].sourcesync}")
    elif (Raw in pkt):
        lod = pkt[Raw].load
        printable_chars = set(bytes(string.printable, 'ascii'))
        printable = all(char in printable_chars for char in lod)
        if printable:
            actlog.info("{:<6}{:<15}{}".format(prefix, s, lod.decode('utf8').splitlines()[0][:26]))
        else:
            byts = [ hex(x).split('x')[-1] for x in lod]
            actlog.info("{:<6}{:<15}{}".format(prefix, s, byts[:15]))
        
    else:
        if TCP in pkt:
            actlog.info("{:<6}{:<15}[{}] Seq:{} A:{}".format(prefix, s, pkt.sprintf('%TCP.flags%'),
                pkt.seq, pkt.ack))
        else:
            actlog.info("{:<6}{:<15}".format(prefix, s))





# --------------------------------------------------------------------------
#                               Internal Helpers
# --------------------------------------------------------------------------

def handle_non_ip(pkt):
    if ARP in pkt and pkt[ARP].op == 1:
        try:
            mac = ip2mac(pkt.pdst);
            genlog.debug(f"generate arp reply for {pkt.pdst} mac {mac} telling {pkt.psrc}")
            arp_reply = Ether(src=mac, dst="ff:ff:ff:ff:ff:ff")/ARP(op="is-at", hwsrc=mac, psrc=pkt.pdst, hwdst="ff:ff:ff:ff:ff:ff", pdst=pkt.psrc)
            sendp(arp_reply, iface=ip2dev(pkt.pdst))
        except:
            genlog.debug("Ignore ARP who-is")
            pass
    else:
        genlog.debug("non IP packet: ignoring")



def l3_l4_match(pkt, fl, act):
    if (fl.intf != pkt.sniffed_on):
        genlog.debug("intf no match expecting {} != pkt {}".format(fl.intf, pkt.sniffed_on))
        return False
    else:
        genlog.debug("intf match expecting {} = pkt {}".format(fl.intf, pkt.sniffed_on))

    if (not pkt.haslayer(IP)):
        handle_non_ip(pkt)

        return False

    if (fl.src and fl.src != pkt[IP].dst):
        genlog.debug("dst no match {} != pkt {}".format(fl.src, pkt[IP].dst))
        return False

    if (fl.proto == 'tcp'):
        if (not pkt.haslayer(TCP)):
            genlog.debug("proto no match, expecting TCP")
            return False
        if (fl.sport and int(fl.sport) != int(pkt[TCP].dport)):
            genlog.debug("packet dport no match expecting {} != pkt dport {}".format(fl.sport, pkt[TCP].dport))
            return False
    elif (fl.proto == 'udp'):
        if (not pkt.haslayer(UDP)):
            genlog.debug("proto no match, expecting UDP")
            return False
        if (fl.sport and int(fl.sport) != int (pkt[UDP].dport)):
            genlog.debug("packet dport no match expecting {} != pkt dport {}".format(fl.sport, pkt[UDP].dport))
            return False

    if ("flags" in act  and act['flags'] != pkt[TCP].flags):
        genlog.debug("flags no match, expecting {}".format(pkt[TCP].flags))
        return False

    return True


def update_l3_l4(fl, pkt):
    if TCP in pkt: 
        sseq = endseq = pkt[TCP].seq

        if 'S' in pkt[TCP].flags or 'F' in pkt[TCP].flags:
            endseq = sseq + 1
            assert not Raw in pkt   # not expecting data in FIN or SYN packet
        elif pkt[TCP].payload:
            if Raw in pkt:
                endseq = sseq + len(pkt[TCP].payload) 
                genlog.debug(f"payload in packet, seq {sseq}-{endseq-1}")

        # update receive next sequence number
        if sseq == fl.ack:
            fl.ack = endseq
            genlog.debug(f"seq match {sseq} now expecting {fl.ack}")
            for i in list(fl.ooq):
                if fl.ack == i:
                    fl.ack=fl.ooq[i]
                    del fl.ooq[i]
                elif fl.ack > i:
                    genlog.debug(f"remove illegal seq nr. {i} from ooq")
                    del fl.ooq[i]

        else:
            fl.ooq[sseq]=endseq 
            genlog.debug(f"out of order packet with seq nr {sseq}")




def l7_match(pkt, fl, act):
    assert 'match' in act
    if (Raw in pkt):
        patrn = re.compile(r'\{([A-Za-z][^}]+)\}')
        a1 = patrn.sub(lambda m: flds_eval(m.group(1)), act['match'])
        genlog.debug(f"match string: '{a1}'")
        if (not re.match(a1, pkt[Raw].load.decode('utf8'))):
            genlog.warning("match '{}' failed in '{}'".format(a1, pkt[Raw].load.decode('utf8')))
            return False
    else:
        genlog.warning("match '{}' failed: No L7 data in pkt".format(act['match']))
        return False

    return True



def flds_eval(exp):
    try:
        return eval(exp)
    except Exception as e:
        genlog.debug(e)
        return exp



def ip2dev(ip):
    return ip2dev_tbl[ip]


# what is the mac addr of interface that has this ip
def ip2mac(ip):
    return get_if_hwaddr(ip2dev(ip))



def ip2nxt_hop(ip):
    ipadr = ipaddress.ip_address(ip)
    for net in routing['routing']:
        if ipadr in ipaddress.ip_network(net):
            return routing['routing'][net]['next-hop']
    raise Error (f"No route from {ip}")



def create_packet(act):
    genlog.debug("{} called from {}".format(inspect.stack()[0][3],inspect.stack()[1][3]))

    fl = flows[act['flow']]
    if (fl.dst == None):
        genlog.error("[x] Error: No destination ip for {}".format(act['flow']))
        raise Error ("No destination ip for {}".format(act['flow']))
    if not hasattr(fl, 'dport') or fl.dport == None :
        genlog.error ("[x] Error: No destination port for {}".format(act['flow']))
        raise Error ("No destination port for {}".format(act['flow']))

    # Ether/IP
    if routing_type == Routing.source:
        ip_layr = Ether(src=fl.src_mac, dst=(ip2nxt_hop(fl.src))) / IP(src=fl.src,dst=fl.dst) 
    else: 
        ip_layr = Ether(src=fl.src_mac, dst=(ip2nxt_hop(fl.dst))) / IP(src=fl.src,dst=fl.dst) 

    ip_layr[IP].id = fl.ipid
    fl.ipid += 1
    if hasattr(fl, 'tos'):
        ip_layr[IP].tos = fl.tos


    # udp/tcp
    if (fl.proto == "tcp"):
        pkt = ip_layr/TCP(sport=int(fl.sport), dport=int(fl.dport), ack=fl.ack, seq=fl.seq, window=65535)
    else:
        pkt = ip_layr/UDP(sport=int(fl.sport), dport=int(fl.dport))


    if act.get('flags',None):
        pkt[TCP].flags= act['flags']
        if 'S' in act['flags']:
            fl.seq=1
            if hasattr(fl, 'mss'):
                pkt[TCP].options = [('MSS',fl.mss)]

    # Raw
    if 'data' in act:
        if type(act['data']) == str:

            data = "".join(act['data'].split('\n'))
            data = data.replace(r'\r','\r')
            data = data.replace(r'\n','\n')

            patrn = re.compile(r'\{([^}]+)\}')
            payload = patrn.sub(lambda m: str(flds_eval(m.group(1))), data)
            pkt = pkt/payload
            genlog.debug(f"payload size: {len(payload)}")

            if pkt.haslayer(TCP):
                pkt[TCP].flags='PA'
                fl.seq+=len(payload)

        elif type(act['data']) == bytes:
            pkt = pkt/act['data']

            if (pkt.haslayer(TCP)):
                pkt[TCP].flags='PA'
                fl.seq+=len(act['data'])

        elif type(act['data']) == RTP:
            pkt = pkt/act['data']
            if 'ssrc' not in fl.l7:
                fl.l7['ssrc'] = random.randint(9000,50000)
            if 'ts' not in fl.l7:
                fl.l7['ts'] = int(time.time())

            pkt[RTP].sourcesync = fl.l7['ssrc']
            pkt[RTP].timestamp = fl.l7['ts']
            
        else:
            raise Error("Unknown send data type")

    return pkt


# -----------------------------------------------------------
#                         Sub Actions
# -----------------------------------------------------------

def echo(pkt, fl, act):
    assert 'echo' in act
    print(act['echo'])


def l7_search(pkt, fl, act, name):
    assert 'search' in act
    if (Raw in pkt):
        for itm in act['search']:
            genlog.debug(f"search pattern:{itm}") 
            m = re.search(itm, pkt[Raw].load.decode('utf8'))
            if m:
                genlog.debug("groupdict:{}".format(m.groupdict()))
                for key,val in m.groupdict().items():
                    genlog.debug(f"search got {key}={val}")
                if not name:
                    name = 'recv'
                if not name in globals():
                    globals()[name] = {}
                globals()[name].update(m.groupdict())

                # dicts['payload'].update(m.groupdict())
            else:
                genlog.warning(f"[!] Warning: search failed {itm}")
    else:
        genlog.warning("[!] Warning: search failed because pkt has no payload")


def l7_verify(pkt, fl, act):
    for itm in act['verify']:
        if not eval(itm):
            genlog.info(f"verification failed: {itm}")
            raise Error("Verify failed")
        else:
            genlog.info(f"verified: {itm}")




# -----------------------------------------------------------
#                          Actions
# -----------------------------------------------------------

def do_delay(act, c):
    log_action("delay", act['timeout'], None)
    time.sleep(act['timeout']/1000)
    return c+1



def do_recv(act, c):
    fl = flows[act['flow']]
    genlog.debug("\n{} on intf {}".format(inspect.stack()[0][3], fl.intf))
    to = eval(act['timeout']) if 'timeout' in act else RCV_TIMEOUT
    
    if c == 0:
        print (f"\nListning on {fl.sport} ...")

    while True:
        try:
            pkt = rcvqueue.get(block=True, timeout=to)
        except queue.Empty:
            genlog.critical ("receive failed")
            raise Error("receive timeout")

        if l3_l4_match(pkt, fl, act) == True:
            if "l7-proto" in act:
                if act["l7-proto"] == "RTP":
                    pkt[UDP].decode_payload_as(RTP)

            log_action("recv", act['flow'], pkt)
            update_l3_l4(fl,pkt)
        else:
            continue


        if 'match' in act: 
            if l7_match(pkt, fl, act):
                genlog.info(f"match success: '{act['match']}'")
            else:
                continue

        globals()['pkt'] = pkt

        name=None
        if ("name" in act):
            name=act['name']
        if ("echo" in act):
            echo(pkt, fl, act)
        if ("search" in act):
            l7_search(pkt, fl, act, name)
        if "exec" in act:
            for itm in act['exec']:
                exec(itm)
        if "verify" in act:
            l7_verify(act, fl, act)


        unknown_a = [ a for a in act.keys() if a not in ['flow','search','verify','exec','flags','match','echo','l7-proto','timeout']]
        for x in unknown_a:
            genlog.warning(f"WARNING: Unknown action:{x}")

        return c+1

def do_send(act, c):
    genlog.debug("\n{} called from {}".format(inspect.stack()[0][3],inspect.stack()[1][3]))

    if 'name' in act:
        pkt = saved_pkts[act['name']]
    else:
        pkt = create_packet(act)

    fl = flows[act['flow']]
    intf = ip2dev(fl.src)

    if TCP in pkt:
        genlog.debug("send to {}:{} intf {}".format(pkt[IP].dst, pkt[TCP].dport, intf))
    elif UDP in pkt:
        genlog.debug("send to {}:{} intf {}".format(pkt[IP].dst, pkt[UDP].dport, intf))

    if hasattr(fl, 'mtu') and len(pkt[IP].payload) > fl.mtu:
        frags = fragment(pkt, fragsize=fl.mtu)
        for frag in frags:
            sendp(frag, iface=intf, verbose=False)
            log_action("send", act['flow'], frag)
    else:
        sendp(pkt, iface=intf, verbose=False)
        log_action("send", act['flow'], pkt)

    if 'save' in act:
        saved_pkts[act['save']] = pkt

    if ("echo" in act):
        echo(pkt, fl, act)

    return c+1



def do_connect(act, c):
    flname = act['flow']
    fl = flows[flname]
    peer_flname = act['peer_flow']
    peer_fl = flows[peer_flname]

    if fl.proto == peer_fl.proto == 'udp':
        return c+1
    elif fl.proto != peer_fl.proto:
        raise Error("connect protocol mismatch")

    exec1 = f"{peer_flname}.dst =  pkt[IP].src"
    exec2 = f"{peer_flname}.dport =  pkt[TCP].sport"
    scen = list()
    scen.append  ({'send': {'flow':flname,      'flags':'S' }});
    scen.append  ({'recv': {'flow':peer_flname, 'flags':'S', 'exec':[exec1, exec2] }});
    scen.append  ({'send': {'flow':peer_flname, 'flags':'SA'}});
    scen.append  ({'recv': {'flow':flname,      'flags':'SA'}});
    scen.append  ({'send': {'flow':flname,      'flags':'A' }});
    scen.append  ({'recv': {'flow':peer_flname, 'flags':'A' }});
    run_scenario(scen)
    return c+1




def do_create(act, c):
    genlog.debug("{} called from {}".format(inspect.stack()[0][3],inspect.stack()[1][3]))
    pkt = create_packet(act)
    if 'name' in act:
        saved_pkts[act['name']] = pkt
    else:
        genlog.error('name field is required')
        raise Error(f"Missing required field:name")

    if ("echo" in act):
        echo(pkt, fl, act)

    log_action("create", act['flow'], pkt)
    return c+1
         


def do_loop_start(act, c):
    if not 'loop' in globals():
        globals()['loop'] = {}

    if 'jump' in loop:
        raise Error('Nested loops are not allowed')
    if 'count' in act:
        loop['count'] = act['count']-1
    else:
        raise Error("count is mandatory in loop")
    loop['jump'] = c+1
    return c+1



def do_loop_end(act, c):
    if not 'count' in loop:
        raise Error("loop-end without loop-start")

    if loop['count'] > 0:
        loop['count'] -= 1
        return loop['jump']
    else:
        del (loop['jump'])
        del (loop['count'])
        return c+1



def do_save(act, c):
    for key, val in act.items():
        data = "".join(val.split('\n'))
        data = data.replace(r'\r','\r')
        data = data.replace(r'\n','\n')

        patrn = re.compile(r'\{([^}]+)\}')
        payload = patrn.sub(lambda m: str(flds_eval(m.group(1))), data) 
        globals()[key] = payload
    return c+1 



def do_execute(act, c):
    for exp in act:
        exec(exp)
    return c+1


# --------------------------------------------------------------------------
#                                  DRIVER
# --------------------------------------------------------------------------

actions = {
        "delay"      : do_delay,
        "send"       : do_send,
        "recv"       : do_recv,
        "create"     : do_create,
        "loop-start" : do_loop_start,
        "loop-end"   : do_loop_end,
        "save"       : do_save,
        "execute"    : do_execute,
        "connect"    : do_connect
        }


def run_scenario(scenario):
    cur  = 0
    end  = len(scenario)
    while cur < end:
        act, val = next(iter(scenario[cur].items()))
        cur = actions[act](val, cur)



# ---------------------------------------------------------------
#                            Receiver
# ---------------------------------------------------------------

def pkt_dbg_print(pkt):
    if (pkt.haslayer(TCP)):
        pktlog.debug("{}: {}:{} -> {}:{} {}".format(
            pkt.sniffed_on,
            pkt[IP].src, 
            pkt[TCP].sport, 
            pkt[IP].dst, 
            pkt[TCP].dport, 
            pkt.sprintf('%TCP.flags%')))
    elif (pkt.haslayer(UDP)):
        pktlog.debug("{}: {}:{} -> {}:{}".format(
            pkt.sniffed_on,
            pkt[IP].src,
            pkt[UDP].sport,
            pkt[IP].dst,
            pkt[UDP].dport))

    if (pkt.haslayer(Raw)):
        try:
            pktlog.debug(indent(pkt.load.decode('utf8'), '    '))
        except UnicodeDecodeError: 
            pass


def pkt_cb(pkt):
    rcvqueue.put(pkt)
    if pktlog.isEnabledFor(logging.DEBUG):
        pkt_dbg_print(pkt)



def setup_logging(log_level):
    global genlog
    global actlog
    global pktlog

    logging.getLogger("scapy").setLevel(log_level)
    conf.verb=0

    # General console logging handler
    genlog = logging.getLogger('replay_data') 
    loghdlr = logging.StreamHandler()
    genlog.addHandler(loghdlr)
    logformtr = logging.Formatter('       %(message)s')
    loghdlr.setFormatter(logformtr)
    genlog.setLevel(log_level)

    # Actions console logging handler
    actlog = logging.getLogger('replay_data_act') # Logger
    loghdlr2 = logging.StreamHandler()
    actlog.addHandler(loghdlr2)
    actlog.setLevel(log_level)

    # packets log, all sniffed packets
    pktlog = logging.getLogger('replay_data_pkt') # Logger
    loghdlr3 = logging.FileHandler("packet.log", mode='w')
    pktlog.addHandler(loghdlr3)
    pktlog.setLevel(log_level)

def init(logl):
    setup_logging(logl)

def setup(scenario_f, routes_f, route_type, params_f, pcap_f, proto):
    # global dicts
    global routing
    global routing_type
    global scenario
    global saved_pkts
    global fname
    global sniffer
    global rcvqueue
    global recv          # last received packet
    global ip2dev_tbl
    global flows

    with open(scenario_f, 'r') as f:
        scen_dict = yaml.full_load(f)

    # routing
    routing_type = route_type
    ip2dev_tbl = dict()
    with open(routes_f, 'r') as f:
        routing = yaml.safe_load(f)
        for dev_name, ips in routing['interfaces'].items():
            for x in ips:
                ip2dev_tbl[x] = dev_name

    if params_f:
        with open(params_f, 'r') as f:
            if not 'params' in globals():
                globals()['params'] = {}
            params.update(yaml.full_load(f))

    rcvqueue       = queue.Queue()  
    saved_pkts     = {}

    intfs = set()
    hosts = set()
    flows = {}
    for name, fl in scen_dict['flows'].items():
        flobj = Flow(fl, proto)
        globals()[name]= flobj
        flows[name]= flobj
        intfs.add(flobj.intf)
        hosts.add(flobj.src)

    fname = pcap_f
    fltr=' or '.join(map(lambda x: "host "+x, list(hosts)))
    sniffer = AsyncSniffer(prn=pkt_cb, filter=fltr, iface=list(intfs), store=(fname != None))
    sniffer.start()
    return scen_dict['scenario']
   

def stop():
    if sniffer:
        pktlst = sniffer.stop()
        if (fname):
            actlog.info(f"pcap saved: {fname}")
            wrpcap(fname, pktlst)




# ---------------------------------------------------------------
#                              Main
# ---------------------------------------------------------------

if __name__ == '__main__':
    parser = argparse.ArgumentParser(formatter_class=lambda prog: argparse.HelpFormatter(prog,max_help_position=57))
    parser.add_argument('-t', '--testfile', metavar='', help='testfile name .yaml', required=True, )
    parser.add_argument('-l', '--log',      metavar='', choices=['DEBUG','INFO','WARNING','ERROR','CRITICAL'], help='Set logging level {%(choices)s}', default='CRITICAL')
    parser.add_argument('-p', '--params',   metavar='', help='parameter file')
    parser.add_argument('-s', '--savepcap', action='store_true', help='save pcap file')
    parser.add_argument('-pr','--proto',    metavar='', choices=['TCP','UDP','udp','tcp'], help='Set transport protocol', default='UDP')

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-sr', '--src_routes', help='source based routing file .yaml')
    group.add_argument('-dr', '--dst_routes', help='destination based routing file .yaml')

    args = parser.parse_args()

    # This is needed otherwise packet will appear twice in pcap
    conf.sniff_promisc=0
    conf.promisc=0

    args=parser.parse_args()
    init(getattr(logging, args.log))

    if args.savepcap:
        fname_b = os.path.basename(args.testfile)
        fname = os.path.splitext(fname_b)[0] + "_send.pcap"
    else:
        fname = None

    try:
        if args.src_routes:
            scenario = setup(args.testfile, args.src_routes, Routing.source, args.params, fname, args.proto)
        else:
            scenario = setup(args.testfile, args.dst_routes, Routing.dest, args.params, fname, args.proto)
        
    except KeyError as inst:
        genlog.critical ("KeyError: {}".format(inst))
        exit()
       
    try:
        time.sleep(3)
        run_scenario(scenario)
    except KeyError as inst:
        genlog.critical ("KeyError: {}".format(inst))
    except Error as err:
        genlog.critical ("Error: {}".format(err))
    except MyValueError:
        genlog.critical ("[x] Test failed because a required field is missing in the message")
    except ValueError:
        print(traceback.format_exc())
    finally:
        stop()




