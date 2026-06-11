#!/usr/bin/python


import argparse
import yaml
import queue
import logging
import ipaddress
import inspect
import string
import threading
import socket
import json
import os
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
        self.src     = flds_eval(fl['src'])
        self.intf    = ip2dev(self.src)
        self.src_mac = ip2mac(self.src)
        self.ipid    = random.randint(1,100)
        self.seq     = 0
        self.ack     = 0
        self.ooq     = {}   # out of order queue
        self.l7      = {}   # Layer 7 data
        self.sport   = flds_eval(fl['sport']) #evalport(fl,'sport')

        if 'dst' in fl:
            self.dst = flds_eval(fl['dst'])
        if 'dport' in fl:
            self.dport = flds_eval(fl['dport'])
        if 'tos' in fl:
            self.tos = fl['tos']
        if 'mss' in fl:
            self.mss = fl['mss']
        if 'mtu' in fl:
            self.mtu = fl['mtu']

        if arg_proto:
            self.proto = arg_proto 
        elif 'proto' in fl:
            self.proto = fl['proto']
        else:
            self.proto = 'udp'



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
#                              Peer IPC Globals
# --------------------------------------------------------------------------
# Populated by setup_peers(); declared here so action handlers can reference them.
peers           = {}   # name -> {'socket': path}
peer_socket     = None # bound UDS SOCK_DGRAM socket owned by this process
peer_event_q    = None # queue.Queue of received peer messages (dicts)
peer_recv       = {}   # event_name -> payload string (mirrors recv[] dict)
_my_peer_name_v = None # name of the peer entry this process owns


def _my_peer_name():
    return _my_peer_name_v


def setup_peers(peers_dict):
    """Bind a UDS datagram socket for the peer entry this process owns,
    then start a background listener thread that feeds peer_event_q."""
    global peers, peer_socket, peer_event_q, peer_recv, _my_peer_name_v

    peers        = peers_dict or {}
    peer_event_q = queue.Queue()
    peer_recv    = {}
    peer_socket  = None

    if not peers:
        return

    # Try to bind each declared socket path; the first one that succeeds
    # is "ours".  The others belong to remote processes.
    for name, cfg in peers.items():
        path = cfg.get('socket', '')
        if not path:
            continue
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            if os.path.exists(path):
                os.unlink(path)
            s.bind(path)
            peer_socket     = s
            _my_peer_name_v = name
            genlog.info(f"Peer IPC: bound socket '{path}' as peer '{name}'")
            break
        except OSError as e:
            s.close()
            genlog.debug(f"Peer IPC: cannot bind '{path}': {e}")

    if peer_socket is None:
        genlog.warning("Peer IPC: no peer socket could be bound — send_peer/recv_peer will not work")
        return

    t = threading.Thread(target=_peer_listener, daemon=True, name="peer-listener")
    t.start()


def _peer_listener():
    """Background daemon thread: read datagrams from peer_socket and enqueue them."""
    while True:
        try:
            data, _ = peer_socket.recvfrom(65535)
            msg = json.loads(data.decode('utf-8'))
            genlog.debug(f"peer_listener: received {msg}")
            peer_event_q.put(msg)
        except OSError:
            # Socket was closed (process shutting down)
            break
        except Exception as e:
            genlog.warning(f"peer_listener error: {e}")


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
        genlog.debug(f"intf no match expecting {fl.intf} found {pkt.sniffed_on}")
        return False
    else:
        genlog.debug(f"intf match expecting {fl.intf} found {pkt.sniffed_on}")

    if (not pkt.haslayer(IP)):
        handle_non_ip(pkt)
        return False

    if (fl.src and fl.src != pkt[IP].dst):
        genlog.debug(f"dst no match, expecting {fl.src} found {pkt[IP].dst}")
        return False

    if (fl.proto == 'tcp'):
        if (not pkt.haslayer(TCP)):
            genlog.debug(f"proto no match, expecting TCP found {pkt[IP].proto}")
            return False
        if (fl.sport and int(fl.sport) != int(pkt[TCP].dport)):
            genlog.debug(f"packet dport no match, expecting {fl.sport} found {pkt[TCP].dport}")
            return False
        if ("flags" in act  and act['flags'] != pkt[TCP].flags):
            genlog.debug(f"flags no match, expecting \"{act['flags']}\" found \"{pkt[TCP].flags}\"")
            return False
    elif (fl.proto == 'udp'):
        if (not pkt.haslayer(UDP)):
            genlog.debug(f"proto no match, expecting TCP found {pkt[IP].proto}")
            return False
        if (fl.sport and int(fl.sport) != int (pkt[UDP].dport)):
            genlog.debug("packet dport no match expecting {fl.sport} found {pkt[UDP].dport}")
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
        elif fl.ack == 0:
            genlog.debug(f"Set initial ack to {sseq}")
            fl.ack = sseq+1
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

def is_ip(s):
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def flds_eval(exp):
    try:
        if is_ip(exp):
            return exp
        else:
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
        if act.get('flags',None):
            pkt[TCP].flags= act['flags']
            if 'S' in act['flags']:
                fl.seq=1
        if hasattr(fl, 'mss'):
            pkt[TCP].options = [('MSS',fl.mss)]
    else:
        pkt = ip_layr/UDP(sport=int(fl.sport), dport=int(fl.dport))



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




def _recv_thread_log(pkt, flow_name, file_handle):
    if not pkt.haslayer(IP):
        return

    src = pkt[IP].src
    dst = pkt[IP].dst
    proto = 'TCP' if pkt.haslayer(TCP) else 'UDP' if pkt.haslayer(UDP) else pkt[IP].proto
    sport = pkt[TCP].sport if pkt.haslayer(TCP) else pkt[UDP].sport if pkt.haslayer(UDP) else ''
    dport = pkt[TCP].dport if pkt.haslayer(TCP) else pkt[UDP].dport if pkt.haslayer(UDP) else ''
    payload = ''
    if pkt.haslayer(Raw):
        try:
            payload = pkt[Raw].load.decode('utf8', errors='replace')
        except Exception:
            payload = pkt[Raw].load.hex()
    elif pkt.haslayer(RTP):
        payload = repr(pkt[RTP])
    else:
        payload = pkt.summary()

    ts = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
    file_handle.write(f">>> {ts} {flow_name} {src}:{sport} -> {dst}:{dport} {proto}\n")
    file_handle.write(f"{payload}\n")
    file_handle.flush()


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



def _recv_thread_worker(flow_name, peer_flow_name, queue_obj, filename, stop_event):
    fl = flows[flow_name]
    peer_flow = flows[peer_flow_name]
    with open(filename, 'w', encoding='utf8') as out:
        out.write(f">>> recv_thread started for flow {flow_name}, peer_flow {peer_flow_name}\n")
        out.flush()
        while not stop_event.is_set():
            try:
                pkt = queue_obj.get(block=True)
            except queue.Empty:
                continue
            if l3_l4_match(pkt, fl, {'flow': flow_name}):
                update_l3_l4(fl, pkt)
                if pkt.haslayer(TCP):
                    ack_act = {'flow': flow_name, 'flags': 'A'}
                    do_send(ack_act, 0)
                _recv_thread_log(pkt, flow_name, out)




# -----------------------------------------------------------
#                          Actions
# -----------------------------------------------------------

def do_delay(act, c):
    log_action("delay", act['timeout'], None)
    time.sleep(act['timeout']/1000)
    return c+1


def do_recv_thread(act, c):
    if 'flow' not in act:
        raise Error('recv_thread action requires flow')
    if 'peer_flow' not in act:
        raise Error('recv_thread action requires peer_flow')

    flow_name = act['flow']
    peer_flow_name = act['peer_flow']
    if flow_name not in flows:
        raise Error(f"Unknown flow: {flow_name}")
    if peer_flow_name not in flows:
        raise Error(f"Unknown peer_flow: {peer_flow_name}")

    filename = act.get('file', f"recv_thread_{flow_name}.txt")

    if flow_name in recv_threads:
        genlog.warning(f"recv_thread '{flow_name}' already running")
        return c+1

    q = queue.Queue()
    stop_event = threading.Event()
    thread = threading.Thread(target=_recv_thread_worker, args=(flow_name, peer_flow_name, q, filename, stop_event), 
                              daemon=True, name=f"recv_thread-{flow_name}")

    recv_thread_queues.append(q)
    recv_threads[flow_name] = {
        'thread': thread,
        'queue': q,
        'stop': stop_event,
        'file': filename,
        'flow': flow_name,
        'peer_flow': peer_flow_name,
    }
    thread.start()
    genlog.info(f"started recv_thread-{flow_name} for flow '{flow_name}' peer_flow '{peer_flow_name}' logging to {filename}")
    return c+1


def do_recv(act, c):
    if 'flow' not in act:
        raise Error('recv action requires flow')

    flow_name = act['flow']
    if flow_name not in flows:
        raise Error(f"Unknown flow: {flow_name}")

    fl = flows[flow_name]
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

    if 'load' in act:
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

    if fl.proto.lower() == peer_fl.proto.lower() == 'udp':
        return c+1
    elif fl.proto.lower() != peer_fl.proto.lower():
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


def do_noop(act, c):
    if 'name' in act:
        globals()[act['name']] = c
    return c+1


def do_send_peer(act, c):
    """Send a named event (with optional payload) to another replay_data process
    via Unix Domain Socket datagram.

    YAML:
        - send_peer:
            name: peer2        # destination peer name (must be in peers: dict)
            event: invite      # event label
            data: "{c2s.src}"  # optional; same {field} interpolation as send:
    """
    if 'name' not in act:
        raise Error("send_peer requires 'name'")
    if 'event' not in act:
        raise Error("send_peer requires 'event'")

    peer_name = act['name']
    event     = act['event']
    raw_data  = act.get('data', '')

    if peer_name not in peers:
        raise Error(f"send_peer: unknown peer '{peer_name}'")

    # Apply {{field}} interpolation identical to create_packet()
    patrn   = re.compile(r'\{([^}]+)\}')
    payload = patrn.sub(lambda m: str(flds_eval(m.group(1))), str(raw_data))

    dest_path = peers[peer_name]['socket']
    msg_bytes = json.dumps({
        'event': event,
        'data' : payload,
        'from' : _my_peer_name(),
    }).encode('utf-8')

    # Use a temporary unbound socket for sending so we don't need a second
    # bound socket; the receiver identifies us by the 'from' field in the JSON.
    s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    try:
        s.sendto(msg_bytes, dest_path)
        genlog.info(f"send_peer -> '{peer_name}' event='{event}' data='{payload}'")
    except OSError as e:
        raise Error(f"send_peer: failed to send to '{peer_name}' ({dest_path}): {e}")
    finally:
        s.close()

    return c + 1


def do_recv_peer(act, c):
    """Block until a named event arrives from another replay_data process.

    YAML:
        - recv_peer:
            event: invite      # event label to wait for
            name: peer1        # optional: only accept from this peer
            timeout: 10        # seconds (default RCV_TIMEOUT)

    Received payload is stored in peer_recv[event_name] (string).
    """
    if 'event' not in act:
        raise Error("recv_peer requires 'event'")

    if peer_event_q is None:
        raise Error("recv_peer: peer IPC not initialised (no peers: section?)")

    event     = act['event']
    from_peer = act.get('name', None)
    to        = act.get('timeout', RCV_TIMEOUT)
    deadline  = time.time() + to

    # Stash messages that don't match so we can put them back afterwards
    stash = []

    try:
        while True:
            remaining = deadline - time.time()
            if remaining <= 0:
                raise Error(f"recv_peer timeout waiting for event '{event}'")
            try:
                msg = peer_event_q.get(timeout=min(remaining, 0.5))
            except queue.Empty:
                if time.time() >= deadline:
                    raise Error(f"recv_peer timeout waiting for event '{event}'")
                continue

            if msg.get('event') != event:
                stash.append(msg)
                continue
            if from_peer and msg.get('from') != from_peer:
                stash.append(msg)
                continue

            # Match found
            globals()['peer_recv'][event] = msg.get('data', '')
            genlog.info(f"recv_peer <- '{msg.get('from')}' event='{event}' data='{msg.get('data','')}'")
            return c + 1
    finally:
        # Return non-matching messages to the queue in original order
        for m in stash:
            peer_event_q.put(m)


# --------------------------------------------------------------------------
#                                  DRIVER
# --------------------------------------------------------------------------

actions = {
        "delay"      : do_delay,
        "send"       : do_send,
        "recv"       : do_recv,
        "recv_thread": do_recv_thread,
        "create"     : do_create,
        "loop-start" : do_loop_start,
        "loop-end"   : do_loop_end,
        "save"       : do_save,
        "execute"    : do_execute,
        "connect"    : do_connect,
        "noop"       : do_noop,
        "send_peer"  : do_send_peer,
        "recv_peer"  : do_recv_peer,
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
    if 'recv_thread_queues' in globals():
        for q in recv_thread_queues:
            q.put(pkt)
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
    pktlog.setLevel(log_level)
    if (log_level == logging.DEBUG):
        loghdlr3 = logging.FileHandler("packet.log", mode='w')
        pktlog.addHandler(loghdlr3)


def init(logl):
    setup_logging(logl)


def setup(flows_dict, routes_f, params_f, pcap_f, proto, peers_dict=None):
    # global dicts
    global routing
    global routing_type
    global saved_pkts
    global fname
    global sniffer
    global rcvqueue
    global recv_thread_queues
    global recv_threads
    global recv          # last received packet
    global ip2dev_tbl
    global flows


    # routing
    ip2dev_tbl = dict()
    with open(routes_f, 'r') as f:
        routing = yaml.safe_load(f)
        for dev_name, ips in routing['interfaces'].items():
            for x in ips:
                ip2dev_tbl[x] = dev_name
        # source routing is default
        routing_type = Routing.dest if 'type' in routing and routing['type'] == "dest" else Routing.source

    if params_f:
        with open(params_f, 'r') as f:
            if not 'params' in globals():
                globals()['params'] = {}
            params.update(yaml.full_load(f))

    rcvqueue           = queue.Queue()
    recv_thread_queues = []
    recv_threads       = {}
    saved_pkts         = {}

    intfs = set()
    hosts = set()
    flows = {}
    for name, fl in flows_dict.items():
        flobj = Flow(fl, proto)
        globals()[name]= flobj
        flows[name]= flobj
        intfs.add(flobj.intf)
        hosts.add(flobj.src)

    fname = pcap_f
    fltr=' or '.join(map(lambda x: "host "+x, list(hosts)))
    sniffer = AsyncSniffer(prn=pkt_cb, filter=fltr, iface=list(intfs), store=(fname != None))
    sniffer.start()

    # Peer IPC — must come after flows are built so {field} interpolation works
    setup_peers(peers_dict)
   

def stop():
    global peer_socket
    if recv_threads:
       for thread_info in recv_threads.values():
           thread_info['stop'].set()
       for thread_info in recv_threads.values():
           thread_info['thread'].join(timeout=1)
    if sniffer:
        pktlst = sniffer.stop()
        if (fname):
            actlog.info(f"pcap saved: {fname}")
            wrpcap(fname, pktlst)
    if peer_socket:
        path = peer_socket.getsockname()
        try:
            peer_socket.close()
        except OSError:
            pass
        try:
            if path and os.path.exists(path):
                os.unlink(path)
        except OSError:
            pass
        peer_socket = None


def set_flow(flow_name, attr, val):
    setattr(flows[flow_name], attr, val)


def save_recv():
    with open("recv.yaml", 'w') as file:
        yaml.dump(globals()['recv'], file, default_flow_style=False, sort_keys=False)

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

    with open(args.testfile, 'r') as f:
        scen_dict = yaml.full_load(f)

    try:
        peers_dict = scen_dict.get('peers', None)
        if args.src_routes:
            setup(scen_dict['flows'], args.src_routes, args.params, fname, args.proto, peers_dict)
        else:
            setup(scen_dict['flows'], args.dst_routes, args.params, fname, args.proto, peers_dict)
       

    except KeyError as inst:
        genlog.critical ("KeyError: {}".format(inst))
        exit()
       
    try:
        time.sleep(3)
        run_scenario(scen_dict['scenario'])
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




