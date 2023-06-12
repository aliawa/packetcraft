#!/usr/bin/python

import argparse
import yaml
import queue
import textwrap
import logging
import ipaddress
import inspect
from scapy.all import *
import pdb


# -----------------------------------------------------------
#                          Configuration 
# -----------------------------------------------------------
RCV_TIMEOUT=10 # timeout in seconds


# -----------------------------------------------------------
#                            Defines
# -----------------------------------------------------------

class Flow:
    def __init__(self, fl):
        self.proto   = fl['proto']
        self.src     = fl['src']
        self.intf    = ip2dev(fl['src'])
        self.src_mac = ip2mac(fl['src'])
        self.ipid    = random.randint(1,100)
        self.seq     = 0
        self.ack     = 0
        self.ooq     = {}   # out of order queue

        if fl['sport'] == 'random':
            self.sport   = random.randint(3000,65535)
        else:
            self.sport   = str(fl['sport'])
        if 'dst' in fl:
            self.dst = fl['dst']
        if 'dport' in fl:
            self.dport = str(fl['dport'])
        if 'tos' in fl:
            self.tos = fl['tos']
        if 'mss' in fl:
            self.mss = fl['mss']

    def __repr__(self):
        d = {x:getattr(self,x) for x in dir(self) if not x.startswith('__')}
        return d.__str__()


class Error(Exception):
    def __init__(self, message):
        self.message=message


class NoRoute(Error):
    def __init__(self, message):
        super().__init__(message)





# --------------------------------------------------------------------------
#                                 ACTIONS
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
    if (Raw in pkt):
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



def do_delay(act, c):
    log_action("delay", act['timeout'], None)
    time.sleep(act['timeout']/1000)
    return c+1


def l3_l4_match(pkt, fl, act):
    if (fl.intf != pkt.sniffed_on):
        genlog.debug("intf no match expecting {} != pkt {}".format(fl.intf, pkt.sniffed_on))
        return False
    else:
        genlog.debug("intf match expecting {} = pkt {}".format(fl.intf, pkt.sniffed_on))

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
            genlog.debug("packet dort no match expecting {} != pkt dport {}".format(fl.sport, pkt[UDP].dport))
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
        elif Raw in pkt:
            endseq = sseq + len(pkt[Raw].load) 
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
        a1 = patrn.sub(lambda m: flds_get_val(m.group(1)), act['match'])
        genlog.debug(f"match string: '{a1}'")
        if (not re.match(a1, pkt[Raw].load.decode('utf8'))):
            genlog.warning("match '{}' failed in '{}'".format(a1, pkt[Raw].load.decode('utf8')))
            return False
    else:
        genlog.warning("match '{}' failed: No L7 data in pkt".format(act['match']))
        return False

    return True



def l7_search(pkt, fl, act):
    assert 'search' in act
    if (Raw in pkt):
        for itm in act['search']:
            genlog.debug(f"search pattern:{itm}") 
            m = re.search(itm, pkt[Raw].load.decode('utf8'))
            if m:
                genlog.debug("groupdict:{}".format(m.groupdict()))
                for key,val in m.groupdict().items():
                    genlog.debug(f"search got {key}={val}")
                dicts['payload'].update(m.groupdict())
            else:
                genlog.warning(f"[!] Warning: search failed {itm}")
    else:
        genlog.warning("[!] Warning: search failed because pkt has no payload")


def echo(pkt, fl, act):
    assert 'echo' in act
    print(act['echo'])


def flds_eval(exp):
    lst = exp.split()
    if len(lst) > 2:
        lhs,op,rhs = lst
        ops = set("+-/*")
        if op in ops:
            if op == '+':
                return str(int(flds_get_val(lhs)) + int(flds_get_val(rhs)))
            elif op == '-':
                return str(int(flds_get_val(lhs)) - int(flds_get_val(rhs)))
            elif op == '*':
                return str(int(flds_get_val(lhs)) / int(flds_get_val(rhs)))
            elif op == '/':
                return str(int(flds_get_val(lhs)) * int(flds_get_val(rhs)))

    return flds_get_val(exp)


def flds_get_val(var):
    if var[0] == "'" or var.isdigit():
        if var.isdigit():
            return int(var)
        else:
            return var
    elif "." in var:
        fld_d,_,fld_n = var.partition('.')
        if fld_d in dicts['flows'].keys():
            return str(getattr(dicts['flows'][fld_d], fld_n))
        else:
            return dicts[fld_d][fld_n]
    else:
        return dicts['payload'].get(var, None)

        

def update_flow(pkt, fl, act):
    assert 'exec' in act
    assert 'pkt' in dicts, "pkt dictionary is required"
    for itm in act['exec']:
        cmd = itm.partition('=')
        lhs = cmd[0].partition('.')     # <flow_name>, '.', <Flow attribute>
        rhs = cmd[2].strip()

        # if condition implementation
        m=re.match(r'{\s*(?P<fld1>[^ :]+)\s*:\s*(?P<fld2>[^ }]+)\s*}', rhs)
        if m :
            flds = m.groupdict()
        else:
            flds = {'fld1':rhs}

        for i in flds.values():
            val = flds_get_val(i)
            if val: break
    
        if not val:
            genlog.error(f"[!] Warning: key {flds.values()} not found")
            raise(ValueError)
        else:
            setattr(dicts['flows'][lhs[0]], lhs[2], val)
            genlog.debug(f"set attribute: Flow['{lhs[0]}'].{lhs[2]} = {val}")




def l7_verify(pkt, fl, act):
    assert 'verify' in act
    assert isinstance(act['verify'], list), 'Verify is not a list'
    assert 'payload' in dicts, 'Payload dictionary is required'
    for itm in act['verify']:
        cmd = re.split(r'\s*==\s*', itm)
        assert len(cmd) <= 2

        if '.' in cmd[0]:
            lhs = cmd[0].partition('.')
            lhs_d,_,lhs_n = lhs
        else:
            lhs_d = 'payload'
            lhs_n = cmd[0]
        if not lhs_d in dicts:
            genlog.error(f"[!] Error: dict '{lhs_d}' not found")
            raise KeyError

        if dicts[lhs_d][lhs_n] != flds_get_val(cmd[1]):
            genlog.info(f"verification failed: {lhs_d}.{lhs_n} != {flds_get_val(cmd[1])}, found:{dicts[lhs_d][lhs_n]}")
            raise Error("Verify failed")
        else:
            genlog.info(f"verified: {lhs_d}.{lhs_n} == {flds_get_val(cmd[1])}")


def update_dicts(pkt):
    dicts['pkt'] = {}
    dicts['payload']={}

    if IP in pkt:
        dicts['pkt']['src'] = pkt[IP].src
        dicts['pkt']['dst'] = pkt[IP].src
    if TCP in pkt:
        dicts['pkt']['sport'] = pkt[TCP].sport
        dicts['pkt']['dport'] = pkt[TCP].dport
        dicts['pkt']['seq'] = pkt[TCP].seq
    elif UDP in pkt:
        dicts['pkt']['sport'] = pkt[UDP].sport
        dicts['pkt']['dport'] = pkt[UDP].dport
    if Raw in pkt:
        try:
            dicts['payload']['len'] = len(pkt.load.decode('utf8'))
        except UnicodeDecodeError:
            dicts['payload']['len'] = len(pkt.load)
    else:
        dicts['payload']['len'] = 0




def do_recv(act, c):
    fl = dicts['flows'][act['flow']]
    genlog.debug("\n{} on intf {}".format(inspect.stack()[0][3], fl.intf))
    to = act['timeout'] if 'timeout' in act else RCV_TIMEOUT

    while True:
        try:
            pkt = rcvqueue.get(block=True, timeout=to)
        except queue.Empty:
            genlog.critical ("receive failed")
            raise Error("receive timeout")

        if l3_l4_match(pkt, fl, act) == True:
            log_action("recv", act['flow'], pkt)
            update_l3_l4(fl,pkt)
        else:
            continue

        if 'match' in act: 
            if l7_match(pkt, fl, act):
                genlog.info(f"match success: '{act['match']}'")
            else:
                continue

        update_dicts(pkt)

        if ("echo" in act):
            echo(pkt, fl, act)
        if ("search" in act):
            l7_search(pkt, fl, act)
        if "exec" in act:
            update_flow(pkt, fl, act)
        if "verify" in act:
            l7_verify(act, fl, act)

        unknown_a = [ a for a in act.keys() if a not in ['flow','search','verify','exec','flags','match','echo']]
        for x in unknown_a:
            genlog.warning(f"WARNING: Unknown action:{x}")

        return c+1




def ip2mac(ip):
    for dev,val in routing['interfaces'].items():
        if ip in val['ips']:
            return val['mac']
    raise Error (f"[x] No mac for {ip}")


def ip2dev(ip):
    for dev,val in routing['interfaces'].items():
        if ip in val['ips']:
            return dev
    raise Error (f"[x] No device for {ip}")


def ip2route(ip):
    ipadr = ipaddress.ip_address(ip)
    for net in routing['routing']:
        if ipadr in ipaddress.ip_network(net):
            return routing['routing'][net]
    raise Error (f"No route to {ip}")



def create_packet(act):
    genlog.debug("{} called from {}".format(inspect.stack()[0][3],inspect.stack()[1][3]))

    fl = dicts['flows'][act['flow']]
    if (fl.dst == None):
        genlog.error("[x] Error: No destination ip for {}".format(act['flow']))
        raise Error ("No destination ip for {}".format(act['flow']))
    if (fl.dport == None):
        genlog.error ("[x] Error: No destination port for {}".format(act['flow']))
        raise Error ("No destination port for {}".format(act['flow']))

    # Ether/IP
    ip_layr = Ether(src=fl.src_mac, dst=(ip2route(fl.dst)['next-hop'])) / IP(src=fl.src,dst=fl.dst) 
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
            patrn = re.compile(r'\{([^}]+)\}')
            #a1 = patrn.sub(lambda m: flds_get_val(m.group(1)), act['data'])
            a1 = patrn.sub(lambda m: flds_eval(m.group(1)), act['data'])
            data = "".join(a1.split('\n'))

            # replace literal \r\n 
            data = data.replace(r'\r','\r')
            data = data.replace(r'\n','\n')
            pkt = pkt/data
            genlog.debug(f"payload size: {len(data)}")

            if pkt.haslayer(TCP):
                pkt[TCP].flags='PA'
                fl.seq+=len(data)

        elif type(act['data']) == bytes:
            pkt = pkt/act['data']

            if (pkt.haslayer(TCP)):
                pkt[TCP].flags='PA'
                fl.seq+=len(act['data'])

        else:
            raise Error("Unknown send data type")

    return pkt


def do_send(act, c):
    genlog.debug("\n{} called from {}".format(inspect.stack()[0][3],inspect.stack()[1][3]))

    if 'name' in act:
        pkt = saved_pkts[act['name']]
    else:
        pkt = create_packet(act)

    fl = dicts['flows'][act['flow']]
    intf = ip2route(fl.dst)['dev']

    if TCP in pkt:
        genlog.debug("send to {}:{} intf {}".format(pkt[IP].dst, pkt[TCP].dport, intf))
    elif UDP in pkt:
        genlog.debug("send to {}:{} intf {}".format(pkt[IP].dst, pkt[UDP].dport, intf))

    sendp(pkt, iface=intf, verbose=False)
    log_action("send", act['flow'], pkt)

    if 'save' in act:
        saved_pkts[act['save']] = pkt

    if ("echo" in act):
        echo(pkt, fl, act)

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
    if not 'loop' in dicts:
        dicts['loop'] = {}

    if 'jump' in dicts['loop']:
        raise Error('Nested loops are not allowed')
    if 'count' in act:
        dicts['loop']['count'] = act['count']-1
    else:
        raise Error("count is mandatory in loop")
    dicts['loop']['jump'] = c+1
    return c+1



def do_loop_end(act, c):
    if not 'count' in dicts['loop']:
        raise Error("loop-end without loop-start")

    if dicts['loop']['count'] > 0:
        dicts['loop']['count'] -= 1
        return dicts['loop']['jump']
    else:
        del (dicts['loop']['jump'])
        del (dicts['loop']['count'])
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
        "loop-end"   : do_loop_end
        }


def run_scenario(scenario):
    cur  = 0
    end  = len(scenario)
    while cur < end:
        act, val = next(iter(scenario[cur].items()))
        cur = actions[act](val, cur)



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
            pktlog.debug(textwrap.indent(pkt.load.decode('utf8'), '    '))
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

def setup(scenario_f, routes_f, params_f, pcap_f):
    global dicts
    global routing
    global scenario
    global saved_pkts
    global fname
    global sniffer
    global rcvqueue

    with open(scenario_f, 'r') as f:
        scen_dict = yaml.load(f, Loader)

    with open(routes_f, 'r') as f:
        routing = yaml.load(f, Loader)

    dicts = {}
    if params_f:
        with open(params_f, 'r') as f:
            dicts.update(yaml.safe_load(f))

    rcvqueue       = queue.Queue()  
    saved_pkts     = {}
    dicts['flows'] = { name:Flow(fl) for name, fl in scen_dict['flows'].items() }
    fname          = pcap_f

    intfs = { fl.intf for fl in dicts['flows'].values() }
    hosts = { fl.src for fl in dicts['flows'].values() }
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
    parser = argparse.ArgumentParser(description="execute tests")
    parser.add_argument('-t', '--testfile', help='testfile name')
    parser.add_argument('-s', '--savepcap', action='store_true', help='save pcap file')
    parser.add_argument('-l', '--log', choices=['DEBUG','INFO','WARNING','ERROR','CRITICAL'], help='Set logging level', default='CRITICAL')
    parser.add_argument('-r', '--routes', help='routing file')
    parser.add_argument('-p', '--params', help='parameter file')

    # This is needed otherwise packet will appear twice in pcap
    conf.sniff_promisc=0
    conf.promisc=0

    args=parser.parse_args()
    init(getattr(logging, args.log))

    with open(args.testfile, 'r') as f:
        dictionary = yaml.load(f, Loader)

    with open(args.routes, 'r') as f:
        routing = yaml.load(f, Loader)

    dicts = {}
    if args.params:
        with open(args.params, 'r') as f:
            dicts.update(yaml.safe_load(f))

    if args.savepcap:
        fname_b = os.path.basename(args.testfile)
        fname = os.path.splitext(fname_b)[0] + "_send.pcap"
    else:
        fname = None


    scenario = setup(args.testfile, args.routes, args.params, fname)
    time.sleep(3)

    try:
        run_scenario(scenario)

    except KeyError as inst:
        genlog.critical ("KeyError: {}".format(inst))
        raise
    except Error as err:
        genlog.critical ("Error: {}".format(err))
    finally:
        stop()




