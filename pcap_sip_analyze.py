import pyshark
import os
import sys # Import the sys module to handle command-line arguments
import argparse
import re
from typing import Iterator, List
import difflib

def sip_key(pkt):
    key = pkt.sip.via_branch 
    if hasattr(pkt.sip, "method"):
        key += pkt.sip.method
    else:
        key += pkt.sip.status_code
    return key

def pcap_walk_hash(pkt, idx, xhash):
    if 'sip' in pkt:
        key = sip_key(pkt)
        xhash[key] = idx

def print_pkt(pkt, file=None, pre="   "):
        protocol = pkt.transport_layer
        src_ip   = pkt.ip.src
        src_port = pkt[pkt.transport_layer].srcport
        dst_ip   = pkt.ip.dst
        dst_port = pkt[pkt.transport_layer].dstport
        # if file:
        print(f"{pre} [{int(pkt.ip.id,16)}] {src_ip}/{src_port} -> {dst_ip}/{dst_port} {protocol} [{file}]")
        # else:
        #     print(f"{pre} {src_ip}/{src_port} --> {dst_ip}/{dst_port}/{protocol} ")
        if hasattr(pkt.sip, "method"):
            print(f"    {pkt.sip.request_line}")
        else:
            print(f"    {pkt.sip.status_line}")
        headers = {'via':'Via',
                   'contact':'Contact', 
                   'cseq':'CSeq', 
                   'sdp_media':'m', 
                   'sdp_connection_info':'c'
                   }
        for name,pname in headers.items():
            val = pkt.sip.get_field(name)
            if val:
                if name == 'contact':
                    val = val.split(';',1)[0]
                print(f"    {pname}: {val}")
        print()


def find_pkt(pkt, filehash):
    key = sip_key(pkt)
    for fname, dic in filehash.items():
        if key in dic['hash'] and len (dic['hash'][key]):
            idx = dic['hash'][key].pop(0)
            return (dic['capture'][idx], fname)
    return None




HEADER_RE = re.compile(r"^== 20\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d\d\d -0\d\d\d ==$")
linenr=0

def panlog_read_block(path: str) -> Iterator[List[str]]:
    with open(path, "r", encoding="utf-8") as f:
        collecting = False
        global linenr
        buf: List[str] = []
        for raw in f:
            linenr = linenr +1
            line = raw.rstrip("\n")
            if not collecting:
                if HEADER_RE.match(line):
                    collecting = True
                    hlinenr = linenr
                    buf = [line]
            else:
                if line == "":
                    yield (hlinenr, buf)
                    collecting = False
                    buf = []
                else:
                    buf.append(line)
        if collecting and buf:
            yield (hlinenr, buf)


def process_block(lines: List[str], lnr:int, xhash:dict, re_srch) -> None:
    text = "\n".join(lines)
    match = re_srch.search(text)
    if match:
        key=f"{match.group('saddr')}{match.group('sport')}{match.group('daddr')}{match.group('dport')}{match.group('ipid')}"
        # print (f"stored: {key}")
        xhash[key] = lnr
    # else:
    #     print (f"no match:{lnr}")


def hash_pcaps(pcap):
        xhash = {}
        capture = pyshark.FileCapture(pcap,
                display_filter='sip',
                only_summaries=False,
                keep_packets=True
                )
        for i, pkt in enumerate(capture):
            if 'sip' in pkt:
                key = pkt.sip.via_branch 
                if hasattr(pkt.sip, "method"):
                    key += pkt.sip.method
                else:
                    key += pkt.sip.status_code

                if key in xhash:
                    # this is a re-transmission
                    xhash[key].append(i)
                else:
                    xhash[key] = [i]
        return capture, xhash



def parse_sip_packets(pcap_file, filehash, logname, loghash):
    capture = pyshark.FileCapture(
        input_file=pcap_file,
        display_filter='sip',
        only_summaries=False,
        keep_packets=False
    )
    for pkt in capture:
        if 'sip' in pkt:
            print_pkt(pkt, pcap_file, pre="-->")
            proc_pkt = find_pkt(pkt, filehash )
            if proc_pkt:
                print_pkt(proc_pkt[0], proc_pkt[1], pre="<--")

            if (logname):
                logkey = f"{pkt.ip.src}{pkt[pkt.transport_layer].srcport}{pkt.ip.dst}{pkt[pkt.transport_layer].dstport}{int(pkt.ip.id,16)}"
                # print (f"search: {logkey}")
                if logkey in loghash:
                    print (f"<-- {logname}: {loghash[logkey]}")
                    print()
                

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--log', type=str, help="log file name")
    parser.add_argument('pcaps', nargs='*', help='pcap files')
    args = parser.parse_args()

    filehash = {}
    for f in args.pcaps[1:]:
        filehash[f]={}
        capture, xhash = hash_pcaps(f)
        filehash[f]['capture'] = capture
        filehash[f]['hash'] = xhash

    loghash = {}
    if (args.log):
        IP_RE = re.compile(r'IP:\s+(?P<saddr>\d+.\d+.\d+.\d+)->(?P<daddr>\d+.\d+.\d+.\d+), protocol \d+\n'
                           r'\s+version \d, ihl \d, tos 0x[0-9a-fA-F]+, len \d+,\n'
                           r'\s+id (?P<ipid>\d+), frag_off 0x\d+, ttl \d+, checksum \d+\(0x\w+\)\n'
                           r'[TU][CD]P:\s+sport (?P<sport>\d+), dport (?P<dport>\d+),')
        for lnr, block in panlog_read_block(args.log):
            process_block(block, lnr, loghash, IP_RE)

    if not os.path.exists(args.pcaps[0]):
        print(f"Error: PCAP file not found at '{pcap_file_path}'")
    else:
        parse_sip_packets(args.pcaps[0], filehash, args.log, loghash)

            



