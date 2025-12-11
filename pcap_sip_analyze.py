import pyshark
import os
import sys # Import the sys module to handle command-line arguments
import argparse
import re
from typing import Iterator, List
import difflib
from rich.console import Console
from rich.table import Table
from rich import box
from rich import print
import shutil

log_output_dir = "panlog_segs"


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

def print_pkt(pkt, lst, file=None):
        protocol = pkt.transport_layer
        src_ip   = pkt.ip.src
        src_port = pkt[pkt.transport_layer].srcport
        dst_ip   = pkt.ip.dst
        dst_port = pkt[pkt.transport_layer].dstport

        if file:
            line = fr"\[{int(pkt.ip.id,16)}] {src_ip}/{src_port} -> {dst_ip}/{dst_port} {protocol} \[{file}]"
        else:
            line = fr"\[{int(pkt.ip.id,16)}] {src_ip}/{src_port} -> {dst_ip}/{dst_port} {protocol}"

        lst.append(line)

        if hasattr(pkt.sip, "method"):
            line = f"{pkt.sip.request_line}"
        else:
            line = f"{pkt.sip.status_line}"
        lst.append(line)

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
                line = f"{pname}: {val}"
                lst.append(line)


def find_pkt(pkt, filehash):
    key = sip_key(pkt)
    for fname, dic in filehash.items():
        if key in dic['hash'] and len (dic['hash'][key]):
            idx = dic['hash'][key].pop(0)
            return (dic['capture'][idx], fname)
    return None





TIMESTAMP_PATTERN = re.compile(r"^== \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3} -0800 ==$")

def panlog_read_block(path: str):
    current_block = []
    linenr=0
    with open(path, 'r') as f:
            for line in f:
                linenr+=1
                if TIMESTAMP_PATTERN.match(line):
                    # When a new pattern is found, yield the completed previous block
                    if current_block:
                        yield linenr, "".join(current_block)
                    # Start a new block with the current matching line
                    current_block = [line]
                else:
                    # Append non-pattern lines to the current block
                    current_block.append(line)
            
            # Yield the very last block after the loop finishes
            if current_block:
                yield linenr, "".join(current_block)



def process_block(text, lnr:int, xhash:dict, re_srch) -> None:
    match = re_srch.search(text)
    if match:
        key=f"{match.group('saddr')}{match.group('sport')}{match.group('daddr')}{match.group('dport')}{match.group('ipid')}"
        xhash[key] = lnr
        return True
    else:
        return False


def print_diff(lst1, lst2, outlst):
    dfr = difflib.Differ()
    if len(lst2) == 0:
        outlst.append("[red]\[missing][/]")
        return

    for lhs, rhs in zip(lst1, lst2):
        result = list(dfr.compare(lhs.split(), rhs.split()))
        seq1 = []
        seq2 = []

        for line in result:
            txt = line.split(" ", 1)
            if txt[0] == '-':
                seq1.append(txt[1].strip())
            elif txt[0] == '+':
                seq2.append(f"[yellow]{txt[1].strip()}[/]")
            elif txt[0] == '?':
                pass
            else:
                seq1.append(txt[1].strip())
                seq2.append(txt[1].strip())
        lhs_str = ' '.join(seq1)
        rhs_str  = ' '.join(seq2)
        outlst.append(rhs_str)



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


def print_table(table, lst1, lst2, log):
    txt1 = "\n".join(lst1)
    txt2 = "\n".join(lst2)
    if (len(table.columns) == 2):
        table.add_row(txt1, txt2)
    if (len(table.columns) == 3):
        table.add_row(txt1,txt2,str(log))

def rich_table_init(logname):
    table = Table(title=None, leading=1, box=box.HORIZONTALS)
    table.add_column("rx", no_wrap=False)
    table.add_column("tx")
    if logname:
        table.add_column("log", min_width=5)
    return table


def process_packets(pcap_file, filehash, logname, loghash, bcolor):
    capture = pyshark.FileCapture(
        input_file=pcap_file,
        display_filter='sip',
        only_summaries=False,
        keep_packets=False
    )

    # initilize table
    table = rich_table_init(logname)

    for pkt in capture:
        lst1 = []
        lst2 = []
        if 'sip' in pkt:
            print_pkt(pkt, lst1)
            proc_pkt = find_pkt(pkt, filehash )
            if proc_pkt:
                print_pkt(proc_pkt[0], lst2, proc_pkt[1])

            lst2_diff=[]
            print_diff(lst1, lst2, lst2_diff)

            lognr = 0
            if (logname):
                logkey = f"{pkt.ip.src}{pkt[pkt.transport_layer].srcport}{pkt.ip.dst}{pkt[pkt.transport_layer].dstport}{int(pkt.ip.id,16)}"
                if logkey in loghash:
                    lognr = loghash[logkey]
                
            print_table(table, lst1, lst2_diff, lognr)

    term_opt = None
    if bcolor == "always":
        term_opt = True
    console = Console(force_terminal=term_opt)
    console.print(table)


def save_block(block, lnr):
    output_path = os.path.join(log_output_dir, f"{lnr}.txt")
    with open(output_path, 'w') as out_f:
        out_f.write(block)


def main (args):
    if not os.path.exists(args.pcaps[0]):
        print(f"Error: PCAP file not found at '{pcap_file_path}'")
        return

    filehash = {}
    for f in args.pcaps[1:]:
        filehash[f]={}
        capture, xhash = hash_pcaps(f)
        filehash[f]['capture'] = capture
        filehash[f]['hash'] = xhash

    loghash = {}
    if (args.log):
        if os.path.exists(log_output_dir):
            try:
                shutil.rmtree(log_output_dir)
            except OSError as e:
                print(f"Error removing directory {directory_path}: {e}")
                return
        os.makedirs(log_output_dir)

        IP_RE = re.compile(r'IP:\s+(?P<saddr>\d+.\d+.\d+.\d+)->(?P<daddr>\d+.\d+.\d+.\d+), protocol \d+\n'
                           r'\s+version \d, ihl \d, tos 0x[0-9a-fA-F]+, len \d+,\n'
                           r'\s+id (?P<ipid>\d+), frag_off 0x\d+, ttl \d+, checksum \d+\(0x\w+\)\n'
                           r'[TU][CD]P:\s+sport (?P<sport>\d+), dport (?P<dport>\d+),')
        for lnr, block in panlog_read_block(args.log):
            if process_block(block, lnr, loghash, IP_RE):
                save_block(block, lnr)

    process_packets(args.pcaps[0], filehash, args.log, loghash, args.color)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--log', type=str, help="log file name")
    parser.add_argument('--color', type=str, choices=['always','auto'], help="color")
    parser.add_argument('pcaps', nargs='+', help='pcap files')
    main (parser.parse_args())

