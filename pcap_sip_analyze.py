import pyshark
import os
import sys # Import the sys module to handle command-line arguments

def pcap_walk_hash(pkt, idx, xhash):
    if 'sip' in pkt:
        key = pkt.ip.id + pkt.sip.via_branch 
        if hasattr(pkt.sip, "method"):
            key += pkt.sip.method
        else:
            key += pkt.sip.status_code

        xhash[key] = idx

def print_pkt(pkt, file=None):
        protocol = pkt.transport_layer
        src_ip   = pkt.ip.src
        src_port = pkt[pkt.transport_layer].srcport
        dst_ip   = pkt.ip.dst
        dst_port = pkt[pkt.transport_layer].dstport
        if file:
            print(f"{src_ip}/{src_port} --> {dst_ip}/{dst_port}/{protocol} -> [{file}]")
        else:
            print(f"{src_ip}/{src_port} --> {dst_ip}/{dst_port}/{protocol} ")
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


def parse_sip_packets(pcap_file, filehash):
    capture = pyshark.FileCapture(
        input_file=pcap_file,
        display_filter='sip',
        only_summaries=False,
        keep_packets=False
    )
    for pkt in capture:
        if 'sip' in pkt:
            print("-" * 75)
            print_pkt(pkt)
            key = pkt.ip.id + pkt.sip.via_branch 
            if hasattr(pkt.sip, "method"):
                key += pkt.sip.method
            else:
                key += pkt.sip.status_code
            for fname, dic in filehash.items():
                if key in dic['hash']:
                    print()
                    print_pkt(dic['capture'][dic['hash'][key]], file=fname)
       

if __name__ == "__main__":
    # sys.argv[0] is the script name itself.
    # We expect sys.argv[1] to be the PCAP file path.
    if len(sys.argv) < 2:
        print("Usage: python sip_parser.py <path_to_pcap_file>")
        print("\nExample: python sip_parser.py my_sip_trace.pcap")
    else:
        filehash = {}
        for f in sys.argv[2:]:
            filehash[f] = {}
            xhash = {}
            # print (f"Using file:{f}")
            capture = pyshark.FileCapture(f,
                    display_filter='sip',
                    only_summaries=False,
                    keep_packets=True
                    )
            for i, pkt in enumerate(capture):
                if 'sip' in pkt:
                    key = pkt.ip.id + pkt.sip.via_branch 
                    if hasattr(pkt.sip, "method"):
                        key += pkt.sip.method
                    else:
                        key += pkt.sip.status_code

                    print (f"{key}:{i}")
                    xhash[key] = i

            filehash[f]['capture'] = capture
            filehash[f]['hash'] = xhash

        rx = sys.argv[1]
        if not os.path.exists(rx):
            print(f"Error: PCAP file not found at '{pcap_file_path}'")
        else:
            parse_sip_packets(rx, filehash)

            



