from sys import argv
from scapy.all import rdpcap, IP, Raw
from os import path

def help_text(sname):
    dirname, fname = path.split(sname)
    print(f"Usage:")
    print(f"    python {fname} <pcap-file>")
    print () 
    print(" Dumps the payload of all packets that have payload" )
    print(" Replaces <NL> and <CR> in payload with \\r and \\n" )
    print () 

def dump_payload(pcap):
    for pkt in rdpcap(pcap):
        if Raw in pkt: 
            payload = pkt[Raw].load.decode('utf8')
            for r in (("\r","\\r"),("\n","\\n\n")):
                payload = payload.replace(*r)
            print (payload)
            print("------------------")

if __name__ == '__main__':
    if len(argv) < 2 or argv[1] == '-h':
        help_text(argv[0])
    else:
        dump_payload(argv[1])
