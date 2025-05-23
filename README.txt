*--------------------------------------------------------------------*
|                                                                    |
|                           replay_data.py                           |
|                                                                    |
*--------------------------------------------------------------------*


Required Modules
----------------------------------------------------------------------
pip		    apt install python3-pip
scapy	    apt install python3-scapy
pyyaml
textwrap3	python3 -m pip install textwrap3


Need for a protocol traffic generator
----------------------------------------------------------------------
Why a black box testing tool is needed
 - We can look at if a predict is created or what is the value of the counter etc. 
   but it will still not tell us if a SIP Call will work

 - When replaying TCP traffic the ACK number should match the seq-nr + data-len of 
   the last received packet. This is not possible to do with tcpreplay

 - if the interestin thing happens when processing the 150th packet in the pcap. Then with pcap
   replay you have to replay all 150 packets while with data_replay we an extract the 15th packet
   and replay just that. 

 - Full control of payload
   Line endings are not added automatically, This is to give control becasue
   somtimes when the body is xml the lines end with '\n' only and not '\r\n'



Features
----------------------------------------------------------------------
- Update the dst-address/port of the flow that received a response.
- Update the dst-address/port of a different flow: For example the control
  flow updating the RTP flow.
- extract data from received packets for example ip-address, port, this could
  be different from the sent data because of NAT
- insert extracted data from received packets into the sent packets.
- receive timesout after 10 seconds but the period can be customized using the "timeout" command



Packet Payload
----------------------------------------------------------------------
Data can be of three types
- text
- text with fields
- binary.
- rtp 

Fields can be inserted that were extracted from the received packets.

If the spaces are important in the data, for example in case of formated xml
use "data: |", otherwise use "data: |-". "|-" will strip extra white spaces

use "data: |2" to tell how many indent spaces, this is usefull if the payload starts
with spaces
Example: 
- send:
    flow: c2s
    data: |2
      \n
      x-my=0\r\n

injecting data in L7 payload:
Following forms are supported:
- {<flow_name>.<Flow field>}
- {<field name from 'payload' dictionary>}
Addition, subtraction, multiplication and division are supported
- {c2s.dport + 1}

Example:
Transport: RTP/AVP/UDP;unicast;client_port={client_rtp}-{client_rtcp};server_port={s2c_rtp.sport}-{s2c_rtcp.sport}



Flow
----------------------------------------------------------------------
The flow is like a socket if the both souce and destination are given
then it is a client socket. If only the src is given then it is a listen 
socket.

Select random client port
flows:
  'c2s':
     proto: tcp
     src: 192.168.0.113
     sport: 'random_num(6000, 8000)'


mtu:
if the flow has mtu defined then the packets will be framented so 
that the IP payload does not exceed the MTU


mss:
if mss is defined it is put in TCP header but it is not used to actually
change the size of tcp packets.


tos:
if tos is specified, it will be inserted into the IP header



Receive Actions
----------------------------------------------------------------------
- search and exec are lists
- match is not a list
- Add a receive action even if no data needs to be extracted to update the TCP ACK counter

When receive fails, exception is thrown to indicate that the test has failed



Dictionaries avaialable for commands
----------------------------------------------------------------------
    objects:
        All flow names become global objects
        c2s.dst
        s2c.src 

    recv dicts:
        recv[]:
        search fields will go into the global dict 'recv' by default
        if the search field is 'rtp_port' then it will be accessed as recv['rtp_port']
        if the recv action has a name then the search field will go in the named dict
        for example if the recv action is named inv then the field will be accessed as inv['dport']

        pkt: 
        The last received packet. All scapy accessors will work
               pkt[Raw].len 
               pkt[IP].src
               pkt[TCP].sport
        param:
            the param dictionary specified by "-p params.yaml" on the command line
            match: 'REGISTER sip:{param.ruri_ip} SIP/2.0'


Helper functions:
----------------------------------------------------------------------
    random_num(a, b)     # returns random number N such that a <= N <= b
    is_valid_ip4(string)
    is_valid_port(int)



Define a new global variable 
----------------------------------------------------------------------
execute: 
    - global cid; cid=random_num(10,99)



Example usage of dictionaries:
    statement                       Meaning
    ----------------------------    --------------------------------------
    c2s.port = '132'                flows['c2s'].port = 132
    c2s.dst = pkt.src               flows['c2s'].dst = fields['pkt.src']
    c2s.dst={destination:IP.src}    flows['c2s'].dst = fields['destination'] if 'destination' in fields else fields['IP.src']



Commands
----------------------------------------------------------------------
- connect:
    flow: ...
    peer_flow: ...
    do tcp-handshake between the two given flows. The initiating flow must have
    dst and dport specified.
    This command has no effect when the two flows are udp, so it can be safely
    used with udp scenarios

- recv:
    Add a recv action even if no data needs to be extracted to update the ACK
    counter
    timeout: timeout in seconds or 'None' if need to wait indefinetly


- create:
    packet is created but not sent. It is created at a point in scenario so it
    gets correct seq and ack numbers but sent later simulating delay
    name: ack_1     # name to use in send action


- match:  (string)
    Regex match at begining of payload
    No fields can be extracted
    Only one match expression is allowed
    Example: Use of variables in match
    match: 'INVITE sip:1028@{param.ruri_ip}:{param.ruri_port} SIP/2.0'


- search: (list)
    all found fields are stored in fields dictionary
    if search fails no error reported, and we don't ignore the packet


- exec: (list)
    extracted fields are assigned to flows dictionary. Exec only updates the flow
    s2c_rtp.dport=client_rtp
    c2s_rtp.dst={source:pkt.src}

    c2s_rtp.dst = {payload.source : pkt.src}
    c2s_rtp.dst = {source : pkt.src}              # use "source" if source is in "payload" dictionary else use pkt.src
                                                  # from 'pkt' dictionary
    c2s_rtp.dst = {source : '1.1.1.1'}            # use "source" if source is in "payload" dictionary else use pkt.src
    c2s_rtp.dst = pkt.src
    c2s_rtp.dst = via_src                         # use default dict 'payload'
    c2s_rtp.dst = payload.via_src                 # dict is specified


- verify: (list)
    verify values in fields dict against the parameters dict
    payload.via_src == invite.via_src            # compare payload field with parameter field 
    via_src == invite.via_src                    # compare implicit payload field with parameter field 
    via_src == contact_src                       # compare two fields in payload
    payload.len == 1460                          # compare payload length as integer
    pkt.seq == 2315                              # compare tcp seq as integer
    contact_ip == param.contact_ip               # compare with a separate parameters file


- send:
    name: 'ref-2'   # retrieve saved packet with this name and send it
    save: 'ref-2'   # save the packet for future use with name

    if send fails exception is thrown to indicate the test has failed

- loop-start:
- loop-end
    loop acts like a do-while loop. The body is executed at least
    once, the counter is checked at loop end and if still not zero then 
    the body of loop is executed again
    Example:
      - loop-start:
        - count: 44

      - loop-end:


- echo
    Debugging help
    echo: "blah blah"


# save fragments for later use
- save:
    body1: | 
      v=0\r\n
      o=user1 53655765 2353687637 IN IP4 {c2s.src}\r\n
      s=-\r\n
      c=IN IP4 {c2s.src[:2]}
    body2: |
      {c2s.src[3:]}\r\n
      t=0 0\r\n
      m=audio {random_num(10000,15000)} RTP/AVP 0\r\n
      a=rtpmap:0 PCMU/8000\r\n


Implementation
----------------------------------------------------------------------
Sending packet
  need outgoing intf            use ip2mac
  dst-ip --> outgoing-intf
  dst-mask --> outgoing-intf

  need src mac address
  flow-src-ip --> intf --> mac

  need dst mac address
  dst-ip --> dst-intf --> mac

receiving packet:
  need flow intf to match incoming packets
  flow-src-ip --> intf (or incoming interface for this ip)


ip2mac:
    get the mac address of the interface which has the given ip

ip2dev:
    get the device name of the interface which has the given ip

ip2route:
    get the route entry for the given ip, which consists of next-hop mac address and 
    name of the egress interface.

Loop implementation
dicts['loop']:
    count: current count of loop, decremented at each iteration
    jump: the location to jump to from loop-end




Search in SIP Examples
----------------------------------------------------------------------
Via Header::
'Via: SIP/2.0/TCP (?P<client_ip>[\d.]+):(?P<client_port>\d+);'
'^(?P<via_ip>\d+.\d+.\d+.\d+):(?P<via_port>\d+);branch='

Contac Header::
'Contact:\s*sip:[^@]+@(?P<contact_ip>[\d.]+):(?P<contact_port>\d+)'

SDP c::
'c=IN IP4 (?P<rtp_dst>.*)\r\n'

=== match in SIP
Request URI::
'{param.ruri_ip}:{param.ruri_port} SIP/2.0'

Content Length:
'\s+\d{3}\r\n'



Sending RTP
----------------------------------------------------------------------
- send:
    flow: s2c_rtp
    data: !rtp
        ssrc: 4567
        marker: 1
        payload: '12345'



Parsing L7 protocol
----------------------------------------------------------------------
- recv:
    flow: c2s_rtp
    l7-proto: "RTP"



Delay in milli-seconds
----------------------------------------------------------------------
- delay:
    timeout: 5


Debugging
----------------------------------------------------------------------
When -l DEBUG is specified all sent and received packets are dumped into
packet.log file

REPLAY-DATA
replay data tool can be used to replay a scenario described in a yaml file.

replay_data.py -t test.yaml -r routing_conf.yaml -l INFO



Routing
-------
replay data uses its own routing rules, and interface confuguration that are 
independent of the underlying os routing. Therefore no routing or ip address
changes are required in the replay machine.

We can configure source based or destination based routing. 
When source based routing is used each entry specifies the egress-interface and next-hop
mac address for each source ip.
When destination based routing is used each entry specifies the egress-interface and next-hop
mac address for each destination netmask


Scenario
--------
A scenario consists of two parts.
    1. Flows
    2. packet exchange and verification rules

Flows:
Flows are like UDP/TCP connections used in the scenario. A flow is completely
specified by the usual 5-tuple. A server flow does not need to be completely
specified, the destination address/port can be populated when the first
client packet is received.

Packet exchange and verification rules:
The yaml file describes the content of the packets to be sent, and verification
rules when a packet is received. These rules can contain, regular expressions, 
exact text matches, fields extracted from payload or fields read from an 
external parameters files.



If condition
----------------------------------------------------------------------
c2s.dst={destination:IP.src}    flows['c2s'].dst = fields['destination'] if 'destination' in fields else fields['IP.src']



Convert a long text line to fixed length lines
--------------------------------------------------------------------------------
Break long output lines from base64 to fixed length lines to include in 
replay_data.py scenarios

Usage:
    split_base64.py <output line size>
Example:
    base64 dns_resp_local.bin | python3 split_base64.py 79
Sample use:
    replay_data.py -t protocol_tests/dns.yaml -r sip_tests/routing_192.yaml -l INFO


Out of order packets
----------------------------------------------------------------------
TODO, 


Example of sending binary packet
----------------------------------------------------------------------
rtp packet it processed using "base64 rtp.bin > rtp.txt"
- delay:
    timeout: 100
- send:
    flow: s2c_rtp
    data: !!binary |
      gAjnBwAAClDe4O6P1dXV1dXV1dXV1dXV1dXV1dXV1dXV1dXV1dXV1dXV1dXV1dXV1dXV1dXV1dXV
      1dXV1dXV1dXV1dXV1dXV1dXV1dXV1dXV1dXV1dXV1dXV1dXV1dXV1dXV1dXV1dXV1dXV1dXV1dXV
      1dXV1dXV1dXV1dXV1dXV1dXV1dXV1dXV1dXV1dXV1dXV1dXV1dXV1dXV1dXV1dXV1dXV1dXV1dXV
      1dXV1dXV1dXV1dXV1dXV1dXV1dXV1dXV1dXV1dXV1dXV1dXV1dXV1dXV1dXV1dXV1dXV1dXV1dXV
      1dXV1dXV1dXV1dXV1dXV1dXV1dXV1dXV


Options
----------------------------------------------------------------------
-pr 
    Specify transport protocol. It can be specified as 'udp' or 'tcp'



Logging
----------------------------------------------------------------------
all sent a received packets are logged in packet.log whenb level DEBUG
is set








#--------------------------------------------------------------------#
|                                                                    |
|                       pcap_dump_flow.py                            |
|                                                                    |
#--------------------------------------------------------------------#

Required Modules
----------------------------------------------------------------------
ruamel                          apt install python3-ruamel.yaml



python3 tcp_list_dataflow.py -pc 3286 -ipc 192.168.1.49 -o flow_c2s -r rx tx

The script filters out the stream to plot based on client ip and port. 
If there is NAT then -pcn and -ipcn must be provided to find the f2s 
(firewall-to-server) and s2f (server-to-firewall) flows

*   wrong sequence number or wrong ack number
+   retransmitted packet.

Output with sip_call using proxy. -flow_c2s

     id        seq   len       next              id        seq   len       next
    ----       ----  ----       ----            ----       ----  ----       ----
     42          0      0          1  -->|                                              SYN from client to fw
                                         |-->     42          0      0          1       SYN from fw to server
                                         |<--     17                            1       SYN/ACK from server to fw
     17                            1  <--|                                              SYN/ACK from fw to client
     43          1    617        618  -->|                                              INVITE from client, tcp payload len is 617, client is expection tcp-ack = 618
                                         |-->  24066          1    617        618       INVITE from proxy to server, note the ip.id changed becaue proxy created a new packet
                                         |<--     18                          618       INVITE acked by server
  59580                          618  <--|                                              INVITE tcp-ack from proxy to client
                                         |-->  47758        618      0        618       Proxy sending tcp-ack on its own to 200 OK received from server
     44        618      0        618  -->|                                              client sends tcp-ack to 200 OK






#--------------------------------------------------------------------#
|                                                                    |
|                          pcap_dump_sip.py                          |
|                                                                    |
#--------------------------------------------------------------------#

dependency:
    sip-parser      alxgb/sip-parser
    pip install sip-parser/src/sip_parser

Usage:
    pcap_dump_sip.py rx.pcap --sip "Call-ID=0022905c-59680003-b6a0cb24-b0fc6828@192.168.30.151"

Other fields that can be searched. See the message below and there parsed version 
    REFER sip:192.168.40.135 SIP/2.0^M
    Via: SIP/2.0/UDP 192.168.30.151:5060;branch=z9hG4bK4eb7d4e8^M
    From: <sip:0022905c5968@192.168.30.151>;tag=0022905c596800046fa3b5e4-7985c768^M
    To: <sip:192.168.40.135>^M
    Call-ID: 0022905c-59680003-b6a0cb24-b0fc6828@192.168.30.151^M
    Date: Wed, 30 Apr 2025 19:13:48 GMT^M
    CSeq: 1000 REFER^M
    User-Agent: Cisco-CP7962G/9.4.2^M
    Expires: 10^M
    Max-Forwards: 70^M
    Contact: <sip:0022905c5968@192.168.30.151:5060>^M
    Require: norefersub^M
    Referred-By: <sip:0022905c5968@192.168.30.151>^M
    Refer-To: cid:5610f564@192.168.30.151^M
    Content-Id: <5610f564@192.168.30.151>^M
    Allow: ACK,BYE,CANCEL,INVITE,NOTIFY,OPTIONS,REFER,REGISTER,UPDATE,SUBSCRIBE^M
    Content-Length: 1313^M
    Content-Type: application/x-cisco-alarm+xml^M
    Content-Disposition: session;handling=required^M


    {
        'via': [{'version': '2.0', 'protocol': 'UDP', 'host': '192.168.30.151', 'port': 5060, 'params': {'branch': 'z9hG4bK4eb7d4e8'}}], 
        'from': {'name': None, 'uri': 'sip:0022905c5968@192.168.30.151', 'params': {'tag': '0022905c596800046fa3b5e4-7985c768'}}, 
        'to': {'name': None, 'uri': 'sip:192.168.40.135', 'params': {}}, 
        'call-id': '0022905c-59680003-b6a0cb24-b0fc6828@192.168.30.151', 
        'date': 'Wed, 30 Apr 2025 19:13:48 GMT', 
        'cseq': {'seq': 1000, 'method': 'REFER'}, 
        'user-agent': 'Cisco-CP7962G/9.4.2', 
        'expires': '10', 
        'max-forwards': 70, 
        'contact': [{'name': None, 'uri': 'sip:0022905c5968@192.168.30.151:5060', 'params': {}}], 
        'require': 'norefersub', 
        'referred-by': '<sip:0022905c5968@192.168.30.151>', 
        'refer-to': {'name': None, 'uri': 'cid:5610f564@192.168.30.151', 'params': {}}, 
        'content-id': '<5610f564@192.168.30.151>', 
        'allow': 'ACK,BYE,CANCEL,INVITE,NOTIFY,OPTIONS,REFER,REGISTER,UPDATE,SUBSCRIBE', 
        'content-length': 1313, 
        'content-type': 'application/x-cisco-alarm+xml', 
        'content-disposition': 'session;handling=required'
    }



    SIP/2.0 202 Accepted^M
    Via: SIP/2.0/UDP 192.168.40.151:27859;branch=z9hG4bK4eb7d4e8^M
    From: <sip:0022905c5968@192.168.40.151:27859>;tag=0022905c596800046fa3b5e4-7985c768^M
    To: <sip:192.168.40.135>;tag=1198734326^M
    Date: Wed, 30 Apr 2025 19:13:48 GMT^M
    Call-ID: 0022905c-59680003-b6a0cb24-b0fc6828@192.168.30.151^M
    CSeq: 1000 REFER^M
    Contact: <sip:192.168.40.135:5060>^M
    Content-Length: 0^M
    ^M

    {
        'via'            : [{'version': '2.0', 'protocol': 'UDP', 'host': '192.168.40.151', 'port': 27859, 'params': {'branch': 'z9hG4bK4eb7d4e8'}}],
        'from'           : {'name': None, 'uri': 'sip:0022905c5968@192.168.40.151:27859', 'params': {'tag': '0022905c596800046fa3b5e4-7985c768'}}, 
        'to'             : {'name': None, 'uri': 'sip:192.168.40.135', 'params': {'tag': '1198734326'}}, 
        'date'           : 'Wed, 30 Apr 2025 19:13:48 GMT', 
        'call-id'        : '0022905c-59680003-b6a0cb24-b0fc6828@192.168.30.151', 
        'cseq'           : {'seq': 1000, 'method': 'REFER'}, 
        'contact'        : [{'name': None, 'uri': 'sip:192.168.40.135:5060', 'params': {}}], 
        'content-length' : 0
    }




#--------------------------------------------------------------------#
|                                                                    |
|                          pcap_dump_payload.py                      |
|                                                                    |
#--------------------------------------------------------------------#

Usage:
    pcap_dump_payload.py <pcap-file>

Dumps the payload of all packets that have payload
Replaces <NL> and <CR> in payload with \r and \n
     
