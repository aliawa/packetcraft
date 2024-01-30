Need for a protocol traffic generator
----------------------------------------------------------------------
Why a black box testing tool is needed
We can look at if a predict is created or what is the value of the counter
etc. but it will still not tell us if the damn call worked or not.

Instead of blindlindly sending tcp ack, as is the case with tcp-replay
we want to send an ack for the data received for realistic traffic flow.

Advantages
if the interestin thing happens when processing the 15th packet in the pcap. Then with pcap
replay you have to replay all 15 packets while with data_replay we an extract the 15th packet
and replay just that. 

Full control of payload
Line endings are not added automatically, This is to give control becasue
somtimes when the body is xml the lines end with '\n' only and not '\r\n'


Features
----------------------------------------------------------------------
- Update the dst-address/port of the flow that received a response.
- Update the dst-address/port of a different flow. For example the control
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
     sport: 'random'


Receive Actions
----------------------------------------------------------------------
- search and exec are lists
- match is not a list
- Add a receive action even if no data needs to be extracted to update the TCP ACK counter

When receive fails, exception is thrown to indicate that the test has failed


Dictionaries avaialable for commands
----------------------------------------------------------------------
    dicts:
        - c2s
        - s2c
        - ...
        - pkt
            - src
            - dst
            - sport
            - dport
            - proto
            - flags
        - payload
            - all searched fields
            - len : autopopulated
        - param
            - the param dictionary imported from command line

Example usage of dictionaries:
    statement                       Meaning
    ----------------------------    --------------------------------------
    c2s.port = '132'                flows['c2s'].port = 132
    c2s.dst = pkt.src               flows['c2s'].dst = fields['pkt.src']
    c2s.dst={destination:IP.src}    flows['c2s'].dst = fields['destination'] if 'destination' in fields else fields['IP.src']



Commands
----------------------------------------------------------------------
- recv:
Add a recv action even if no data needs to be extracted to update the ACK
counter


- create:
packet is created but not sent. It is created at a point in scenario so it
gets correct seq and ack numbers but sent later simulating delay


- match: 
regex match at begining of payload, no fields can be extracted
only one match expression is allowed


- search:
all found fields are stored in fields dictionary
if search fails no error reported, and we don't ignore the packet


- exec:
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


- verify:
verify values in fields dict against the parameters dict
payload.via_src == invite.via_src            # compare payload field with parameter field 
via_src == invite.via_src                    # compare implicit payload field with parameter field 
via_src == contact_src                       # compare two fields in payload
payload.len == 1460                          # compare payload length as integer
pkt.seq == 2315                              # compare tcp seq as integer


- send:
name:                                       # retrieve saved packet with this name and send it
save: name                                  # save the packet for future use with name
if send fails exception is thrown to indicate the test has failed

- loop
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



Implementation
----------------------------------------------------------------------
Sending packet
  need outgoing intf
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
