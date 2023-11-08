import base64
from scapy.packet import *
from scapy.fields import *
from scapy.ansmachine import *
from scapy.layers.inet import *
from scapy.layers.dns import *
#import dissector


# SIP parser for Scapy

class SIPStartField(StrField):
    """
    field class for handling sip start field
    @attention: it inherets StrField from Scapy library
    """
    holds_packets = 1
    #name = "SIPStartField"

    def getfield(self, pkt, s):
        """
        this method will get the packet, takes what does need to be
        taken and let the remaining go, so it returns two values.
        first value which belongs to this field and the second is
        the remaining which does need to be dissected with
        other "field classes".
        @param pkt: holds the whole packet
        @param s: holds only the remaining data which is not dissected yet.
        """
        cstream = -1
        if pkt.underlayer:
            if pkt.underlayer.name == "TCP":
                cstream = dissector.check_stream(\
                pkt.underlayer.underlayer.fields["src"],\
                 pkt.underlayer.underlayer.fields["dst"],\
                  pkt.underlayer.fields["sport"],\
                   pkt.underlayer.fields["dport"],\
                    pkt.underlayer.fields["seq"], s)
        if not cstream == -1:
            s = cstream
        remain = b""
        value = b""
        ls = s.splitlines(True)
        f = ls[0].split()
        if b"SIP" in f[0]:
            ls = s.splitlines(True)
            f = ls[0].split()
            length = len(f)
            value = ""
            if length == 3:
                value = "SIP-Version:" + f[0] + ", Status-Code:" +\
                f[1] + ", Reason-Phrase:" + f[2]
                ls.remove(ls[0])
                for element in ls:
                    remain = remain + element
            else:
                value = ls[0]
                ls.remove(ls[0])
                for element in ls:
                    remain = remain + element
            return remain, value
        elif b"SIP" in f[2]:
            ls = s.splitlines(True)
            f = ls[0].split()
            length = len(f)
            value = []
            if length == 3:
                value = b"Method:" + f[0] + b", Request-URI:" +\
                f[1] + b", SIP-Version:" + f[2]
                ls.remove(ls[0])
                for element in ls:
                    remain = remain + element
            else:
                value = ls[0]
                ls.remove(ls[0])
                for element in ls:
                    remain = remain + element
            return remain, value
        else:
            return s, ""

def int_to_bytes(x: int) -> bytes:
    return x.to_bytes((x.bit_length() + 7) // 8, 'big')

class SIPMsgField(StrField):
    """
    field class for handling the body of sip packets
    @attention: it inherets StrField from Scapy library
    """
    holds_packets = 1
    #name = "SIPMsgField"
    myresult = b""

    def __init__(self, name, default):
        """
        class constructor, for initializing instance variables
        @param name: name of the field
        @param default: Scapy has many formats to represent the data
        internal, human and machine. anyways you may sit this param to None.
        """
        self.name = name
        self.fmt = "!B"
        self.remain =0 
        Field.__init__(self, name, default, "!B")

def getfield(self, pkt, s):
        """
        this method will get the packet, takes what does need to be
        taken and let the remaining go, so it returns two values.
        first value which belongs to this field and the second is
        the remaining which does need to be dissected with
        other "field classes".
        @param pkt: holds the whole packet
        @param s: holds only the remaining data which is not dissected yet.
        """
        if s.startswith(b"\r\n"):
            s = s.lstrip(b"\r\n")
            if s == b"":
                return b"", b""
        # self.myresult = b""
        # for c in s:
        #     self.myresult = self.myresult + base64.standard_b64encode(c)
        # return b"", self.myresult
        res = b""
        barr = bytearray(s)
        for c in barr:
            res = res + base64.standard_b64encode(int_to_byte(c))
        return b"", res

class SIPField(StrField):
    """
    field class for handling the body of sip fields
    @attention: it inherets StrField from Scapy library
    """
    holds_packets = 1
    #name = "SIPField"

    def getfield(self, pkt, s):
        """
        this method will get the packet, takes what does need to be
        taken and let the remaining go, so it returns two values.
        first value which belongs to this field and the second is
        the remaining which does need to be dissected with
        other "field classes".
        @param pkt: holds the whole packet
        @param s: holds only the remaining data which is not dissected yet.
        """
        if self.name == "unknown-header(s): ":
            remain = b""
            value = []
            ls = s.splitlines(True)
            i = -1
            for element in ls:
                i = i + 1
                if element == b"\r\n":
                    return s, []
                elif element != b"\r\n" and (b": " in element[:10])\
                 and (element[-2:] == b"\r\n"):
                    value.append(element)
                    ls.remove(ls[i])
                    remain = ""
                    unknown = True
                    for element in ls:
                        if element != b"\r\n" and (": " in element[:15])\
                         and (element[-2:] == b"\r\n") and unknown:
                            value.append(element)
                        else:
                            unknow = False
                            remain = remain + element
                    return remain, value
            return s, []

        remain = b""
        value = b""
        ls = s.splitlines(True)
        i = -1
        for element in ls:
            i = i + 1
            if element.upper().startswith(self.name.upper().replace('_','-').encode('utf-8')):
                value = element.decode('utf-8')
                #value = value.strip(self.name)
                ls.remove(ls[i])
                remain = b""
                for element in ls:
                    remain = remain + element
                return remain, value[len(self.name) + 1:].strip()
        return s, ""

    def __init__(self, name, default, fmt, remain=0):
        """
        class constructor for initializing the instance variables
        @param name: name of the field
        @param default: Scapy has many formats to represent the data
        internal, human and machine. anyways you may sit this param to None.
        @param fmt: specifying the format, this has been set to "H"
        @param remain: this parameter specifies the size of the remaining
        data so make it 0 to handle all of the data.
        """
        self.name = name
        StrField.__init__(self, name, default, fmt, remain)


class SIP(Packet):
    """
    class for handling the body of sip packets
    @attention: it inherets Packet from Scapy library
    """
    name = "sip"
    fields_desc = [SIPStartField("start-line", "", "H"),
                   SIPField("accept", "", "H"),
                   SIPField("accept_contact", "", "H"),
                   SIPField("accept_encoding", "", "H"),
                   SIPField("accept_language", "", "H"),
                   SIPField("accept_resource_priority", "", "H"),
                   SIPField("alert_info", "", "H"),
                   SIPField("allow", "", "H"),
                   SIPField("allow_events", "", "H"),
                   SIPField("authentication_info", "", "H"),
                   SIPField("authorization", "", "H"),
                   SIPField("call_id", "", "H"),
                   SIPField("call_info", "", "H"),
                   SIPField("contact", "", "H"),
                   SIPField("content_disposition", "", "H"),
                   SIPField("content_encoding", "", "H"),
                   SIPField("content_language", "", "H"),
                   SIPField("content_length", "", "H"),
                   SIPField("content_type", "", "H"),
                   SIPField("cseq", "", "H"),
                   SIPField("date", "", "H"),
                   SIPField("error_info", "", "H"),
                   SIPField("event", "", "H"),
                   SIPField("expires", "", "H"),
                   SIPField("from", "", "H"),
                   SIPField("in_reply_to", "", "H"),
                   SIPField("join", "", "H"),
                   SIPField("max_forwards", "", "H"),
                   SIPField("mime_version", "", "H"),
                   SIPField("min_expires", "", "H"),
                   SIPField("min_se", "", "H"),
                   SIPField("organization", "", "H"),
                   SIPField("p_access_network_info", "", "H"),
                   SIPField("p_asserted_identity", "", "H"),
                   SIPField("p_associated_uri", "", "H"),
                   SIPField("p_called_party_id", "", "H"),
                   SIPField("p_charging_function_addresses", "", "H"),
                   SIPField("p_charging_vector", "", "H"),
                   SIPField("p_dcs_trace_party_id", "", "H"),
                   SIPField("p_dcs_osps", "", "H"),
                   SIPField("p_dcs_billing_info", "", "H"),
                   SIPField("p_dcs_laes", "", "H"),
                   SIPField("p_dcs_redirect", "", "H"),
                   SIPField("p_media_authorization", "", "H"),
                   SIPField("p_preferred_identity", "", "H"),
                   SIPField("p_visited_network_id", "", "H"),
                   SIPField("path", "", "H"),
                   SIPField("priority", "", "H"),
                   SIPField("privacy", "", "H"),
                   SIPField("proxy_authenticate", "", "H"),
                   SIPField("proxy_authorization", "", "H"),
                   SIPField("proxy_require", "", "H"),
                   SIPField("rack", "", "H"),
                   SIPField("reason", "", "H"),
                   SIPField("record_route", "", "H"),
                   SIPField("referred_by", "", "H"),
                   SIPField("reject_contact", "", "H"),
                   SIPField("replaces", "", "H"),
                   SIPField("reply_to", "", "H"),
                   SIPField("request_disposition", "", "H"),
                   SIPField("require", "", "H"),
                   SIPField("resource_priority", "", "H"),
                   SIPField("retry_after", "", "H"),
                   SIPField("route", "", "H"),
                   SIPField("rseq", "", "H"),
                   SIPField("security_client", "", "H"),
                   SIPField("security_server", "", "H"),
                   SIPField("security_verify", "", "H"),
                   SIPField("server", "", "H"),
                   SIPField("service_route", "", "H"),
                   SIPField("session_expires", "", "H"),
                   SIPField("sip_etag", "", "H"),
                   SIPField("sip_if_match", "", "H"),
                   SIPField("subject", "", "H"),
                   SIPField("subscription_state", "", "H"),
                   SIPField("supported", "", "H"),
                   SIPField("timestamp", "", "H"),
                   SIPField("to", "", "H"),
                   SIPField("unsupported", "", "H"),
                   SIPField("user_agent", "", "H"),
                   SIPField("via", "", "H"),
                   SIPField("warning", "", "H"),
                   SIPField("www_authenticate", "", "H"),
                   SIPField("refer_to", "", "H"),
                   SIPField("history_info", "", "H"),
                   SIPField("unknown_header(s)", "", "H"),
                   SIPMsgField("message_body", "")]

bind_layers(TCP, SIP, sport=5060)
bind_layers(TCP, SIP, dport=5060)
bind_layers(UDP, SIP, sport=5060)
bind_layers(UDP, SIP, dport=5060)



mystr="""INVITE sip:7000@1.1.1.1:5060;user=phone;transport=tcp SIP/2.0
Via: SIP/2.0/TCP 2.2.2.2:5060;branch=z9hG4bKbe15632f914B3568
From: "7012" <sip:7012@1.1.1.1:5060>;tag=BA76D475-4FE052EC
To: <sip:7000@1.1.1.1:5060;user=phone>
Call-ID: 5a2fb8b1-3c6d8673-82af160a@192.168.1.100
CSeq: 1 INVITE
Contact: <sip:7012@2.2.2.2:5060;transport=tcp>
Max-forwards: 70
Content-Type: application/sdp
Content-Length:   250

v=0
o=- 978385019 978385019 IN IP4 2.2.2.2
s=Polycom IP Phone
c=IN IP4 2.2.2.2
t=0 0
a=sendrecv
m=audio 16436 RTP/AVP 0 8 18 101"""

b = IP()/TCP()/SIP(str.encode(mystr))
print(f">{b[SIP].via}<")
print(f">{b[SIP].contact}<")
print(f">{b[SIP].content_length}<")
print(f">{b[SIP].message_body}<")

b[SIP].content_length = 56
print(f">{b[SIP].content_length}<")

