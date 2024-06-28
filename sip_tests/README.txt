NAT policies used in testing
----------------------------------------------------------------------
"dip_nat; index: 1" {
        nat-type ipv4;
        from any;
        source 192.168.1.0/24;
        source-region none;
        to vw-untrust;
        to-interface  ;
        destination any;
        destination-region none;
        service 0:any/any/any;
        translate-to "src: 10.2.2.10-10.2.2.99 (dynamic-ip) (pool idx: 1)";
        terminal no;
}

"dipp_nat; index: 2" {
        nat-type ipv4;
        from any;
        source 192.168.2.0/24;
        source-region none;
        to vw-untrust;
        to-interface  ;
        destination any;
        destination-region none;
        service 0:any/any/any;
        translate-to "src: 10.3.3.50-10.3.3.99 (dynamic-ip-and-port) (pool idx: 2)";
        terminal no;
}

"static-nat; index: 3" {
        nat-type ipv4;
        from any;
        source 192.168.3.0;
        source-region none;
        to vw-untrust;
        to-interface  ;
        destination any;
        destination-region none;
        service 0:any/any/any;
        translate-to "src: 10.3.3.200 (static-ip) (pool idx: 3)";
        terminal no;
}

"dest-nat; index: 4" {
        nat-type ipv4;
        from any;
        source 192.168.4.0/24;
        source-region none;
        to vw-untrust;
        to-interface  ;
        destination 100.10.10.10;
        destination-region none;
        service 0:any/any/any;
        translate-to "dst: 10.1.1.2:5060";
        terminal no;


RTP SCENARIOS
----------------------------------------------------------------------
1. Just test creation of RTP/ RTCP predicts, no other predicts are created.
sip_rtp_1.txt

2. Bidirectional rtp predicts, but no predict conversion
sip_rtp_2.txt

3. RTP predict conversion, c2s rtp predict matched
sip_rtp_3.txt

3. RTP predict conversion, s2c rtp predict(The one created by 200 OK) matched
sip_rtp_4.txt

3. same as sip_rtp_3.yaml, but rtp session is kept alive until predict expires, then re-invite and 200 ok
sip_rtp_5.txt

3. same as sip_rtp_4.yaml, but rtp session is kept alive until predict expires, then re-invite and 200 ok
sip_rtp_6.txt



3PARTY SCENARIOS
----------------------------------------------------------------------
sip_call_3party_sip.yaml
    3rd party addresses only sip predict creation and conversion
sip_call_3party_sip_client.yaml
    3rd party addresses sip and rtp predict creation and conversion, first rtp packet from client
sip_call_3party_sip_server.yaml
    3rd party addresses sip and rtp predict creation and conversion, first rtp packet from server
sip_call_3party_rtp_merge_error.yaml
    3rd party addresses, first rtp packet from server, but no sdp from client side
    what happens when a packet hits a predict created by s2c flow but src addr of packet is not mapped
    This case fails in ALG 1.5
sip_call_3party_rtp_merge_error_2.yaml
    same as sip_call_3party_rtp_merge_error.yaml, but the 200 OK from server hits a predict instead 
    of the flow created by INVITE, This case does not work in ALG 1.5, but it also fails in ALG 1.0


TODO
----------------------------------------------------------------------
1) Add a parse_sip:
    This will parse the received message as sip payload, so a sip dictionary 
    becomes available.
    sip.via     entire sip via header
    sip.via.ip
    sip.contact.port

    Example:
    exec:
        - parse_sip()
        - parse_ftp()

        - parse('sip') 
        - parse('ftp')
    parser: sip
    parser: ftp


