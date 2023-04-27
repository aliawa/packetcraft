# 1. frame.number
# 2. ip.src
# 3. ip.dst
# 4. tcp.seq
# 5. tcp.nxtseq
# 6. tcp.ack
# 7. ip.id

# tshark -r tx2\(1\).pcap -e frame.number -e eth.src -e eth.dst -e tcp.seq \
#     -e tcp.nxtseq  -e tcp.ack -e ip.id -e sip.Method -e sip.Status-Code  \
#      -Tfields -E separator=, '(tcp && ip.addr==10.3.36.135)' > b.txt
# cat b.txt | awk -f tcp_analyze_v2.awk

BEGIN {
    FS=","
    data=""
    border="|"
    mac2="00:1b:17:9c:38:10"
    mac1="00:1b:17:9c:38:13"
    print ""
}

{
    data=""
    if ($5!="") {
        data=$4"-"$5-1"["$5-$4"]"
    }

    if ($8!="") {
        sip=substr($8,0,6) 
    } else if ($9!="") {
        sip=$9
    } else {
        sip=""
    }
}

$2 == mac1 {
    line = sprintf ("|    A:%5s%18s %-6s <--|%41s", $6,data,sip,border)
}
$3 == mac1 {
    line = sprintf ("|--> A:%5s%18s %-6s    |%41s", $6,data,sip,border)
}



$2 == mac2 {
    line = sprintf ("%-41s|--> A:%5s%18s %-6s    |", border,$6,data,sip)
}
$3 == mac2 {
    line = sprintf ("%-41s|    A:%5s%18s %-6s <--|", border,$6,data,sip)
}

{
    printf "%6s|%5d %s\n", $1,$7,line
}


#
#|--> A: 18530   10779-11432 <--|                              |
#|                              |--> A: 18422   10634-11291 <--|
