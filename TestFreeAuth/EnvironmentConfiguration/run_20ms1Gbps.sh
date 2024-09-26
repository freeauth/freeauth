#!/bin/bash
set -e
stage_print() {
    echo "========================================"
    echo -e $1
    echo "========================================"
}


stage_print "Set latency and bandwidth to 20ms and 1Gbps"

if sudo tc -s qdisc ls dev lo | grep -q "noqueue"; then
    echo ""
else
    sudo tc qdisc del dev lo root
fi
#Set latency and bandwidth to 20ms and 1Gbps
tc qdisc add dev lo root handle 1:0 htb default 1
# Parameters obtained after testing on the server
tc class add dev lo parent 1:0 classid 1:1 htb rate 180Mbps burst 32k
tc qdisc add dev lo parent 1:1 handle 2:0 netem delay 10ms 1ms

sleep 1

stage_print "Please check if latency is configured successfully"
ping -c 5 127.0.0.1 

sleep 1

stage_print "Please check if bandwidth is configured successfully"
iperf -s &
iperf -c 127.0.0.1

