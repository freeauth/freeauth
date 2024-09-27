#!/bin/bash
set -e
stage_print() {
    echo "========================================"
    echo -e $1
    echo "========================================"
}


stage_print "WAN Setting: Latency 20ms and bandwidth 1Gbps"

if tc -s qdisc ls dev lo | grep -q "noqueue"; then
    echo ""
else
    tc qdisc del dev lo root
fi
#Set latency and bandwidth to 20ms and 1Gbps
tc qdisc add dev lo root netem rate 1Gbit delay 10ms

sleep 1

stage_print "Please check if latency is configured successfully"
ping -c 5 127.0.0.1 

sleep 1

stage_print "Please check if bandwidth is configured successfully"
iperf -s &
iperf -c 127.0.0.1

