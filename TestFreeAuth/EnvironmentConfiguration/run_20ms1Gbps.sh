#!/bin/bash
set -e
project_root="../../$(dirname $0)"
project_root="$(realpath $project_root)"
project_build_out="$project_root/build"
rust_project_root="$project_root/TestFreeAuth/StatementGeneration"
circuits_path="$project_root/2pc/key-derivation"
export CARGO_TARGET_DIR="$project_build_out"
stage_print() {
    echo "========================================"
    echo -e $1
    date
    echo "========================================"
}

tc qdisc delete dev lo root

stage_print "Set latency and bandwidth to 20ms and 1Gbps"
#Set latency and bandwidth to 20ms and 1Gbps
tc qdisc add dev lo root handle 1:0 htb default 1
tc class add dev lo parent 1:0 classid 1:1 htb rate 1Gbps burst 15k
tc qdisc add dev lo parent 1:1 handle 2:0 netem delay 10ms 1ms

sleep 1

#RUN Test1: Email Ownership Authentication
stage_print "Running test programs"
stage_print "Test1: Email Ownership Authentication"
cd "$project_build_out"
killall TestSMTPServer || true
killall TestSMTPVerifier || true
killall TestSingleCommitVerifier || true

SMTPServerLog=$(mktemp)
SMTPVerifierLog=$(mktemp)
SMTPProverLog=$(mktemp)

"$project_build_out/TestSMTPServer" > "$SMTPServerLog" 2>&1  &

"$project_build_out/TestSMTPVerifier" > "$SMTPVerifierLog" 2>&1 &

sleep 0.4
"$project_build_out/TestSMTPProver" > "$SMTPProverLog" 2>&1 &
prover_pid=$!

wait $prover_pid

echo "==========Output from Server============="
cat "$SMTPServerLog"
echo

echo "==========Output from Verifier============="
cat "$SMTPVerifierLog"
echo

echo "==========Output from Prover============="
cat "$SMTPProverLog"
echo

sleep 0.5
#RUN Test2: Commitment Generation

stage_print "Test2: Commitment Generation"
"$project_build_out/TestSingleCommitVerifier" -p 18400 & 
sleep 0.3
/usr/bin/time "$project_build_out/TestSingleCommitProver" -v 18400
sleep 0.5

#RUN Test3: Statement Generation
stage_print "Test3: Statement Generation"
/usr/bin/time "$project_build_out/release/email"

stage_print "Finished successfully"


killall TestSMTPServer || true
killall TestSMTPVerifier || true
killall TestSingleCommitVerifier || true

tc qdisc delete dev lo root

stage_print "Cleaned all Processes"
