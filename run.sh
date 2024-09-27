#!/bin/bash
set -e
project_root="$(dirname $0)"
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
"$project_build_out/TestSingleCommitProver" -v 18400
sleep 0.5

#RUN Test3: Statement Generation
stage_print "Test3: Statement Generation"
"$project_build_out/release/email"

stage_print "Finished successfully"

killall TestSMTPServer || true
killall TestSMTPVerifier || true
killall TestSingleCommitVerifier || true

if tc -s qdisc ls dev lo | grep -q "noqueue"; then
    echo ""
else
    tc qdisc del dev lo root
fi

stage_print "Cleaned all Processes"