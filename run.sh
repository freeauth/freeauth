#!/bin/bash
set -e
project_root="$(dirname $0)"
project_root="$(realpath $project_root)"
project_build_out="$project_root/build"
rust_project_root="$project_root/FreeAuth/StatementGeneration"
circuits_path="$project_root/2pc/key-derivation"
export CARGO_TARGET_DIR="$project_build_out"
stage_print() {
    echo "========================================"
    echo -e $1
    date
    echo "========================================"
}
stage_print "Running test programs"
stage_print "Test1: Email Ownership Authentication"
cd "$project_build_out"
killall TestSMTPServer || true
killall TestSMTPVerifier || true
killall TestSingleCommitVerifier || true
"$project_build_out/TestSMTPServer" &
"$project_build_out/TestSMTPVerifier" &
sleep 0.4
/usr/bin/time "$project_build_out/TestSMTPProver"
sleep 0.5
stage_print "Test2: Commitment Generation"
"$project_build_out/TestSingleCommitVerifier" -p 18400 & 
sleep 0.3
/usr/bin/time "$project_build_out/TestSingleCommitProver" -v 18400
sleep 0.5
stage_print "Test3: Statement Generation"
/usr/bin/time "$project_build_out/release/email"

stage_print "Finished successfully"
