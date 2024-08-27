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

# Install dependencies
sudo apt update
sudo apt -y install cmake make gcc g++ rustc cargo golang git libssl-dev

stage_print "Run cmake configuration"
test -d "$project_build_out" && rm -rf "$project_build_out"
mkdir -p "$project_build_out"
cmake -S "$project_root" -B "$project_build_out"

stage_print "Now comile the C/C++ project"
make -C "$project_build_out" -j"$(nproc)"

stage_print "Derive the 2PC circuits"
test -d "$circuits_path" && rm -rf "$circuits_path"
mkdir -p $circuits_path
cd "$circuits_path"
"$project_build_out/DiStefano/DeriveCircuits"

stage_print "Build the Rust project"
cd "$rust_project_root"
cargo build --release
stage_print "compiled successfully"
