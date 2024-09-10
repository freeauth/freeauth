#!/bin/bash

set -e
project_root="$(dirname $0)"
project_root="$(realpath $project_root)"
project_build_out="$project_root/build"
rust_project_root="$project_root/TestFreeAuth/StatementGeneration"
circuits_path="$project_root/2pc/key-derivation"
export CARGO_TARGET_DIR="$project_build_out"
if [ -f "$project_root/2pc" ]; then
    rm "$project_root/2pc"
    ln -s "$project_root/DiStefano/2pc" "$project_root/2pc"
fi

stage_print() {
    echo "========================================"
    echo -e $1
    date
    echo "========================================"
}

stage_print "Run cmake configuration"
test -d "$project_build_out" && rm -rf "$project_build_out"
mkdir -p "$project_build_out"
cmake -S "$project_root" -B "$project_build_out"

stage_print "Now compile the C/C++ project"
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
