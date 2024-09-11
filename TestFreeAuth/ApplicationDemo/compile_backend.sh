#!/usr/bin/bash
set -e
project_root="$(dirname $0)/../../"
[ ! -d $project_root/build ] && mkdir $project_root/build
[ ! -d $project_root/TestFreeAuth/ApplicationDemo/libs ] && mkdir $project_root/TestFreeAuth/ApplicationDemo/libs
[ ! -f $project_root/build/Makefile ] && cmake -S $project_root -B $project_root/build
make -j6 -C $project_root/build
cp $project_root/build/libNodeWrapperSMTP.* $project_root/TestFreeAuth/ApplicationDemo/libs/
