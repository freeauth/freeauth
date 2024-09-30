#!/usr/bin/bash
set -e
project_root="$(dirname $0)"
project_root="$(realpath $project_root)"
project_root="$(dirname $project_root)"
echo "$project_root"
[ ! -d $project_root/build ] && mkdir $project_root/build
[ ! -d $project_root/ApplicationDemo/libs ] && mkdir $project_root/ApplicationDemo/libs
[ ! -f $project_root/build/Makefile ] && cmake -S $project_root -B $project_root/build
make -j6 -C $project_root/build
cp $project_root/build/libNodeWrapperSMTP.* $project_root/ApplicationDemo/libs/
