#!/bin/bash

current_dir=$(pwd)

echo "目标目录: $current_dir"

qvr_dir=$current_dir/machines/qemu-virt-riscv64

rm -f $current_dir/compile_commands.json

cp $qvr_dir/compile_commands.json $current_dir/compile_commands.json

sed -i '/-fstrict-volatile-bitfields/d' $current_dir/compile_commands.json
sed -i '/fvar-tracking/d' $current_dir/compile_commands.json

sed -i "s|-Ibuild|-I$qvr_dir/build|g" $current_dir/compile_commands.json
sed -i "s|-Ipackages|-I$qvr_dir/packages|g" $current_dir/compile_commands.json
sed -i "s|-Idriver|-I$qvr_dir/driver|g" $current_dir/compile_commands.json
sed -i "s|-Iapplications|-I$qvr_dir/applications|g" $current_dir/compile_commands.json

sed -i "s|\"build|\"$qvr_dir/build|g" $current_dir/compile_commands.json
sed -i "s|\"driver|\"$qvr_dir/driver|g" $current_dir/compile_commands.json
sed -i "s|\"packages|\"$qvr_dir/packages|g" $current_dir/compile_commands.json
sed -i "s|\"applications|\"$qvr_dir/applications|g" $current_dir/compile_commands.json

sed -i "s|/code/|$current_dir/|g" $current_dir/compile_commands.json

sudo rm -f $qvr_dir/compile_commands.json

