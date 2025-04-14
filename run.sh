#! /usr/bin/env bash

if [ -n "${BASH_SOURCE[0]}" ]; then
    script_path="${BASH_SOURCE[0]}"
else
    script_path="$0"
fi

script_dir=$(dirname "$script_path")

image_name=local/rtt-rv64
container_name=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 16)

git submodule update --init --recursive

if [[ ! -f "$script_dir/toolchains/qemu-longarch/loongarch64-musl-gcc-nightly-2025-3-27.tar.gz" ]]; then
    wget https://github.com/LoongsonLab/oscomp-toolchains-for-oskernel/releases/download/loongarch64-cross-toolchains-qemu/loongarch64-musl-gcc-nightly-2025-3-27.tar.gz -P "$script_dir/toolchains/qemu-longarch"
fi

if [[ ! -f "$script_dir/toolchains/qemu-virt-riscv64/riscv64gc-linux-musleabi_for_x86_64-pc-linux-gnu_latest.tar.bz2" ]]; then
    wget https://download.rt-thread.org/download/rt-smart/toolchains/riscv64gc-linux-musleabi_for_x86_64-pc-linux-gnu_latest.tar.bz2 -P "$script_dir/toolchains/qemu-virt-riscv64"
fi

if ! docker image inspect "$image_name" &>/dev/null; then
    docker build --rm -t "$image_name" \
        -f "$script_dir/Containerfile" \
        "$script_dir"
fi

docker run -dit --rm -v .:/code -w /code --name "$container_name" \
    --privileged "$image_name" bash
docker exec "$container_name" \
    make -C testsuits-for-oskernel build-all -j8
docker attach "$container_name"
