#! /usr/bin/env bash

# 参数校验函数
usage() {
    echo "用法: $0 <http_port> [https_port]"
    echo "示例:"
    echo "  $0 7890            # http_port=https_port=7890"
    echo "  $0 8080 8081       # http_port=8080, https_port=8081"
    exit 1
}

# 解析命令行参数
if [[ $# -lt 1 || $# -gt 2 ]]; then
    usage
fi

http_port="$1"
https_port="${2:-$http_port}" # 如果第二个参数不存在，复用第一个参数

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
        --network host \
        --build-arg HTTP_PORT="$http_port" \
        --build-arg http_port="$http_port" \
        --build-arg https_port="$https_port" \
        --build-arg HTTPS_PORT="$https_port" -f "$script_dir/Containerfile" \
        "$script_dir"
fi

docker run -dit --rm -v .:/code -w /code --name "$container_name" \
    --network host --privileged "$image_name" bash
docker exec "$container_name" \
    NPROC=8 make -C testsuits-for-oskernel sdcard
docker ps -a -f "name=$container_name"
cat <<EOF
Use: docker attach $container_name
     cd machines/qemu-virt-riscv64
     scons --menuconfig
     pkgs --update
     scons -j8
EOF
