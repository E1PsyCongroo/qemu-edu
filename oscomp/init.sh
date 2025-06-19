apt-get -y update
apt-get -y install scons python3-kconfiglib python3-tqdm python3-requests python3-yaml

wget --no-check-certificate https://download.rt-thread.org/download/rt-smart/toolchains/riscv64gc-linux-musleabi_for_x86_64-pc-linux-gnu_latest.tar.bz2
tar jxvf /root/toolchains/qemu-virt-riscv64/riscv64gc-linux-musleabi_for_x86_64-pc-linux-gnu_latest.tar.bz2 -C /opt

bash ./toolchains/install_ubuntu.sh --gitee
source ~/.env/env.sh

export PATH=/opt/riscv64gc-linux-musleabi/bin:$PATH

cd ./machines/qemu-virt-riscv64
pkgs --update
scons -j$(nproc)
cd ../..
cp ./machines/qemu-virt-riscv64/rtthread.bin ./kernel-rv

cd ./oscomp/rv
make all
cd ../..
cp ./oscomp/rv/build/disk.img ./disk.img
