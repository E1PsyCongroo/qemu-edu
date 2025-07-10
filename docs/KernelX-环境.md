# KernelX-环境

```bash

# 对于 riscv 环境：

echo $RTT_EXEC_PATH
/opt/riscv64gc-linux-musleabi_for_x86_64-pc-linux-gnu/bin

echo $RTT_CC_PREFIX
riscv64-unknown-linux-musl-

echo $PATH
/root/.local/bin:/root/.env/tools/scripts:/opt/riscv64gc-linux-musleabi_for_x86_64-pc-linux-gnu/bin:/opt/qemu-bin-9.2.1/bin:/opt/riscv64-linux-musl-cross/bin:/opt/loongarch64-linux-musl-cross/bin:/opt/gcc-13.2.0-loongarch64-linux-gnu/bin/:/opt/toolchain-loongarch64-linux-gnu-gcc8-host-x86_64-2022-07-18/bin/:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/opt/kendryte-toolchain/bin:/root/.cargo/bin:/opt/riscv64--musl--bleeding-edge-2020.08-1/bin

# 编译我们的系统
root@HewoArch:/# riscv64-unknown-linux-musl-gcc -v      
Using built-in specs.
COLLECT_GCC=riscv64-unknown-linux-musl-gcc
COLLECT_LTO_WRAPPER=/opt/riscv64gc-linux-musleabi_for_x86_64-pc-linux-gnu/bin/../libexec/gcc/riscv64-unknown-linux-musl/10.1.0/lto-wrapper
Target: riscv64-unknown-linux-musl
Configured with: /builds/alliance/risc-v-toolchain/riscv-gcc/configure --target=riscv64-unknown-linux-musl --prefix=/builds/alliance/risc-v-toolchain/install-native/ --with-sysroot=/builds/alliance/risc-v-toolchain/install-native//riscv64-unknown-linux-musl --with-system-zlib --enable-shared --enable-tls --enable-languages=c,c++ --disable-libmudflap --disable-libssp --disable-libquadmath --disable-libsanitizer --disable-nls --disable-bootstrap --src=/builds/alliance/risc-v-toolchain/riscv-gcc --disable-multilib --with-abi=lp64 --with-arch=rv64imafdc --with-tune=rocket 'CFLAGS_FOR_TARGET=-O2   -mcmodel=medany -march=rv64imafdc -mabi=lp64' 'CXXFLAGS_FOR_TARGET=-O2   -mcmodel=medany -march=rv64imafdc -mabi=lp64'
Thread model: posix
Supported LTO compression algorithms: zlib
gcc version 10.1.0 (GCC) 
build date: Oct 20 2023 16:21:07
build sha: 8a397096c1ef8f0e71f75edb27d7fc6996785206
build job: 547555
build pipeline: 203957

# 编译我们的测试环境 /oscomp
root@HewoArch:/# riscv64-linux-musl-gcc -v
Using built-in specs.
COLLECT_GCC=riscv64-linux-musl-gcc
COLLECT_LTO_WRAPPER=/opt/riscv64-linux-musl-cross/bin/../libexec/gcc/riscv64-linux-musl/11.2.1/lto-wrapper
Target: riscv64-linux-musl
Configured with: ../src_gcc/configure --enable-languages=c,c++,fortran CC='gcc -static --static' CXX='g++ -static --static' FC='gfortran -static --static' CFLAGS='-g0 -O2 -fno-align-functions -fno-align-jumps -fno-align-loops -fno-align-labels -Wno-error' CXXFLAGS='-g0 -O2 -fno-align-functions -fno-align-jumps -fno-align-loops -fno-align-labels -Wno-error' FFLAGS='-g0 -O2 -fno-align-functions -fno-align-jumps -fno-align-loops -fno-align-labels -Wno-error' LDFLAGS='-s -static --static' --enable-default-pie --enable-static-pie --disable-cet --disable-bootstrap --disable-assembly --disable-werror --target=riscv64-linux-musl --prefix= --libdir=/lib --disable-multilib --with-sysroot=/riscv64-linux-musl --enable-tls --disable-libmudflap --disable-libsanitizer --disable-gnu-indirect-function --disable-libmpx --enable-initfini-array --enable-libstdcxx-time=rt --enable-deterministic-archives --enable-libstdcxx-time --enable-libquadmath --enable-libquadmath-support --disable-decimal-float --with-build-sysroot=/tmp/m1132/build/local/riscv64-linux-musl/obj_sysroot AR_FOR_TARGET=/tmp/m1132/build/local/riscv64-linux-musl/obj_binutils/binutils/ar AS_FOR_TARGET=/tmp/m1132/build/local/riscv64-linux-musl/obj_binutils/gas/as-new LD_FOR_TARGET=/tmp/m1132/build/local/riscv64-linux-musl/obj_binutils/ld/ld-new NM_FOR_TARGET=/tmp/m1132/build/local/riscv64-linux-musl/obj_binutils/binutils/nm-new OBJCOPY_FOR_TARGET=/tmp/m1132/build/local/riscv64-linux-musl/obj_binutils/binutils/objcopy OBJDUMP_FOR_TARGET=/tmp/m1132/build/local/riscv64-linux-musl/obj_binutils/binutils/objdump RANLIB_FOR_TARGET=/tmp/m1132/build/local/riscv64-linux-musl/obj_binutils/binutils/ranlib READELF_FOR_TARGET=/tmp/m1132/build/local/riscv64-linux-musl/obj_binutils/binutils/readelf STRIP_FOR_TARGET=/tmp/m1132/build/local/riscv64-linux-musl/obj_binutils/binutils/strip-new --build=x86_64-pc-linux-muslx32 --host=x86_64-pc-linux-muslx32
Thread model: posix
Supported LTO compression algorithms: zlib
gcc version 11.2.1 20211120 (GCC) 
root@HewoArch:/# 

root@HewoArch:/# scons -v
SCons by Steven Knight et al.:
        SCons: v4.0.1.c289977f8b34786ab6c334311e232886da7e8df1, 2020-07-17 01:50:03, by bdbaddog on ProDog2020
        SCons path: ['/usr/lib/python3/dist-packages/SCons']
Copyright (c) 2001 - 2020 The SCons Foundation

```

为了方便使用,我们配置了一个 Containerfile, 用于生成跟评测机相同的环境.同时,我们实现了一个 run.py, 用于自动检测本机环境,补充对应工具链,生成对应 docker 镜像以及进入 docker 环境.

进入环境后, 我们主要工具链放置于 /opt, 代码放置于 /code, 采用卷挂载形式.

在 /code 目录下

```bash
cd machines/qemu-virt-riscv64 # 进入 riscv64 的目录
scons -c # 清理之前的构建
scons --menuconfig # 打开菜单,如果没有需求,可以直接退出
pkgs --update # 更新网络包
scons -j12 # 编译
./run.sh ../../testsuits-for-oskernel/releases/sdcard-rv.img # 这里允许指定打开什么镜像

```


