FROM docker.educg.net/cg/os-contest:20250226
ARG HTTP_PORT
ARG HTTPS_PORT
ARG http_port
ARG https_port
ENV HTTP_PROXY=http://127.0.0.1:${HTTP_PORT}
ENV HTTPS_PROXY=http://127.0.0.1:${HTTPS_PORT}
ENV ALL_PROXY=http://127.0.0.1:${HTTP_PORT}
ENV NO_PROXY=localhost,127.0.0.1,::1
ENV http_proxy=http://127.0.0.1:${http_port}
ENV https_proxy=http://127.0.0.1:${https_port}
ENV all_proxy=http://127.0.0.1:${http_port}
ENV no_proxy=localhost,127.0.0.1,::1
RUN apt-get -y update
RUN apt-get -y install tar git build-essential cmake wget curl dosfstools gdb-multiarch qemu-system-misc scons python3-kconfiglib python3-tqdm python3-requests python3-yaml vim
COPY toolchains /root/toolchains
RUN bash /root/toolchains/install_ubuntu.sh --gitee
RUN tar jxvf /root/toolchains/qemu-virt-riscv64/riscv64gc-linux-musleabi_for_x86_64-pc-linux-gnu_latest.tar.bz2 -C /opt
RUN tar zxvf /root/toolchains/qemu-longarch/loongarch64-musl-gcc-nightly-2025-3-27.tar.gz -C /opt
RUN echo "source ~/.env/env.sh" >>~/.bashrc
ENV RTT_EXEC_PATH=/opt/riscv64gc-linux-musleabi_for_x86_64-pc-linux-gnu/bin
ENV RTT_CC_PREFIX=riscv64-unknown-linux-musl-
ENV PATH=/opt/riscv64gc-linux-musleabi_for_x86_64-pc-linux-gnu/bin:$PATH
CMD ["bash"]
