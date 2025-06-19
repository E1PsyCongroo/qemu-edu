#!/usr/bin/env python3

import argparse
import os
import subprocess
import random
import string
from pathlib import Path

# 获取脚本路径
script_path = Path(__file__).resolve()
script_dir = script_path.parent


def main():
    # 参数解析
    parser = argparse.ArgumentParser(
        prog=f"{__file__}", description="startup container"
    )
    parser.add_argument("-g", "--gui", help="开启容器图形化显示", action="store_true")
    args = parser.parse_args()

    # 更新git子模块
    subprocess.run(["git", "submodule", "update", "--init", "--recursive"], check=True)

    # 下载工具链文件
    toolchain_qemu_longarch = (
        script_dir
        / "toolchains/qemu-longarch/loongarch64-musl-gcc-nightly-2025-3-27.tar.gz"
    )
    if not toolchain_qemu_longarch.exists():
        toolchain_qemu_longarch.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            [
                "wget",
                "--no-check-certificate",
                "https://github.com/LoongsonLab/oscomp-toolchains-for-oskernel/releases/download/loongarch64-cross-toolchains-qemu/loongarch64-musl-gcc-nightly-2025-3-27.tar.gz",
                "-P",
                str(toolchain_qemu_longarch.parent),
            ],
            check=True,
        )

    toolchain_riscv = (
        script_dir
        / "toolchains/qemu-virt-riscv64/riscv64gc-linux-musleabi_for_x86_64-pc-linux-gnu_latest.tar.bz2"
    )
    if not toolchain_riscv.exists():
        toolchain_riscv.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            [
                "wget",
                "--no-check-certificate",
                "https://download.rt-thread.org/download/rt-smart/toolchains/riscv64gc-linux-musleabi_for_x86_64-pc-linux-gnu_latest.tar.bz2",
                "-P",
                str(toolchain_riscv.parent),
            ],
            check=True,
        )

    # 检查Docker镜像
    image_name = "local/rtt-rv64"
    result = subprocess.run(
        ["docker", "image", "inspect", image_name],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if result.returncode != 0:
        # 构建镜像
        build_args = [
            "--rm",
            "-t",
            image_name,
            "--network",
            "host",
            "-f",
            str(script_dir / "Containerfile"),
            str(script_dir),
        ]
        subprocess.run(["docker", "build"] + build_args, check=True)

    # 生成容器名
    container_name = "".join(random.choices(string.ascii_letters + string.digits, k=16))

    docker_run_flag = [
        "-dit",
        "--rm",
        "-v",
        str(script_dir) + ":/code",
        "-w",
        "/code",
        "--name",
        container_name,
        "--network",
        "host",
        "--privileged",
    ]
    if args.gui:
        # 设置X11权限
        subprocess.run(["xhost", "+local:"], check=True)
        docker_run_flag.extend([
            "-e",
            f"DISPLAY={os.environ.get('DISPLAY', '')}",
            "-v",
            "/tmp/.X11-unix:/tmp/.X11-unix",
        ])

    try:
        # 运行容器
        docker_run_cmd = (
            [
                "docker",
                "run",
            ]
            + docker_run_flag
            + [
                image_name,
                "bash",
            ]
        )
        subprocess.run(docker_run_cmd, check=True)

        # 显示容器信息
        subprocess.run(["docker", "ps", "-a", "-f", f"name={container_name}"])

        print(
            """Use: make NPROC=8 -C testsuits-for-oskernel sdcard
            cd machines/qemu-virt-riscv64
            scons --menuconfig
            pkgs --update
            scons -j8
            """.strip("\n")
        )

        # 附加到容器
        subprocess.run(["docker", "attach", container_name])
    finally:
        if (args.gui):
            # 清理X11权限
            subprocess.run(["xhost", "-local:"], check=True)


if __name__ == "__main__":
    main()
