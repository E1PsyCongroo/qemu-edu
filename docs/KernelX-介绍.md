# 高清的 KernelX

## 简介

KernelX 是一个基于 RT-Thread(smart) 的，使用 c 开发的微内核操作系统。

参赛队员为：

## 架构

来张图

RTT https://www.rt-thread.org/document/site/#/rt-thread-version/rt-thread-standard/README

## 关于 RT-Thread

RT-Thread(Real Time-Thread), 是一款广泛运用于嵌入式的实时多线程操作系统。RT-Thread 主要使用 C 语言编写，参考了面向对象设计的设计范式。同时，RT-Thread 采取的是微内核架构，具有一个极简的内核以及丰富的拓展、组件，同时支持在线软件包管理，提供更加丰富的功能和强大的裁剪能力以适应不同的设备。

## 我们的工作

1. 修复RT-Thread中的一些函数实现问题，如`openat`函数。

2. 将RT-Thread中LWP实现的系统调用修改为符合POSIX标准的。虽然RT-Thread已经实现了一些系统调用，但是他们并不符合POSIX标准。例如`clone`函数的实现，RT-Thread的原有实现将`clone`和`fork`的实现分开，`clone`只负责产生线程，`fork`负责产生进程，同时，`clone`使用一个`void *`来传递六个参数，而Linux则是直接使用寄存器传递六个参数，我们按照原有的逻辑，重写了`clone`系统调用，合并了`clone`和`fork`，并将传参方式改为了直接参数传递。这样的系统调用还有很多,例如`brk`的系统逻辑。系统调用号也需要进行修改。

3. 增加系统调用。RT-Thread虽然提供了一些系统调用的实现，但是这些系统调用并不足以支持测例的运行。我们通过运用RT-Thread提供的运行时环境，增加一些系统调用，例如`fstatat`、`mprotect`、`fsync`、`readv`、`writev`、`shmget`、`shmat`、`shmctl`。

可以QA方式扯

## 文档列表

放其他的文档

## 快速启动

如果在非评测机下的linux环境，我们提供了 docker 环境。

...
// 我写

如果在评测机环境

...
// 自由爷你写

详细的环境逻辑请参考文档：

## 项目结构

## 开源引用声明