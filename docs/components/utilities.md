# utilities

Utilities是一系列工具组件的集合。

## RT-Link 

RT-Link 是一套开放的链路层传输协议，设计的初衷是为了稳定、安全、高效率的完成设备间点对点的数据传输，并且接口简单、使用便捷。具有数据重传、帧序号检查、状态同步等一系列能力，保证传输的稳定，支持 CRC 校验，采用以太网检验协议，对下具有统一的操作API，可支持多种底层硬件接口，并且API简洁。

## ulog 日志 

ulog 是一个非常简洁、易用的 C/C++ 日志组件，占用空间少，但有非常全面的功能。日志输出的后端多样，可支持例如串口、网络，文件、闪存等后端形式；输出被设计为线程安全的方式，并支持异步输出模式；支持运行期 / 编译期设置输出级别；支持按关键词及标签方式进行全局过滤；日志格式可兼容 linux syslog。

ulog主要特性：

- 日志输出的后端多样化，可支持例如：串口、网络，文件、闪存等后端形式。

- 日志系统高可靠，在中断 ISR 、Hardfault 等复杂环境下依旧可用。

- 日志支持运行期 / 编译期设置输出级别。

- 日志内容支持按关键词及标签方式进行全局过滤。

- API 和日志格式可兼容 linux syslog。

- 支持以 hex 格式 dump 调试数据到日志中。

- 兼容 rtdbg （RTT 早期的日志头文件）及 EasyLogger 的日志输出 API。

ulog的组成

- **前端** 离应用最近的一层，给用户提供了 syslog 及 LOG_X 两类 API 接口，方便用户在不同的场景中使用。

- **核心** 中间核心层的主要工作是将上层传递过来的日志，按照不同的配置要求进行格式化与过滤然后生成日志帧，最终通过不同的输出模块，输出到最底层的后端设备上。

- **后端** 接收到核心层发来的日志帧后，将日志输出到已经注册的日志后端设备上，例如：文件、控制台、日志服务器等等。

ulog 主要有两种日志输出宏API，用于输出不同等级的日志信息。

```c
#define LOG_E(...)                           ulog_e(LOG_TAG, __VA_ARGS__)
#define LOG_W(...)                           ulog_w(LOG_TAG, __VA_ARGS__)
#define LOG_I(...)                           ulog_i(LOG_TAG, __VA_ARGS__)
#define LOG_D(...)                           ulog_d(LOG_TAG, __VA_ARGS__)
#define LOG_RAW(...)                         ulog_raw(__VA_ARGS__)
#define LOG_HEX(name, width, buf, size)      ulog_hex(name, width, buf, size)
```

在使用的时候，可以先指定`LOG_TAG`和最低输出等级`LOG_LVL`，ulog会根据每个文件不同配置决定不同的日志输出。

```c
#define LOG_TAG              "example"
#define LOG_LVL              LOG_LVL_DBG
#include <ulog.h>
```
