# FinSH

FinSH 是一个命令行组件，为用户提供了更加简单、符合逻辑的交互界面。FinSH 提供了一整套操作接口供用户通过命令行使用，同时支持权限验证等高级功能。

FinSH 分为两种使用逻辑，这里主要谈论 MSH(Module SHell) 模式，也就是常见的命令行解析，比如

```bash
msh />version

 \ | /
- RT -     Thread Smart Operating System
 / | \     5.2.0 build Jun 28 2025 06:47:11
 2006 - 2024 Copyright by RT-Thread team
```

msh 支持如下功能：

```bash
msh />help
RT-Thread shell commands:
dbg              - dbg
list_channel     - list IPC channel information
list_processgroup - list process group
list_process     - list process
kill             - send a signal to a process
killall          - kill processes by name
list_session     - list session
list_shm         - show share memory info
sys_log          - sys_log 1(enable) / 0(disable)
list_kmem        - List varea in kernel virtual memory space
list_page        - show page info
ifconfig         - list the information of all network interfaces
ping             - ping network host
dns              - list and set the information of dns
netstat          - list the information of TCP / IP
utest_list       - output all utest testcase
utest_run        - utest_run [-thread or -help] [testcase name] [loop num]
reboot           - reset machine
list_fd          - list file descriptor
fd_dump          - fd dump
dentry_dump      - dump dentry in the system
dfs_cache        - dump dfs page cache
pin              - pin [option]
date             - get date and time or set (local timezone) [year month day hour min sec]
rtc_sync         - Update time by soft rtc
serial_bypass_list - serial bypass list
clear            - clear the terminal screen
version          - show RT-Thread version information
list             - list objects
help             - RT-Thread shell help
ps               - List threads in the system
free             - Show the memory usage in the system
ls               - List information about the FILEs.
ln               - Make symbolic link between files
link             - Make link between files
cp               - Copy SOURCE to DEST.
mv               - Rename SOURCE to DEST.
cat              - Concatenate FILE(s)
rm               - Remove(unlink) the FILE(s).
cd               - Change the shell working directory.
pwd              - Print the name of the current working directory.
mkdir            - Create the DIRECTORY.
mkfs             - format disk with file system
mount            - mount <device> <mountpoint> <fstype>
umount           - Unmount the mountpoint
df               - disk free
echo             - echo string to file
tail             - print the last N - lines data of the given file
chmod            - Change the file attr.
backtrace        - print backtrace of a thread
```