set confirm off
set architecture riscv:rv64
target remote 127.0.0.1:1234
symbol-file rtthread.elf
set disassemble-next-line auto
set riscv use-compressed-breakpoints yes

directory /home/hewo/CS/proj/OS/qemu-edu/rt-thread/components/lwp/syscall
directory /home/hewo/CS/proj/OS/qemu-edu/rt-thread/components
directory /home/hewo/CS/proj/OS/qemu-edu/rt-thread
