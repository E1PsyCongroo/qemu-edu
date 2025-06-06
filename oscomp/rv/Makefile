CROSS_COMPILE = riscv64-linux-musl-
CC = $(CROSS_COMPILE)gcc

INC += ./include

CFLAGS += -Wall -O2 -march=rv64imafdc -mabi=lp64d
CFLAGS += -static
CFLAGS += $(addprefix -I, $(INC))

BUILDDIR = ./build
FSDIR = $(BUILDDIR)/fs
TARGET = $(FSDIR)/test-all
DISKIMG = $(BUILDDIR)/disk.img

SRC += $(wildcard ./src/*.c)

all: $(DISKIMG)

$(TARGET): $(SRC)
	mkdir -p $(FSDIR)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC)

$(DISKIMG): $(TARGET)
	dd if=/dev/zero of=$(DISKIMG) bs=1M count=256
	mkfs.ext4 $(DISKIMG)
	mkdir -p /mnt/tmpfs
	mount -o loop $(DISKIMG) /mnt/tmpfs
	cp -a $(FSDIR)/* /mnt/tmpfs/
	umount /mnt/tmpfs
	rmdir /mnt/tmpfs

clean:
	rm -rf $(BUILDDIR)
