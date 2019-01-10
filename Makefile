CC=gcc
CFLAGS=-c -m32
OBJECT_FILES=boot.o kernel.o md5.o
LDFLAGS=-m elf_i386

all: kernel

%.o: %.S
	$(CC) $(CFLAGS) $< -o $@

kernel: boot.o kernel.o md5.o
	$(LD) $(LDFLAGS) $^ -o $@

.PHONY: all clean

clean:
	rm $(OBJECT_FILES) kernel
