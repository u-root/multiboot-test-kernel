CC=gcc
CFLAGS=-c -m32 -nostdlib -fno-stack-protector -fno-builtin
OBJECT_FILES=boot.o kernel.o sha256.o
LDFLAGS=-m elf_i386

all: kernel.gz

%.o: %.S
	$(CC) $(CFLAGS) $< -o $@

kernel.gz: kernel
	gzip kernel

kernel: boot.o kernel.o sha256.o
	$(LD) $(LDFLAGS) $^ -o $@

.PHONY: all clean

clean:
	rm -f $(OBJECT_FILES) kernel kernel.gz
