# multiboot-test-kernel
A multiboot test kernel.

This is a slightly modified kernel provided by the Multiboot v1 [spec](https://www.gnu.org/software/grub/manual/multiboot/multiboot.html#Example-OS-code).

The kernel writes received Multiboot information to a serial output in JSON format and computes sha256 sum for each loaded module.
