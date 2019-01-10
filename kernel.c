/* kernel.c - the C part of the kernel */
/* Copyright (C) 1999, 2010  Free Software Foundation, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <sys/io.h>
#include "md5.h"
#include "multiboot.h"
/* Macros. */

/* Check if the bit BIT in FLAGS is set. */
#define CHECK_FLAG(flags, bit) ((flags) & (1 << (bit)))

/* Forward declarations. */
void cmain(unsigned long magic, unsigned long addr);
static void itoa(char *buf, int base, int d);
static void putchar(int c);
void printf(const char *format, ...);

void print_module(multiboot_uint32_t start, multiboot_uint32_t end,
                  multiboot_uint32_t cmdline) {
  MD5_CTX ctx;
  MD5_Init(&ctx);
  MD5_Update(&ctx, (void *)start, end - start);
  unsigned char res[16];
  MD5_Final(res, &ctx);

  printf("{\"start\": %u, \"end\": %u, \"cmdline\": \"%s\", \"md5\": \"",
         (unsigned)start, (unsigned)end, (char *)cmdline);
  for (int i = 0; i < 16; i++) {
    printf("%02x", res[i]);
  }
  printf("\"}");
}

/* Check if MAGIC is valid and print the Multiboot information structure
   pointed by ADDR. */
void cmain(unsigned long magic, unsigned long addr) {
  multiboot_info_t *mbi;
  /* Clear the screen. */
  printf("Starting multiboot kernel\n");
  
  printf("{\n");
  /* Am I booted by a Multiboot-compliant boot loader? */
  if (magic != MULTIBOOT_BOOTLOADER_MAGIC) {
    printf("\"status\": \"Invalid magic number\"\n}\n");
    return;
  }

  /* Set MBI to the address of the Multiboot information structure. */
  mbi = (multiboot_info_t *)addr;

  /* Print out the flags. */
  printf("\"flags\": %u,\n", (unsigned)mbi->flags);

  /* Are mem_* valid? */
  if (CHECK_FLAG(mbi->flags, 0))
    printf("\"mem_lower\": %u, \"mem_upper\": %u,\n", (unsigned)mbi->mem_lower,
           (unsigned)mbi->mem_upper);

  /* Is boot_device valid? */
  if (CHECK_FLAG(mbi->flags, 1))
    printf("\"boot_device\": %u,\n", (unsigned)mbi->boot_device);

  /* Is the command line passed? */
  if (CHECK_FLAG(mbi->flags, 2))
    printf("\"cmdline\": \"%s\",\n", (char *)mbi->cmdline);

  /* Are mods_* valid? */
  if (CHECK_FLAG(mbi->flags, 3)) {
    multiboot_module_t *mod;
    int i;

    printf("\"mods_count\": %d, \"mods_addr\": %u,\n", (int)mbi->mods_count,
           (int)mbi->mods_addr);
    printf("\"modules\": [\n");
    for (i = 0, mod = (multiboot_module_t *)mbi->mods_addr; i < mbi->mods_count;
         i++, mod++) {
      print_module(mod->mod_start, mod->mod_end, mod->cmdline);
      if (i != mbi->mods_count - 1) printf(",\n");
    }
    printf("\n],\n");
  }

  /* Bits 4 and 5 are mutually exclusive! */
  if (CHECK_FLAG(mbi->flags, 4) && CHECK_FLAG(mbi->flags, 5)) {
    printf("\"status\":\"Both bits 4 and 5 are set\"\n}\n");
    return;
  }

  /* Is the symbol table of a.out valid? */
  if (CHECK_FLAG(mbi->flags, 4)) {
    multiboot_aout_symbol_table_t *multiboot_aout_sym = &(mbi->u.aout_sym);

    printf(
        "\"multiboot_aout_symbol_table\": {\"tabsize\" = 0x%0x, "
        "\"strsize\" = 0x%x, \"addr\" = 0x%x},\n",
        (unsigned)multiboot_aout_sym->tabsize,
        (unsigned)multiboot_aout_sym->strsize,
        (unsigned)multiboot_aout_sym->addr);
  }

  /* Is the section header table of ELF valid? */
  if (CHECK_FLAG(mbi->flags, 5)) {
    multiboot_elf_section_header_table_t *multiboot_elf_sec = &(mbi->u.elf_sec);

    printf(
        "\"multiboot_elf_sec\": {\"num\": %u, \"size\": %u,"
        " \"addr\": %u, \"shndx\": %u},\n",
        (unsigned)multiboot_elf_sec->num, (unsigned)multiboot_elf_sec->size,
        (unsigned)multiboot_elf_sec->addr, (unsigned)multiboot_elf_sec->shndx);
  }

  /* Are mmap_* valid? */
  if (CHECK_FLAG(mbi->flags, 6)) {
    multiboot_memory_map_t *mmap;

    printf("\"mmap_addr\": %u, \"mmap_length\": %u,\n",
           (unsigned)mbi->mmap_addr, (unsigned)mbi->mmap_length);
    printf("\"mmap\": [\n");
    int first = 1;
    for (mmap = (multiboot_memory_map_t *)mbi->mmap_addr;
         (unsigned long)mmap < mbi->mmap_addr + mbi->mmap_length;
         mmap = (multiboot_memory_map_t *)((unsigned long)mmap + mmap->size +
                                           sizeof(mmap->size))) {
      if (!first) printf(",\n");
      first = 0;
      printf(
          "{\"size\": %u, \"base_addr\": \"0x%x%08x\", "
          "\"length\": \"0x%x%08x\", \"type\": %u}",
          (unsigned)mmap->size, (unsigned)(mmap->addr >> 32),
          (unsigned)(mmap->addr & 0xffffffff), (unsigned)(mmap->len >> 32),
          (unsigned)(mmap->len & 0xffffffff), (unsigned)mmap->type);
    }
    printf("\n],\n");
  }
  if (CHECK_FLAG(mbi->flags, 9))
    printf("\"bootloader\": \"%s\",\n", (char *)mbi->boot_loader_name);

  printf("\"status\": \"ok\"\n}\n");
}

/* Convert the integer D to a string and save the string in BUF. If
   BASE is equal to 'd', interpret that D is decimal, and if BASE is
   equal to 'x', interpret that D is hexadecimal. */
static void itoa(char *buf, int base, int d) {
  char *p = buf;
  char *p1, *p2;
  unsigned long ud = d;
  int divisor = 10;

  /* If %d is specified and D is minus, put `-' in the head. */
  if (base == 'd' && d < 0) {
    *p++ = '-';
    buf++;
    ud = -d;
  } else if (base == 'x')
    divisor = 16;

  /* Divide UD by DIVISOR until UD == 0. */
  do {
    int remainder = ud % divisor;

    *p++ = (remainder < 10) ? remainder + '0' : remainder + 'a' - 10;
  } while (ud /= divisor);

  /* Terminate BUF. */
  *p = 0;

  /* Reverse BUF. */
  p1 = buf;
  p2 = p - 1;
  while (p1 < p2) {
    char tmp = *p1;
    *p1 = *p2;
    *p2 = tmp;
    p1++;
    p2--;
  }
}

/* Put the character C on the screen. */
static void putchar(int c) { outb(c, 0x3f8); }

/* Format a string and print it on the screen, just like the libc
   function printf. */
void printf(const char *format, ...) {
  char **arg = (char **)&format;
  int c;
  char buf[20];

  arg++;

  while ((c = *format++) != 0) {
    if (c != '%')
      putchar(c);
    else {
      char *p, *p2;
      int pad0 = 0, pad = 0;

      c = *format++;
      if (c == '0') {
        pad0 = 1;
        c = *format++;
      }

      if (c >= '0' && c <= '9') {
        pad = c - '0';
        c = *format++;
      }

      switch (c) {
        case 'd':
        case 'u':
        case 'x':
          itoa(buf, c, *((int *)arg++));
          p = buf;
          goto string;
          break;

        case 's':
          p = *arg++;
          if (!p) p = "(null)";

        string:
          for (p2 = p; *p2; p2++)
            ;
          for (; p2 < p + pad; p2++) putchar(pad0 ? '0' : ' ');
          while (*p) putchar(*p++);
          break;

        default:
          putchar(*((int *)arg++));
          break;
      }
    }
  }
}
