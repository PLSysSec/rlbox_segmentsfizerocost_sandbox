#include <asm/ldt.h>
#include <asm/unistd_32.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

// Adapted NaCl code for segment setup

static int modify_ldt(int func, void *ptr, unsigned long bytecount) {
  return syscall(__NR_modify_ldt, func, ptr, bytecount);
}

struct LdtEntry {
  uint16_t limit_00to15;
  uint16_t base_00to15;

  unsigned int base_16to23 : 8;

  unsigned int type : 5;
  unsigned int descriptor_privilege : 2;
  unsigned int present : 1;

  unsigned int limit_16to19 : 4;
  unsigned int available : 1;
  unsigned int code_64_bit : 1;
  unsigned int op_size_32 : 1;
  unsigned int granularity : 1;

  unsigned int base_24to31 : 8;
};

// Find a free selector
static int NaClFindUnusedEntryNumber() {
  int size = sizeof(struct LdtEntry) * LDT_ENTRIES;
  struct LdtEntry * entries = (struct LdtEntry *) malloc(size);
  int retval = modify_ldt(0, entries, size);

  if (-1 != retval) {
    retval = -1;  /* In case we don't find any free entry */
    for (int i = 0; i < LDT_ENTRIES; ++i) {
      if (!entries[i].present) {
        retval = i;
        break;
      }
    }
  }

  free(entries);
  return retval;
}

/*
 * Find and allocate an available selector, inserting an LDT entry with the
 * appropriate permissions. Returns 0 on failure, segment on success.
 */
static uint16_t NaClLdtAllocateSelector(int entry_number,
                                 int size_is_in_pages,
                                 void* base_addr,
                                 uint32_t size_minus_one) {
    if (-1 == entry_number) {
        // No free entries were available.
        return 0;
    }
    struct user_desc ud;
    ud.entry_number = entry_number;
    ud.contents = MODIFY_LDT_CONTENTS_DATA;
    ud.read_exec_only = 0;
    ud.seg_32bit = 1;
    ud.seg_not_present = 0;
    ud.useable = 1;

    if (size_is_in_pages && ((unsigned long) base_addr & 0xfff)) {
        // Base address not page aligned
        abort();
    }
    ud.base_addr = (unsigned long) base_addr;

    if (size_minus_one > 0xfffff) {
        // If size is in pages, no more than 2**20 pages can be protected.
        // If size is in bytes, no more than 2**20 bytes can be protected.
        abort();
    }
    ud.limit = size_minus_one;
    ud.limit_in_pages = size_is_in_pages;

    // Install the LDT entry.
    int retval = modify_ldt(1, &ud, sizeof ud);
    if (-1 == retval) {
        return 0;
    }

    // Return an LDT selector with a requested privilege level of 3.
    return (ud.entry_number << 3) | 0x7;
}

static void NaClLdtInitPlatformSpecific() {
    // Allocate the last LDT entry to force the LDT to grow to its maximum size.
    NaClLdtAllocateSelector(LDT_ENTRIES - 1, 0, 0, 0);
}

static uint16_t NaClAllocateSegmentForDataRegion(void * data_region_start, size_t data_pages) {
    const int entry_number = NaClFindUnusedEntryNumber();
    return NaClLdtAllocateSelector(entry_number, 1, data_region_start, data_pages - 1);
}

static void NaClLdtDeleteSelector(uint16_t selector) {
    struct user_desc ud;
    ud.entry_number = selector >> 3;
    ud.seg_not_present = 1;
    ud.base_addr = 0;
    ud.limit = 0;
    ud.limit_in_pages = 0;
    ud.read_exec_only = 0;
    ud.seg_32bit = 0;
    ud.useable = 0;
    ud.contents = MODIFY_LDT_CONTENTS_DATA;
    modify_ldt(1, &ud, sizeof ud);
}
