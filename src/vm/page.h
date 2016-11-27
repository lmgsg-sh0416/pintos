#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <stdbool.h>
#include <stdint.h>
#include <hash.h>
#include "filesys/file.h"

enum sup_pte_type {
  SPTE_FILE,
  SPTE_ZERO,
  SPTE_SWAP
};

struct sup_pte {
  enum sup_pte_type type;
  void *upage; // start page
  void *kpage;
  void *start_vaddr;
  void *end_vaddr;

  struct file *file;
  off_t offset;
  bool writable;

  uint32_t read_bytes;
  uint32_t zero_bytes;

  struct hash_elem elem;
};

unsigned upage_hash (const struct hash_elem *e, void *aux);
bool upage_less (const struct hash_elem *a, const struct hash_elem *b, void *aux);

#endif /* vm/page.h */
