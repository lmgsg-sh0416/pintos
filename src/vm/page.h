#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <stdbool.h>
#include <stdint.h>
#include <hash.h>
#include <bitmap.h>
#include "filesys/file.h"

struct page {
  struct bitmap *first_load;

  /* Memory view */
  void *start_vaddr;
  void *end_vaddr;
  void *upage;        // Alignment for start_vaddr

  /* File view */
  struct file *file;
  off_t file_offset;
  uint32_t read_bytes;

  /* Writeable */
  bool writable;

  /* Hash */
  struct hash_elem elem;
};

unsigned upage_hash (const struct hash_elem *_e, void *aux);
bool upage_less (const struct hash_elem *_a, const struct hash_elem *_b, void *aux);
void init_sup_pagedir (void);
bool insert_page_entry (size_t page_num, void *start_vaddr, void *end_vaddr, void *upage,
    struct file *file, off_t file_offset, uint32_t read_bytes, bool writable);

#endif /* vm/page.h */
