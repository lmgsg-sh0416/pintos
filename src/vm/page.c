#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <hash.h>
#include <bitmap.h>
#include "threads/thread.h"
#include "threads/synch.h"
#include "vm/page.h"

// For hash table
unsigned
upage_hash (const struct hash_elem *_e, void *aux)
{
  const struct page *e = hash_entry (_e, struct page, elem);
  return hash_bytes (&e->upage, sizeof e->upage);
}

bool
upage_less (const struct hash_elem *_a, const struct hash_elem *_b, void *aux)
{
  const struct page *a = hash_entry (_a, struct page, elem);
  const struct page *b = hash_entry (_b, struct page, elem);
  return a->upage < b->upage;
}
// For hash table END

void
init_sup_pagedir (void)
{
  struct thread *cur = thread_current ();
  hash_init (&(cur->sup_pagedir), upage_hash, upage_less, NULL);
}

bool
insert_page_entry (size_t page_num, void *start_vaddr, void *end_vaddr, void *upage,
    struct file *file, off_t file_offset, uint32_t read_bytes, bool writable)
{
  struct thread *cur = thread_current ();
  struct page *p = (struct page*) malloc (sizeof *p);
  if (p == NULL)
    return false;
  p->first_load = bitmap_create (page_num);
  p->start_vaddr = start_vaddr;
  p->end_vaddr = end_vaddr;
  p->upage = upage;
  p->file = file;
  p->file_offset = file_offset;
  p->read_bytes = read_bytes;
  p->writable = writable;

  hash_insert (&(cur->sup_pagedir), &p->elem);
  return true;
}

